# SPDX-License-Identifier: Apache-2.0
"""Explicit external authority. Callers, not candidate data, supply trust roots."""

import os
import stat
from dataclasses import dataclass

from .common import Refusal, canonical, digest, fields, parse_json, sha, text, utc

POLICY_SHA256 = "51653fb23403f441afec8cb0fc2780a6f649a089d119b0cf79e66e9f9622bf16"
ADOPTION_SHA256 = "67ba0b9e8136a79e46f66d0c2fafd8dd1e372331c820486183ac70195cdbdb45"
FILTER_SHA256 = "face557219d5ab2c901cacbf92ee8894a6a34fa5939a221796a75d1b0d25e9a9"
BACKEND_SHA256 = "573236e5328ac2ebb08f59ae3a9805b4f8d12bdef14be8af4450d5463294985f"


@dataclass(frozen=True)
class TrustedRef:
    path: str
    sha256: str


@dataclass(frozen=True)
class TrustContext:
    candidate_roots: tuple
    input_roots: tuple
    output_roots: tuple = ()

    @property
    def forbidden_roots(self):
        return self.candidate_roots + self.input_roots + self.output_roots


def absolute_parts(path):
    text(path, 4096)
    if not path.startswith("/") or path == "/" or "\\" in path:
        raise Refusal("unsafe_path")
    parts = path[1:].split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise Refusal("unsafe_path")
    return parts


def open_directory(path):
    parts = absolute_parts(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except OSError:
        os.close(fd)
        raise Refusal("unsafe_directory") from None


def open_at_regular(directory, name, maximum, executable=False):
    if not hasattr(os, "O_PATH"):
        raise Refusal("unsupported_platform")
    metadata = None
    fd = None
    try:
        metadata = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        info = os.fstat(metadata)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise Refusal("unsafe_file")
        if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise Refusal("unsafe_file")
        if executable and not info.st_mode & 0o111:
            raise Refusal("not_executable")
        # Only a verified regular inode is reopened through this generated proc descriptor.
        fd = os.open("/proc/self/fd/" + str(metadata), os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        opened = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
            raise Refusal("input_changed")
        result, fd = fd, None
        return result
    except OSError:
        raise Refusal("input_unreadable") from None
    finally:
        if metadata is not None:
            os.close(metadata)
        if fd is not None:
            os.close(fd)


def open_regular(path, maximum, executable=False):
    parts = absolute_parts(path)
    parent = "/" + "/".join(parts[:-1])
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC) if len(parts) == 1 else open_directory(parent)
    try:
        return open_at_regular(directory, parts[-1], maximum, executable)
    finally:
        os.close(directory)


def read_descriptor(fd, maximum):
    before = os.fstat(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while True:
        part = os.read(fd, min(65536, maximum + 1 - total))
        if not part:
            break
        total += len(part)
        if total > maximum:
            raise Refusal("input_limit")
        chunks.append(part)
    after = os.fstat(fd)
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if signature(before) != signature(after) or total != after.st_size:
        raise Refusal("input_changed")
    os.lseek(fd, 0, os.SEEK_SET)
    return b"".join(chunks)


def read_ref(ref, context, maximum=1048576):
    if not isinstance(ref, TrustedRef):
        raise Refusal("missing_authority")
    sha(ref.sha256)
    absolute_parts(ref.path)
    for root in context.forbidden_roots:
        absolute_parts(root)
        if os.path.commonpath((root, ref.path)) == root:
            raise Refusal("candidate_authority")
    fd = open_regular(ref.path, maximum)
    try:
        raw = read_descriptor(fd, maximum)
    except OSError:
        raise Refusal("input_unreadable") from None
    finally:
        os.close(fd)
    if digest(raw) != ref.sha256:
        raise Refusal("authority_mismatch")
    return raw


@dataclass(frozen=True)
class Policy:
    raw: bytes
    sha256: str
    adoption_sha256: str

    @property
    def data(self):
        return parse_json(self.raw)

    @property
    def profile(self):
        return self.data["isolation"]["profile"]


def resolve_policy(policy_ref, adoption_ref, context):
    if policy_ref.sha256 != POLICY_SHA256 or adoption_ref.sha256 != ADOPTION_SHA256:
        raise Refusal("unapproved_policy")
    raw = read_ref(policy_ref, context)
    adoption = parse_json(read_ref(adoption_ref, context))
    if adoption.get("state") != "ADOPTED_FOR_LOCAL_IMPLEMENTATION_ONLY" or adoption.get("execution_authorized") is not False:
        raise Refusal("unapproved_policy")
    if adoption.get("exact_pins", {}).get("security-acceptance.proposed-v4.json") != policy_ref.sha256:
        raise Refusal("unapproved_policy")
    policy = parse_json(raw)
    if policy.get("schema_version") != "1.0":
        raise Refusal("unsupported_policy")
    isolation = policy["isolation"]
    if digest(canonical(isolation["profile"])) != isolation["profile_canonical_sha256"]:
        raise Refusal("profile_mismatch")
    if isolation["profile"]["filter_sha256"] != FILTER_SHA256 or isolation["approved_backend_file_sha256"] != BACKEND_SHA256:
        raise Refusal("profile_mismatch")
    if policy["activation"]["scanner_adapters_enabled"] or policy["activation"]["model_providers_enabled"]:
        raise Refusal("activation_forbidden")
    return Policy(raw, policy_ref.sha256, adoption_ref.sha256)


def resolve_document(ref, context, kind, version="1.0"):
    result = parse_json(read_ref(ref, context))
    if type(result) is not dict or result.get("kind") != kind or result.get("schema_version") != version:
        raise Refusal("unsupported_document")
    return result


def execution_authority(ref, context, policy, expected, now):
    document = resolve_document(ref, context, "synthetic-execution-authority")
    required = {"schema_version", "kind", "authorized_actor", "issued_at", "expires_at", "action_id", "bindings"}
    fields(document, required)
    text(document["authorized_actor"])
    text(document["action_id"])
    if not utc(document["issued_at"]) <= now < utc(document["expires_at"]):
        raise Refusal("expired_authority")
    fields(document["bindings"], expected.keys())
    if document["bindings"] != expected or expected.get("policy_sha256") != policy.sha256:
        raise Refusal("execution_binding_mismatch")
    if expected.get("purpose") != "synthetic_fixture":
        raise Refusal("activation_forbidden")
    return document
