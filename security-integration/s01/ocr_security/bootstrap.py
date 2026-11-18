# SPDX-License-Identifier: Apache-2.0
"""Executed only as sealed bytes by a separately pinned isolated system Python."""

import ctypes
import os
import resource
import sys


def main():
    try:
        source_fd, interpreter_fd, backend_fd = map(int, sys.argv[1:4])
        keep_fds = sorted(set(map(int, sys.argv[4].split(","))))
        argv = sys.argv[5:]
        if not argv or argv[0] != "bwrap" or min(source_fd, interpreter_fd, backend_fd) < 3:
            raise ValueError()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.personality.argtypes = [ctypes.c_ulong]
        libc.personality.restype = ctypes.c_int
        if libc.personality(0xFFFFFFFF) != 0:
            raise ValueError()
        if backend_fd not in keep_fds or source_fd in keep_fds or interpreter_fd in keep_fds or any(fd < 3 or fd >= 32 for fd in keep_fds):
            raise ValueError()
        first = 3
        for fd in keep_fds:
            os.closerange(first, fd)
            first = fd + 1
        os.closerange(first, 2147483647)
        os.set_inheritable(backend_fd, False)
        os.umask(0o077)
        for kind, maximum in ((resource.RLIMIT_CPU, 2),
                              (resource.RLIMIT_AS, 134217728),
                              (resource.RLIMIT_FSIZE, 1048576),
                              (resource.RLIMIT_NOFILE, 32),
                              (resource.RLIMIT_CORE, 0)):
            resource.setrlimit(kind, (maximum, maximum))
        os.execve(backend_fd, argv, {})
    except BaseException:
        os.write(2, b"bootstrap_refused\n")
        os._exit(125)


if __name__ == "__main__":
    main()
