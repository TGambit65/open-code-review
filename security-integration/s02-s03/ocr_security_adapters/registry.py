# SPDX-License-Identifier: Apache-2.0
"""Explicit disabled registrations. Importing these adapters changes no settings."""

from .boundary import disabled_result, execute

REGISTRATIONS = (
    ("ocr", "S02", "sanitized independent reasoning"),
    ("opengrep", "S03", "local approved rules"),
    ("gitleaks", "S03", "fully redacted CLI"),
    ("osv", "S03", "preloaded offline databases"),
)


def status():
    return [dict(disabled_result(name), sprint=sprint, purpose=purpose) for name, sprint, purpose in REGISTRATIONS]


def run(name, *args, **kwargs):
    return execute(None)


def rollback(name):
    """Idempotent data-only disable receipt. Does not delete sources or evidence."""
    return dict(disabled_result(name, "disabled_by_operator"), retained_evidence=True,
                standard_ocr_changed=False, hosted_fallback=False)
