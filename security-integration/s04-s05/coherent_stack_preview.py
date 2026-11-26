# SPDX-License-Identifier: Apache-2.0
"""Offline aggregate preview; no actions, file reads, or draft creation."""

import json

from ocr_security.common import Refusal, relative_path
from ocr_security_gate.batching import batch_decision

_MAX_COHORTS = 64
_MAX_PATH_ENTRIES = 10_000


def _paths(values):
    if type(values) not in (list, tuple) or len(values) > _MAX_PATH_ENTRIES:
        raise Refusal("invalid_preview_path_group")
    return {relative_path(value) for value in values}


def preview(existing_paths, cohorts, *, final_boundary=None):
    """Apply the unchanged single-cohort policy within the current batch only."""
    if type(cohorts) not in (list, tuple) or len(cohorts) > _MAX_COHORTS:
        raise Refusal("invalid_preview_cohorts")
    current = _paths(existing_paths)
    total_entries = len(existing_paths)
    for cohort in cohorts:
        if type(cohort) not in (list, tuple) or not cohort:
            raise Refusal("invalid_preview_cohort")
        total_entries += len(cohort)
        if total_entries > _MAX_PATH_ENTRIES:
            raise Refusal("preview_path_budget_exceeded")

    initial = len(current)
    accepted = []
    # Validate the terminal reason via the existing policy. This is also the
    # terminal decision when no cohort remains, recomputed after accepted rows.
    decision = batch_decision(sorted(current), (), False, final_boundary)
    stopped_index = None
    for index, cohort in enumerate(cohorts, 1):
        upcoming = _paths(cohort)
        decision = batch_decision(sorted(current), sorted(upcoming), True)
        if decision["decision"] != "preserve_then_continue_coherent_scope":
            stopped_index = index
            break
        current.update(upcoming)
        accepted.append({
            "cohort_index": index,
            "new_distinct_paths": decision["next_new_paths"],
            "cumulative_distinct_paths": len(current),
        })
    else:
        decision = batch_decision(sorted(current), (), False, final_boundary)

    return {
        "kind": "coherent-stack-preview",
        "starting_distinct_paths": initial,
        "ending_distinct_paths": len(current),
        "accepted_cohorts": accepted,
        "stop": {
            "cohort_index": stopped_index,
            "reason": decision["decision"],
            "projected_distinct_paths": decision["projected_distinct_paths"],
            "boundary_reason": decision["boundary_reason"],
        },
        "minimum_target": decision["minimum_target"],
        "maximum_paths": decision["maximum_paths"],
        "padding_allowed": False,
        "preservation_delayed": False,
        "new_draft_created": False,
        "requires_root": True,
    }


def preview_json(existing_paths, cohorts, *, final_boundary=None):
    """Return deterministic UTF-8 JSON for a human-owned, offline handoff."""
    result = preview(existing_paths, cohorts, final_boundary=final_boundary)
    return json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
