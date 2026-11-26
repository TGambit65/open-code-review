# SPDX-License-Identifier: Apache-2.0
"""Offline aggregate preview; no actions, file reads, or draft creation."""

import json

from ocr_security.common import Refusal, relative_path
from ocr_security_gate.batching import MAXIMUM_PATHS, batch_decision

_MAX_COHORTS = 64
_MAX_PATH_ENTRIES = 10_000


def _paths(values):
    if type(values) not in (list, tuple) or len(values) > _MAX_PATH_ENTRIES:
        raise Refusal("invalid_preview_path_group")
    return {relative_path(value) for value in values}


def preview(existing_paths, cohorts, *, final_boundary=None):
    """Apply the unchanged single-cohort policy within the current batch only."""
    return _preview(existing_paths, cohorts, final_boundary, check_all=False)


def preview_checked(existing_paths, cohorts, *, final_boundary=None):
    """Opt in to validation of every path, including unevaluated cohorts."""
    return _preview(existing_paths, cohorts, final_boundary, check_all=True)


def _bounded_existing_paths(existing_paths, cohorts):
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

    return current


def _preview(existing_paths, cohorts, final_boundary, *, check_all):
    current = _bounded_existing_paths(existing_paths, cohorts)
    # Enforce the combined count limit before normalizing any later cohort.
    if check_all:
        cohorts = tuple(_paths(cohort) for cohort in cohorts)
    initial = len(current)
    accepted = []
    # Validate the terminal reason via the existing policy. This is also the
    # terminal decision when no cohort remains, recomputed after accepted rows.
    # The retained batch helper expects list-shaped path arguments.
    decision = batch_decision(sorted(current), [], False, final_boundary)
    stopped_index = None
    for index, cohort in enumerate(cohorts, 1):
        upcoming = cohort if check_all else _paths(cohort)
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
        decision = batch_decision(sorted(current), [], False, final_boundary)

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

def preview_compatible_280(existing_paths, cohorts, *, final_boundary):
    """Opt in to count-only planning for ordered, already-compatible cohorts."""
    if type(final_boundary) is not str or final_boundary not in (
        "final_scope", "dependency_hold", "no_eligible_work",
    ):
        raise Refusal("invalid_preview_final_boundary")
    current = _bounded_existing_paths(existing_paths, cohorts)
    # Validate all entries, even when the current count or an early group stops
    # the count projection. None of these strings is used to access a file.
    normalized = tuple(_paths(cohort) for cohort in cohorts)
    initial = len(current)
    accepted = []
    stop = {
        "cohort_index": None,
        "reason": "hold_over_cap_existing_batch",
        "projected_distinct_paths": initial,
        "boundary_reason": None,
    }
    if initial <= MAXIMUM_PATHS:
        for index, cohort in enumerate(normalized, 1):
            new_paths = cohort - current
            projected = len(current) + len(new_paths)
            if projected > MAXIMUM_PATHS:
                stop = {
                    "cohort_index": index,
                    "reason": "stop_before_overflow",
                    "projected_distinct_paths": projected,
                    "boundary_reason": None,
                }
                break
            current.update(new_paths)
            accepted.append({
                "cohort_index": index,
                "new_distinct_paths": len(new_paths),
                "cumulative_distinct_paths": projected,
            })
        else:
            stop = {
                "cohort_index": None,
                "reason": "at_cap" if len(current) == MAXIMUM_PATHS else "smaller_boundary",
                "projected_distinct_paths": len(current),
                "boundary_reason": final_boundary,
            }
    return {
        "kind": "compatible-280-count-preview",
        "starting_distinct_paths": initial,
        "ending_distinct_paths": len(current),
        "maximum_paths": MAXIMUM_PATHS,
        "accepted_cohorts": accepted,
        "stop": stop,
        "padding_allowed": False,
        "new_draft_created": False,
        "requires_root": True,
    }
