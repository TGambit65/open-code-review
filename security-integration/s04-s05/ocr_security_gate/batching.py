# SPDX-License-Identifier: Apache-2.0
"""Whole-PR distinct-path budgeting; source preservation never waits for filler."""
from ocr_security.common import Refusal, relative_path
from .contracts import sequence, choice


def batch_decision(existing_paths,next_coherent_paths,remaining_eligible,final_boundary=None):
    old={relative_path(x) for x in sequence(existing_paths,10000)}
    upcoming={relative_path(x) for x in sequence(next_coherent_paths,10000)}
    if type(remaining_eligible) is not bool:raise Refusal("invalid_eligibility")
    if final_boundary is not None:choice(final_boundary,("final_scope","dependency_hold","no_eligible_work"))
    current,projected=len(old),len(old|upcoming)
    if current>300:decision="hold_over_cap_existing_batch"
    elif projected>300:decision="preserve_current_then_dependent_draft"
    elif current>=200:decision="freeze_current_batch"
    elif remaining_eligible and upcoming:decision="preserve_then_continue_coherent_scope"
    elif final_boundary is not None:decision="document_smaller_boundary"
    else:decision="preserve_and_resolve_next_scope"
    return {"kind":"distinct-path-batch-decision","current_distinct_paths":current,"next_new_paths":len(upcoming-old),
            "projected_distinct_paths":projected,"decision":decision,"boundary_reason":final_boundary,
            "minimum_target":200,"maximum_paths":300,"padding_allowed":False,"preservation_delayed":False,
            "new_draft_created":False,"requires_root":True}
