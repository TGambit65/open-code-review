# SPDX-License-Identifier: Apache-2.0
"""Fixture expectations are not target policy and never grant execution authority."""
from ocr_security.common import Refusal, canonical, digest, fields, sha
from .contracts import choice, unique


def fixture_outcome(expectation,observation,target_decision):
    fields(expectation,("case_id","fixture_sha256","polarity","expected_rule_hashes"))
    fields(observation,("fixture_sha256","rule_hashes","process_status","coverage_complete","execution_receipt_sha256"))
    choice(expectation["polarity"],("positive","negative"))
    sha(expectation["fixture_sha256"]);sha(observation["execution_receipt_sha256"])
    expected={sha(x) for x in unique(expectation["expected_rule_hashes"],256)}
    found={sha(x) for x in unique(observation["rule_hashes"],256)}
    if expectation["polarity"]=="positive" and not expected:raise Refusal("empty_positive_expectation")
    if expectation["polarity"]=="negative" and expected:raise Refusal("invalid_negative_expectation")
    bound=expectation["fixture_sha256"]==observation["fixture_sha256"]
    reliable=bound and observation["process_status"]=="success" and observation["coverage_complete"] is True
    detected=expected<=found if expectation["polarity"]=="positive" else not found
    # A positive expected defect can qualify the detector while blocking the target.
    separated=expectation["polarity"]!="positive" or target_decision.get("status")!="pass"
    return {"kind":"fixture-qualification-evaluation","case_id_sha256":digest(canonical(expectation["case_id"])),
            "fixture_sha256":expectation["fixture_sha256"],"qualification":"passed" if reliable and detected and separated else "failed",
            "target_status":target_decision.get("status","not-run"),"target_clearance_granted":False,"execution_enabled":False}
