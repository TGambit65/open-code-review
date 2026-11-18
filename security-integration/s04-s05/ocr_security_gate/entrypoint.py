# SPDX-License-Identifier: Apache-2.0
"""One read-only assessment path. Artifacts are returned in memory, never uploaded."""
from dataclasses import dataclass
from ocr_security.common import canonical, digest
from .gate import evaluate
from .reports import project, render


@dataclass(frozen=True)
class Assessment:
    private_decision: bytes
    public_artifacts: tuple
    public_report_sha256: str


def assess(target,policy,evidence,snapshot,views,current_set,previous_set,now,excerpt_ranges=(),**evidence_options):
    decision=evaluate(target,policy,evidence,snapshot,current_set,previous_set,now,**evidence_options)
    public=project(decision,evidence,views,snapshot,excerpt_ranges)
    artifacts=tuple((name,render(public,format)) for name,format in
                    (("security-report.json","json"),("security-report.md","markdown"),("security-report.html","html")))
    return Assessment(canonical(decision),artifacts,public.sha256)


def artifact_receipts(assessment):
    return {"public_report_sha256":assessment.public_report_sha256,
            "files":[{"name":name,"sha256":digest(raw),"bytes":len(raw)} for name,raw in assessment.public_artifacts],
            "private_decision_sha256":digest(assessment.private_decision),"files_written":False,"uploaded":False}
