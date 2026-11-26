"""Detached private projection of fictional status records, not authority."""

from dataclasses import dataclass

_STAGES = (
    ("implementation", ()),
    ("independent_source_review", ("implementation",)),
    ("remote_preservation", ("implementation",)),
    ("offline_fixtures", ("remote_preservation",)),
    ("native_baseline", ("remote_preservation",)),
    ("sanitized_review", ("remote_preservation",)),
    ("rendering", ("remote_preservation",)),
    ("independent_evidence_review", (
        "implementation", "independent_source_review", "remote_preservation",
        "offline_fixtures", "native_baseline", "sanitized_review", "rendering",
    )),
)
_STAGE_IDS = frozenset(stage for stage, _ in _STAGES)
_DISPLAY = {
    "passed": "complete", "failed": "blocked", "blocked": "blocked",
    "partial": "blocked", "unrun": "unrun",
}


@dataclass(frozen=True)
class StageView:
    stage: str
    status: str
    prerequisites: tuple[str, ...]
    unmet_prerequisites: tuple[str, ...]


@dataclass(frozen=True)
class Handoff:
    stages: tuple[StageView, ...]
    qualification: str = "HELD"


def project(records: tuple[dict[str, str], ...]) -> Handoff:
    """Summarize only closed stage/result pairs; reject ambiguous input."""
    by_stage = _reported_states(records)
    return Handoff(tuple(
        StageView(stage, by_stage.get(stage, "missing"), prerequisites, tuple(
            prior for prior in prerequisites if by_stage.get(prior) != "complete"
        ))
        for stage, prerequisites in _STAGES
    ))


def _reported_states(records):
    if type(records) is not tuple or len(records) > len(_STAGES):
        raise ValueError("Expected a bounded tuple of fictional stage records.")
    by_stage: dict[str, str] = {}
    for record in records:
        if type(record) is not dict or len(record) != 2:
            raise ValueError("Expected stage and result fields only.")
        if any(type(key) is not str for key in record) or record.keys() != {"stage", "result"}:
            raise ValueError("Expected stage and result fields only.")
        stage, result = record["stage"], record["result"]
        if type(stage) is not str or stage not in _STAGE_IDS or stage in by_stage:
            raise ValueError("Unknown or duplicate stage.")
        if type(result) is not str or result not in _DISPLAY:
            raise ValueError("Unknown stage result.")
        by_stage[stage] = _DISPLAY[result]
    return by_stage


@dataclass(frozen=True)
class SupportedStageView(StageView):
    reported_status: str


@dataclass(frozen=True)
class SupportedHandoff:
    stages: tuple[SupportedStageView, ...]
    qualification: str = "HELD"


def project_supported(records: tuple[dict[str, str], ...]) -> SupportedHandoff:
    """Opt in to a dependency-supported view; no external evidence is checked."""
    by_stage = _reported_states(records)
    # The fixed inventory lists each prerequisite before its dependents.
    supported = set()
    rows = []
    for stage, prerequisites in _STAGES:
        unmet = tuple(prior for prior in prerequisites if prior not in supported)
        reported = by_stage.get(stage, "missing")
        status = reported
        if reported == "complete":
            if unmet:
                status = "blocked"
            else:
                supported.add(stage)
        rows.append(SupportedStageView(stage, status, prerequisites, unmet, reported))
    return SupportedHandoff(tuple(rows))


def render(records: tuple[dict[str, str], ...]) -> str:
    """Render a bounded examiner note from the checked records only."""
    view = project(records)
    lines = [f"Qualification: {view.qualification} (fictional status only; no authority)."]
    for row in view.stages:
        required = ", ".join(row.prerequisites) or "none"
        unmet = ", ".join(row.unmet_prerequisites) or "none"
        lines.append(f"{row.stage}: {row.status}; prerequisites: {required}; unmet: {unmet}.")
    ready = (row.stage for row in view.stages
             if row.status != "complete" and not row.unmet_prerequisites)
    waiting = (row.stage for row in view.stages if row.unmet_prerequisites)
    lines.append("Ready for human evidence (listed prerequisites only): " + (", ".join(ready) or "none") + ".")
    lines.append("Unmet prerequisite group: " + (", ".join(waiting) or "none") + ".")
    return "\n".join(lines) + "\n"


def render_supported(records: tuple[dict[str, str], ...]) -> str:
    """Opt in to a fixed private note about fictional declared metadata only."""
    view = project_supported(records)
    lines = [
        f"Qualification: {view.qualification} "
        "(fictional declared metadata only; no external evidence checked; no authority)."
    ]
    for row in view.stages:
        unmet = ", ".join(row.unmet_prerequisites) or "none"
        lines.append(
            f"{row.stage}: declared: {row.reported_status}; "
            f"prerequisite-supported status: {row.status}; "
            f"direct unmet prerequisites: {unmet}."
        )
    return "\n".join(lines) + "\n"
