"""Deterministic evidence/finding aggregation for scan sessions."""
from __future__ import annotations

from masterkey_agent.core.models import Evidence, Finding, ModuleResult

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def correlate_results(results: list[ModuleResult]) -> tuple[list[Evidence], list[Finding]]:
    evidence_by_id: dict[str, Evidence] = {}
    findings_by_id: dict[str, Finding] = {}

    for result in results:
        for item in result.evidence:
            evidence_by_id.setdefault(item.id, item)
        for item in result.findings:
            findings_by_id.setdefault(item.id, item)

    valid_refs = set(evidence_by_id)
    findings: list[Finding] = []
    for item in findings_by_id.values():
        item.validate()
        item.evidence_refs = sorted(
            ref for ref in dict.fromkeys(item.evidence_refs) if ref in valid_refs
        )
        findings.append(item)

    evidence = sorted(
        evidence_by_id.values(),
        key=lambda item: (item.source_module, item.evidence_type, item.id),
    )
    findings.sort(
        key=lambda item: (_SEVERITY_ORDER[item.severity], item.category, item.id)
    )
    return evidence, findings
