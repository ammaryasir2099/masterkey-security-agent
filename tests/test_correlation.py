from masterkey_agent.core.correlation import correlate_results
from masterkey_agent.core.models import Evidence, Finding, ModuleResult


def test_correlation_deduplicates_findings_and_sorts_deterministically():
    evidence = Evidence("ev-2", "b", "header.csp", "observed")
    finding_b = Finding(
        "finding-b",
        "B",
        "low",
        "security_headers",
        "B",
        evidence_refs=["ev-2", "ev-missing"],
    )
    finding_a = Finding(
        "finding-a",
        "A",
        "info",
        "content",
        "A",
        evidence_refs=["ev-2"],
    )
    results = [
        ModuleResult("b", True, evidence=[evidence], findings=[finding_b]),
        ModuleResult("a", True, evidence=[evidence], findings=[finding_b, finding_a]),
    ]

    correlated_evidence, findings = correlate_results(results)
    assert [item.id for item in correlated_evidence] == ["ev-2"]
    assert [item.id for item in findings] == ["finding-a", "finding-b"]
    assert findings[1].evidence_refs == ["ev-2"]
    assert all(
        ref in {item.id for item in correlated_evidence}
        for finding in findings
        for ref in finding.evidence_refs
    )


def test_correlation_rejects_unknown_finding_severity():
    result = ModuleResult(
        "test",
        True,
        findings=[Finding("f", "Example", "critical", "test", "Example")],
    )
    try:
        correlate_results([result])
    except ValueError as exc:
        assert "severity" in str(exc)
    else:
        raise AssertionError("invalid severity must be rejected")
