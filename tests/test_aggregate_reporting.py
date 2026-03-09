from datetime import datetime, timezone

from audit.aggregate import build_full_report
from audit.models import (
    DKIMAnalysis,
    DMARCAnalysis,
    DnsSnapshot,
    EvidencePack,
    Finding,
    MTASTSAnalysis,
    SPFAnalysis,
    ScoreBreakdown,
    TLSRPTAnalysis,
)


def _evidence(domain: str, score: int, findings: list[Finding]) -> EvidencePack:
    return EvidencePack(
        version="test",
        report_name=f"Report {domain}",
        timestamp=datetime.now(timezone.utc),
        domain=domain,
        resolver="system",
        runtime={"timeout": 6.0},
        dns=DnsSnapshot(),
        spf=SPFAnalysis(),
        dmarc=DMARCAnalysis(),
        dkim=DKIMAnalysis(),
        smtp=[],
        mtasts=MTASTSAnalysis(),
        tlsrpt=TLSRPTAnalysis(),
        findings=findings,
        score=ScoreBreakdown(total=score, maturity_tier="Tier 3 (Transitional)"),
    )


def test_build_full_report_aggregates_domains_and_issues() -> None:
    shared = Finding(
        id="DMARC_NONE",
        severity="High",
        title="DMARC monitoring only",
        description="Policy in monitor mode.",
        evidence="p=none",
        remediation="Move to quarantine/reject",
    )
    unique = Finding(
        id="TLSRPT_MISSING",
        severity="Medium",
        title="TLS-RPT missing",
        description="No TLS-RPT",
        evidence="absent",
        remediation="Add rua",
    )
    evidences = [
        _evidence("b.com", 30, [shared]),
        _evidence("a.com", 60, [shared, unique]),
    ]

    report = build_full_report(evidences)

    assert report["domains_total"] == 2
    assert report["issues_total"] == 3
    assert report["severity_totals"]["High"] == 2
    assert report["domain_summary"][0]["domain"] == "b.com"
    assert report["domain_summary"][1]["domain"] == "a.com"

    top_issue = report["aggregated_issues"][0]
    assert top_issue["id"] == "DMARC_NONE"
    assert top_issue["count"] == 2
    assert top_issue["domains"] == ["a.com", "b.com"]
