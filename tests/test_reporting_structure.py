from datetime import datetime, timezone

from audit.models import (
    DKIMAnalysis,
    DMARCAnalysis,
    DnsSnapshot,
    EvidencePack,
    MTASTSAnalysis,
    SPFAnalysis,
    ScoreBreakdown,
    TLSRPTAnalysis,
)
from audit.report.renderer import build_executive_json


def _sample_evidence() -> EvidencePack:
    return EvidencePack(
        version="test",
        report_name="Email Security Posture Assessment - example.com",
        timestamp=datetime.now(timezone.utc),
        domain="example.com",
        resolver="system",
        runtime={"timeout": 6.0},
        dns=DnsSnapshot(spf=["v=spf1 include:_spf.a ~all"], dmarc=["v=DMARC1; p=none"]),
        spf=SPFAnalysis(
            exists=True,
            record="v=spf1 include:_spf.a ~all",
            softfail=True,
            include_chain=["example.com", "_spf.a"],
            third_party_senders=["mailgun", "salesforce", "sendgrid", "hubspot"],
        ),
        dmarc=DMARCAnalysis(exists=True, record="v=DMARC1; p=none", policy="none", tags={"p": "none"}),
        dkim=DKIMAnalysis(missing=True),
        smtp=[],
        mtasts=MTASTSAnalysis(),
        tlsrpt=TLSRPTAnalysis(),
        findings=[],
        score=ScoreBreakdown(total=45, auth=20, transport=20, hardening=5, maturity_tier="Tier 3 (Transitional)", risk_level_badge="High"),
    )


def test_executive_json_includes_requested_reporting_sections() -> None:
    payload = build_executive_json(_sample_evidence())
    assert "score_breakdown" in payload
    assert "top_5_risks" in payload
    assert "technical_appendix" in payload
    assert "mx_records" in payload["technical_appendix"]
    assert "mx_host_resolution" in payload["technical_appendix"]
    assert "stakeholder_views" in payload
