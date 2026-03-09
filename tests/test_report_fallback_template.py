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
from audit.report import renderer


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
            third_party_senders=["mailgun"],
        ),
        dmarc=DMARCAnalysis(exists=True, record="v=DMARC1; p=none", policy="none", tags={"p": "none"}),
        dkim=DKIMAnalysis(missing=True),
        smtp=[],
        mtasts=MTASTSAnalysis(),
        tlsrpt=TLSRPTAnalysis(),
        findings=[],
        score=ScoreBreakdown(
            total=45,
            auth=20,
            transport=20,
            hardening=5,
            maturity_tier="Tier 3 (Transitional)",
            risk_level_badge="High",
        ),
    )


def test_fallback_template_remains_full_report(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(renderer.Path, "exists", lambda _: False)
    output_path = tmp_path / "report.html"

    renderer.render_html(_sample_evidence(), output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "Executive Summary" in html
    assert "Score Breakdown" in html
    assert "Technical Appendix" in html
    assert "MX Records" in html
