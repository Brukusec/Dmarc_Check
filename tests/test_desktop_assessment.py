from datetime import datetime, timezone
from pathlib import Path

from audit.desktop.assessment import AssessmentService, DomainAssessmentResult
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


def test_safe_report_filename_normalizes_and_sanitizes() -> None:
    name = AssessmentService.safe_report_filename("Example.COM/Bad:Name", "html")
    assert name.startswith("report_example.com_bad_name_")
    assert name.endswith(".html")


def test_normalize_domain() -> None:
    assert AssessmentService.normalize_domain(" ExAmPle.com. ") == "example.com"


def test_run_assessment_writes_aggregate_outputs(tmp_path: Path) -> None:
    service = AssessmentService()
    shared = Finding(
        id="DMARC_NONE",
        severity="High",
        title="DMARC monitoring only",
        description="Policy in monitor mode.",
        evidence="p=none",
        remediation="Move to quarantine/reject",
    )

    def make_evidence(domain: str) -> EvidencePack:
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
            findings=[shared],
            score=ScoreBreakdown(total=55, maturity_tier="Tier 3 (Transitional)"),
        )

    original = service._assess_one

    def _stub(
        domain: str,
        output_dir: Path,
        output_format: str,
        resolve_spf_chains: bool,
        write_json: bool,
        write_pdf: bool,
        log,
    ) -> DomainAssessmentResult:
        return DomainAssessmentResult(
            domain=domain,
            score=55,
            tier="Tier 3 (Transitional)",
            spf_status="Present",
            dkim_status="Detected",
            dmarc_status="none",
            status="Completed",
            evidence=make_evidence(domain),
        )

    service._assess_one = _stub  # type: ignore[assignment]
    try:
        results = service.run_assessment(
            domains=["a.com", "b.com"],
            output_dir=tmp_path,
            output_format="HTML",
            resolve_spf_chains=False,
            write_json=False,
            write_pdf=False,
            log=lambda _msg: None,
            progress=lambda _n: None,
        )
    finally:
        service._assess_one = original  # type: ignore[assignment]

    assert len(results) == 2
    assert (tmp_path / "full_report.json").exists()
    assert (tmp_path / "all_issues.csv").exists()
