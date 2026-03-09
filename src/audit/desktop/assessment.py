from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from audit import __version__
from audit.aggregate import write_aggregated_issues_csv, write_full_report
from audit.bimi import analyze_bimi
from audit.dkim import analyze_dkim
from audit.dmarc import analyze_dmarc
from audit.dns import COMMON_SELECTORS, DNSClient
from audit.findings import build_findings
from audit.models import EvidencePack, ScoreBreakdown
from audit.mtasts import analyze_mtasts
from audit.report.renderer import build_executive_json, render_html
from audit.scoring import score
from audit.spf import analyze_spf
from audit.tlsrpt import analyze_tlsrpt

INVALID_WINDOWS_CHARS = re.compile(r'[<>:"/\\|?*]')


@dataclass
class DomainAssessmentResult:
    domain: str
    score: int
    tier: str
    spf_status: str
    dkim_status: str
    dmarc_status: str
    status: str
    report_path: Path | None = None
    json_path: Path | None = None
    evidence: EvidencePack | None = None
    error: str | None = None


class AssessmentService:
    def __init__(self, timeout: float = 6.0, resolver: str | None = None):
        self.timeout = timeout
        self.resolver = resolver

    @staticmethod
    def normalize_domain(domain: str) -> str:
        return domain.strip().lower().rstrip(".")

    @staticmethod
    def safe_report_filename(domain: str, extension: str = "html") -> str:
        normalized = AssessmentService.normalize_domain(domain)
        safe_domain = INVALID_WINDOWS_CHARS.sub("_", normalized)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        return f"report_{safe_domain}_{stamp}.{extension}"

    def run_assessment(
        self,
        domains: list[str],
        output_dir: Path,
        output_format: str,
        resolve_spf_chains: bool,
        write_json: bool,
        write_pdf: bool,
        log: Callable[[str], None],
        progress: Callable[[int], None],
    ) -> list[DomainAssessmentResult]:
        output_dir.mkdir(parents=True, exist_ok=True)
        results: list[DomainAssessmentResult] = []
        evidences: list[EvidencePack] = []

        total = max(1, len(domains))
        for idx, domain in enumerate(domains, start=1):
            normalized = self.normalize_domain(domain)
            log(f"[{idx}/{total}] Assessing domain: {normalized}")
            try:
                result = self._assess_one(
                    normalized,
                    output_dir=output_dir,
                    output_format=output_format,
                    resolve_spf_chains=resolve_spf_chains,
                    write_json=write_json,
                    write_pdf=write_pdf,
                    log=log,
                )
            except Exception as exc:  # noqa: BLE001
                log(f"ERROR {normalized}: {exc}")
                result = DomainAssessmentResult(
                    domain=normalized,
                    score=0,
                    tier="Tier 1 (Critical Exposure)",
                    spf_status="Error",
                    dkim_status="Error",
                    dmarc_status="Error",
                    status="Failed",
                    error=str(exc),
                )
            results.append(result)
            if result.evidence is not None:
                evidences.append(result.evidence)
            progress(int((idx / total) * 100))

        if evidences:
            full_report_path = output_dir / "full_report.json"
            issues_csv_path = output_dir / "all_issues.csv"
            write_full_report(evidences, full_report_path)
            write_aggregated_issues_csv(evidences, issues_csv_path)
            log(f"Aggregate full report written: {full_report_path}")
            log(f"Aggregate issues CSV written: {issues_csv_path}")

        return results

    def _assess_one(
        self,
        domain: str,
        output_dir: Path,
        output_format: str,
        resolve_spf_chains: bool,
        write_json: bool,
        write_pdf: bool,
        log: Callable[[str], None],
    ) -> DomainAssessmentResult:
        client = DNSClient(nameserver=self.resolver, timeout=self.timeout)
        dns = client.discover(domain)
        log(f"DNS lookups complete for {domain}: MX={len(dns.mx)} SPF={len(dns.spf)} DMARC={len(dns.dmarc)}")

        lookup_fn = client.query_spf_txt if resolve_spf_chains else None
        spf = analyze_spf(dns.spf, domain, lookup_fn)
        dmarc = analyze_dmarc(dns.dmarc)
        dkim = analyze_dkim(dns.dkim, COMMON_SELECTORS)
        mtasts = analyze_mtasts(dns.mtasts, domain, timeout=self.timeout)
        tlsrpt = analyze_tlsrpt(dns.tlsrpt)
        bimi = analyze_bimi(dns.bimi)

        findings = build_findings(spf, dmarc, dkim, mtasts, tlsrpt, smtp_starttls_ratio=0.0, smtp_results=[])
        score_map = score(spf, dmarc, dkim, mtasts, tlsrpt, 0.0, bool(bimi["present"]))

        evidence = EvidencePack(
            version=__version__,
            report_name=f"Email Security Posture Assessment - {domain}",
            timestamp=datetime.now(timezone.utc),
            domain=domain,
            resolver=self.resolver or "system",
            runtime={"timeout": self.timeout, "desktop_mode": True},
            dns=dns,
            spf=spf,
            dmarc=dmarc,
            dkim=dkim,
            smtp=[],
            mtasts=mtasts,
            tlsrpt=tlsrpt,
            findings=findings,
            score=ScoreBreakdown(**score_map),
        )

        html_path: Path | None = None
        json_path: Path | None = None

        if output_format in {"HTML", "Both"}:
            html_path = output_dir / self.safe_report_filename(domain, "html")
            render_html(evidence, html_path)
            log(f"HTML report written: {html_path}")

        if output_format in {"JSON", "Both"} or write_json:
            json_path = output_dir / self.safe_report_filename(domain, "json")
            payload = {
                "evidence": evidence.model_dump(mode="json"),
                "executive": build_executive_json(evidence),
            }
            json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            log(f"JSON report written: {json_path}")

        if write_pdf:
            log("PDF export requested. Optional: add WeasyPrint/reportlab pipeline for PDF generation.")

        return DomainAssessmentResult(
            domain=domain,
            score=evidence.score.total,
            tier=evidence.score.maturity_tier,
            spf_status="Hardfail" if spf.hardfail else ("Softfail" if spf.softfail else "Present"),
            dkim_status="Missing" if dkim.missing else "Detected",
            dmarc_status=dmarc.policy if dmarc.exists else "Missing",
            status="Completed",
            report_path=html_path,
            json_path=json_path,
            evidence=evidence,
        )
