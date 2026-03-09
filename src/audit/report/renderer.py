from __future__ import annotations

import sys
from pathlib import Path

from jinja2 import DictLoader, Environment, FileSystemLoader, select_autoescape

from audit.models import EvidencePack

FALLBACK_REPORT_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\">
  <title>{{ e.report_name }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #0f172a; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
    th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #e2e8f0; }
    .meta { color: #475569; font-size: 13px; }
  </style>
</head>
<body>
  <h1>{{ e.report_name }}</h1>
  <p class=\"meta\"><strong>Domain:</strong> {{ e.domain }} | <strong>Timestamp:</strong> {{ report_generated }} | <strong>Tool Version:</strong> {{ e.version }} | <strong>Resolver:</strong> {{ e.resolver }}</p>
  <p class=\"meta\"><strong>Runtime Parameters:</strong> {{ e.runtime }}</p>

  <h2>Executive Summary</h2>
  <p><strong>Overall Score:</strong> {{ e.score.total }}/100 ({{ e.score.risk_level_badge }})</p>
  <p><strong>Maturity:</strong> {{ e.score.maturity_tier }}</p>

  <h2>Score Breakdown</h2>
  <table>
    <tr><th>Category</th><th>Weight</th><th>Score</th></tr>
    <tr><td>Auth posture (SPF/DKIM/DMARC)</td><td>50%</td><td>{{ e.score.auth }}/50</td></tr>
    <tr><td>Transport security (STARTTLS, cert hygiene, MTA-STS, TLS-RPT)</td><td>40%</td><td>{{ e.score.transport }}/40</td></tr>
    <tr><td>Brand/hardening (BIMI, hygiene)</td><td>10%</td><td>{{ e.score.hardening }}/10</td></tr>
  </table>

  <h2>Top 5 Risks</h2>
  <table>
    <tr><th>#</th><th>Severity</th><th>Description</th></tr>
    {% for risk in top_5_risks %}
    <tr><td>{{ loop.index }}</td><td>{{ risk.severity }}</td><td>{{ risk.description }}</td></tr>
    {% endfor %}
  </table>

  <h2>Findings</h2>
  <table>
    <tr><th>ID</th><th>Severity</th><th>Description</th><th>Evidence</th><th>Remediation</th></tr>
    {% for f in e.findings %}
    <tr><td>{{ f.id }}</td><td>{{ f.severity }}</td><td>{{ f.description }}</td><td>{{ f.evidence }}</td><td>{{ f.remediation }}</td></tr>
    {% endfor %}
  </table>

  <h2>Technical Appendix</h2>
  <h3>Raw DNS Answers</h3>
  <pre>{{ e.dns.raw }}</pre>
  <h3>MX Probe Results</h3>
  <pre>{{ e.smtp }}</pre>
</body>
</html>
"""


def _report_environment() -> Environment:
    template_dirs = [Path(__file__).parent / "templates"]
    if getattr(sys, "_MEIPASS", None):
        meipass = Path(sys._MEIPASS)
        template_dirs.extend([meipass / "audit" / "report" / "templates", meipass / "report" / "templates"])

    existing_dirs = [str(path) for path in template_dirs if path.exists()]
    if existing_dirs:
        return Environment(loader=FileSystemLoader(existing_dirs), autoescape=select_autoescape())

    return Environment(loader=DictLoader({"report.html.j2": FALLBACK_REPORT_TEMPLATE}), autoescape=select_autoescape())


def build_executive_json(evidence: EvidencePack) -> dict:
    return {
        "report_metadata": {
            "report_name": evidence.report_name,
            "domain": evidence.domain,
            "assessment_date": evidence.timestamp.date().isoformat(),
            "generated_at": evidence.timestamp.isoformat(),
            "tool_version": evidence.version,
            "resolver": evidence.resolver,
            "runtime_parameters": evidence.runtime,
        },
        "posture": {
            "overall_score": evidence.score.total,
            "severity_band": evidence.score.risk_level_badge,
            "maturity_tier": evidence.score.maturity_tier,
        },
        "score_breakdown": {
            "auth_posture_50": evidence.score.auth,
            "transport_security_40": evidence.score.transport,
            "brand_hardening_10": evidence.score.hardening,
        },
        "top_5_risks": _top_risks(evidence),
        "issues": [finding.model_dump() for finding in evidence.findings],
        "stakeholder_views": _stakeholder_views(evidence),
        "maturity_model": {
            "weights": {"auth": "50%", "transport": "40%", "hardening": "10%"},
            "severity_bands": ["Critical", "High", "Medium", "Low", "Info"],
        },
        "technical_appendix": {
            "dns_raw": evidence.dns.raw,
            "mx_probe_results": [row.model_dump() for row in evidence.smtp],
        },
    }


def render_html(evidence: EvidencePack, out_path: Path) -> None:
    env = _report_environment()
    tpl = env.get_template("report.html.j2")
    out = tpl.render(
        e=evidence,
        report_generated=evidence.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z"),
        top_5_risks=_top_risks(evidence),
        severity_order={"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4},
    )
    out_path.write_text(out.replace("\\n", "\n"), encoding="utf-8")


def _top_risks(evidence: EvidencePack) -> list[dict[str, str]]:
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    ranked = sorted(evidence.findings, key=lambda item: (severity_rank.get(item.severity, 99), item.id))
    return [
        {"id": finding.id, "severity": finding.severity, "description": finding.description}
        for finding in ranked[:5]
    ]


def _stakeholder_views(e: EvidencePack) -> dict[str, list[str]]:
    return {
        "red_team": ["Focus on spoofing paths exposed by DMARC/SPF/DKIM gaps."],
        "blue_team": ["Track rua/tlsrpt telemetry and triage anomalies daily."],
        "security_architecture": ["Drive strict alignment and transport policy standardization."],
    }
