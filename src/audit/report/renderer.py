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
    .meta { color: #475569; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; }
    th { background: #e2e8f0; }
  </style>
</head>
<body>
  <h1>{{ e.report_name }}</h1>
  <p class=\"meta\">Domain: {{ e.domain }} | Generated: {{ report_generated }}</p>
  <h2>Score Summary</h2>
  <p><strong>Overall Security Score:</strong> {{ e.score.total }}/100 ({{ e.score.maturity_tier }})</p>
  <h2>Control Dashboard</h2>
  <table>
    <tr><th>Control Area</th><th>Status</th><th>Risk Level</th><th>Maturity</th></tr>
    {% for row in dashboard_rows %}
    <tr>
      <td>{{ row.control_area }}</td><td>{{ row.status }}</td><td>{{ row.risk_level }}</td><td>{{ row.maturity }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


def _report_environment() -> Environment:
    template_dirs = [Path(__file__).parent / "templates"]
    if getattr(sys, "_MEIPASS", None):
        meipass = Path(sys._MEIPASS)
        template_dirs.extend(
            [
                meipass / "audit" / "report" / "templates",
                meipass / "report" / "templates",
            ]
        )

    existing_dirs = [str(path) for path in template_dirs if path.exists()]
    if existing_dirs:
        return Environment(loader=FileSystemLoader(existing_dirs), autoescape=select_autoescape())

    return Environment(
        loader=DictLoader({"report.html.j2": FALLBACK_REPORT_TEMPLATE}),
        autoescape=select_autoescape(),
    )


def build_executive_json(evidence: EvidencePack) -> dict:
    control_rows = _control_dashboard(evidence)
    top_actions = _top_actions(evidence)
    issues = _issue_breakdown(evidence)
    return {
        "report_metadata": {
            "report_name": evidence.report_name,
            "domain": evidence.domain,
            "assessment_date": evidence.timestamp.date().isoformat(),
            "generated_at": evidence.timestamp.isoformat(),
        },
        "posture": {
            "overall_score": evidence.score.total,
            "maturity_tier": evidence.score.maturity_tier,
            "maturity_level": evidence.score.maturity_tier_level,
            "risk_level": evidence.score.risk_level_badge,
            "risk_trend_classification": _risk_trend(evidence.score.maturity_tier_level),
            "is_spoofing_resistant": evidence.dmarc.policy == "reject" and evidence.spf.hardfail,
            "enforcement_status": evidence.dmarc.enforcement_level,
        },
        "dashboard": control_rows,
        "weighted_scoring": {
            "dmarc_enforcement_30": evidence.score.dmarc_enforcement,
            "dkim_presence_alignment_25": evidence.score.dkim_alignment,
            "spf_strength_20": evidence.score.spf_strength,
            "sender_inventory_hygiene_15": evidence.score.sender_hygiene,
            "monitoring_reporting_10": evidence.score.monitoring,
        },
        "risk_exposure": {
            "business_impacts": _business_impacts(evidence),
            "key_exposures": _key_exposures(evidence),
            "likelihood": _likelihood(evidence),
            "impact": _impact(evidence),
            "confidence": _assessment_confidence(evidence),
        },
        "issues": issues,
        "stakeholder_views": _stakeholder_views(evidence),
        "remediation_roadmap": _roadmap(evidence),
        "top_priority_actions": top_actions,
        "maturity_model": {
            "tier_meaning": _tier_meaning(evidence.score.maturity_tier_level),
            "tier5_target": "Tier 5 represents reject-level DMARC, strict sender governance, stable DKIM rotation, and continuous monitoring workflows.",
        },
    }


def render_html(evidence: EvidencePack, out_path: Path) -> None:
    env = _report_environment()
    tpl = env.get_template("report.html.j2")
    out = tpl.render(
        e=evidence,
        dashboard_rows=_control_dashboard(evidence),
        key_exposures=_key_exposures(evidence),
        business_impacts=_business_impacts(evidence),
        risk_trend=_risk_trend(evidence.score.maturity_tier_level),
        top_actions=_top_actions(evidence),
        spf_policy=("-all" if evidence.spf.hardfail else ("~all" if evidence.spf.softfail else "other/unknown")),
        hardcoded_ips=evidence.spf.ip4_count + evidence.spf.ip6_count,
        report_generated=evidence.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z"),
        roadmap=_roadmap(evidence),
        issues=_issue_breakdown(evidence),
        stakeholder_views=_stakeholder_views(evidence),
        assessment_confidence=_assessment_confidence(evidence),
        tier_meaning=_tier_meaning(evidence.score.maturity_tier_level),
        likelihood=_likelihood(evidence),
        impact=_impact(evidence),
    )
    out_path.write_text(out, encoding="utf-8")


def _risk_trend(maturity_level: int) -> str:
    mapping = {1: "Early-stage control", 2: "Early-stage control", 3: "Transitional", 4: "Mature", 5: "Hardened"}
    return mapping.get(maturity_level, "Transitional")


def _key_exposures(e: EvidencePack) -> list[str]:
    exposures: list[str] = []
    if e.dmarc.policy == "none":
        exposures.append("Weak DMARC enforcement (p=none) leaves spoofed messages in monitoring mode.")
    if e.spf.softfail:
        exposures.append("SPF softfail (~all) can increase acceptance of unauthorized sending infrastructure.")
    if len(e.spf.third_party_senders) > 3:
        exposures.append("Excessive third-party senders broaden trust boundaries and governance overhead.")
    if e.dkim.missing:
        exposures.append("Missing DKIM coverage reduces non-repudiation and impairs DMARC alignment outcomes.")
    if e.spf.lookup_count > 10:
        exposures.append("Overly complex SPF record risks permerror and operational fragility.")
    return exposures or ["No major exposure patterns identified from current telemetry."]


def _business_impacts(e: EvidencePack) -> list[str]:
    impacts = [
        "Brand impersonation and customer phishing risk if enforcement remains partial.",
        "Business Email Compromise (BEC) exposure through spoofed executive/vendor identities.",
        "Vendor payment fraud and invoice redirection risk in accounts payable workflows.",
        "Regulatory and audit pressure due to weak anti-spoofing policy governance.",
        "Customer trust erosion following abusive email campaigns using lookalike identity.",
    ]
    if e.score.total <= 60:
        impacts.append("Elevated financial fraud exposure due to insufficient sender authentication controls.")
    return impacts


def _control_dashboard(e: EvidencePack) -> list[dict[str, str]]:
    dmarc_status = f"p={e.dmarc.policy}" if e.dmarc.exists else "Missing"
    return [
        {"control_area": "SPF", "status": "Softfail" if e.spf.softfail else ("Hardened" if e.spf.hardfail else "Present"), "risk_level": "Moderate" if e.spf.softfail else "Low", "maturity": f"{4 if e.spf.hardfail else 3}/5"},
        {"control_area": "DKIM", "status": "Missing" if e.dkim.missing else "Enabled", "risk_level": "High" if e.dkim.missing else "Low", "maturity": f"{1 if e.dkim.missing else 4}/5"},
        {"control_area": "DMARC", "status": dmarc_status, "risk_level": "High" if e.dmarc.policy == "none" else "Low", "maturity": f"{2 if e.dmarc.policy == 'none' else 5}/5"},
        {"control_area": "Alignment", "status": "Partial" if "not" in e.spf.alignment_note.lower() else "Aligned", "risk_level": "Moderate", "maturity": "3/5"},
        {"control_area": "Monitoring", "status": "Enabled" if e.dmarc.reporting_enabled else "Partial", "risk_level": "Low" if e.dmarc.reporting_enabled else "Moderate", "maturity": f"{4 if e.dmarc.reporting_enabled else 2}/5"},
    ]


def _top_actions(e: EvidencePack) -> list[dict[str, str]]:
    actions = [
        {
            "action": "Advance DMARC from monitoring to quarantine policy with pct=100 and defined sp= policy.",
            "risk_reduction": "High",
            "complexity": "Medium",
            "owner": "Security Engineering",
        },
        {
            "action": "Validate universal DKIM signing across all production sender paths and retire weak selectors.",
            "risk_reduction": "High",
            "complexity": "Medium",
            "owner": "Blue Team",
        },
        {
            "action": "Rationalize SPF includes/IP ranges and enforce -all after sender inventory attestation.",
            "risk_reduction": "Medium",
            "complexity": "Medium",
            "owner": "Security Architecture",
        },
        {
            "action": "Enable DMARC forensic and aggregate report triage with weekly governance review.",
            "risk_reduction": "Medium",
            "complexity": "Low",
            "owner": "Blue Team",
        },
        {
            "action": "Create approved sender inventory with owner attestations and decommission SLAs.",
            "risk_reduction": "Medium",
            "complexity": "Medium",
            "owner": "Security Architecture",
        },
    ]
    if e.dmarc.policy == "reject":
        actions[0]["action"] = "Maintain DMARC reject policy with quarterly exception governance and drift monitoring."
    return actions


def _roadmap(e: EvidencePack) -> list[dict[str, object]]:
    _ = e
    return [
        {
            "phase": "PHASE 1 – Immediate Hardening (0–30 days)",
            "items": [
                {"recommendation": "Move DMARC to quarantine with pct=100.", "risk_reduction": "High", "complexity": "Low"},
                {"recommendation": "Validate DKIM signing for all active sender services.", "risk_reduction": "High", "complexity": "Medium", "owner": "Blue"},
                {"recommendation": "Inventory all authorized mail senders and business owners.", "risk_reduction": "High", "complexity": "Medium", "owner": "Arch"},
            ],
        },
        {
            "phase": "PHASE 2 – Enforcement (30–60 days)",
            "items": [
                {"recommendation": "Move DMARC policy to reject after controlled monitoring window.", "risk_reduction": "High", "complexity": "Medium", "owner": "Eng"},
                {"recommendation": "Replace SPF ~all with -all after validation.", "risk_reduction": "Medium", "complexity": "Low", "owner": "Eng"},
                {"recommendation": "Remove obsolete SPF IP ranges/includes.", "risk_reduction": "Medium", "complexity": "Medium", "owner": "Eng"},
            ],
        },
        {
            "phase": "PHASE 3 – Governance & Monitoring",
            "items": [
                {"recommendation": "Establish continuous DMARC monitoring with exception workflows.", "risk_reduction": "Medium", "complexity": "Low", "owner": "Blue"},
                {"recommendation": "Maintain a centralized sender inventory with quarterly ownership attestation.", "risk_reduction": "Medium", "complexity": "Medium", "owner": "Arch"},
                {"recommendation": "Run quarterly email posture reviews and board-level KPI reporting.", "risk_reduction": "Medium", "complexity": "Low", "owner": "Arch"},
            ],
        },
    ]


def _issue_breakdown(e: EvidencePack) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    if e.dmarc.policy == "none":
        issues.append(
            {
                "id": "ESPA-001",
                "severity": "High",
                "control": "DMARC",
                "description": "DMARC policy is in monitoring mode.",
                "evidence": f"Record: {e.dmarc.record or 'missing'}",
                "business_impact": "High spoofing opportunity and elevated BEC probability.",
                "likelihood": "Likely",
                "risk_rating": "High",
                "remediation": "Move policy to quarantine/reject with pct=100 and staged rollout.",
                "complexity": "Medium",
                "residual_risk": "Sustained direct-domain impersonation if untreated.",
            }
        )
    if e.spf.softfail:
        issues.append(
            {
                "id": "ESPA-002",
                "severity": "Moderate",
                "control": "SPF",
                "description": "SPF uses softfail (~all) rather than explicit fail (-all).",
                "evidence": f"SPF: {e.spf.record or 'missing'}",
                "business_impact": "Inconsistent rejection behavior can permit abuse at receiver discretion.",
                "likelihood": "Possible",
                "risk_rating": "Moderate",
                "remediation": "Complete sender inventory validation and transition to -all.",
                "complexity": "Low",
                "residual_risk": "Unauthorized relays may continue to pass in tolerant recipient ecosystems.",
            }
        )
    if len(e.spf.third_party_senders) > 3:
        issues.append(
            {
                "id": "ESPA-003",
                "severity": "Moderate",
                "control": "Sender Governance",
                "description": "Third-party sender footprint is broad and complex.",
                "evidence": f"Third-party senders: {', '.join(e.spf.third_party_senders)}",
                "business_impact": "Expanded trust boundary and increased vendor abuse risk.",
                "likelihood": "Possible",
                "risk_rating": "Moderate",
                "remediation": "Implement sender owner attestation and decommission orphaned senders.",
                "complexity": "Medium",
                "residual_risk": "Compromised vendors can still impersonate trusted traffic.",
            }
        )
    if not e.dmarc.ruf_present:
        issues.append(
            {
                "id": "ESPA-004",
                "severity": "Low",
                "control": "Monitoring",
                "description": "DMARC forensic reporting (ruf) is not configured.",
                "evidence": f"DMARC tags: {e.dmarc.tags}",
                "business_impact": "Reduced visibility into authentication failure details.",
                "likelihood": "Likely",
                "risk_rating": "Moderate",
                "remediation": "Add ruf mailbox or equivalent SOC telemetry intake path.",
                "complexity": "Low",
                "residual_risk": "Fine-grained incident triage remains slower.",
            }
        )
    if not e.dmarc.subdomain_policy:
        issues.append(
            {
                "id": "ESPA-005",
                "severity": "Moderate",
                "control": "DMARC",
                "description": "No explicit DMARC subdomain policy (sp=) is declared.",
                "evidence": f"DMARC tags: {e.dmarc.tags}",
                "business_impact": "Subdomains may be used for impersonation where controls drift.",
                "likelihood": "Possible",
                "risk_rating": "Moderate",
                "remediation": "Define explicit sp=quarantine/reject aligned with parent policy.",
                "complexity": "Low",
                "residual_risk": "Shadow subdomains can remain exploitable.",
            }
        )
    return issues


def _stakeholder_views(e: EvidencePack) -> dict[str, list[str]]:
    return {
        "red_team": [
            "External impersonation probability is elevated when DMARC is non-enforcing.",
            "Third-party sender sprawl increases opportunities for trusted-channel abuse.",
            "Softfail SPF reduces certainty of receiving-side rejection behavior.",
        ],
        "blue_team": [
            "Track rua/ruf reports daily and route anomalies to phishing response queues.",
            "Correlate DMARC failures with secure email gateway telemetry for rapid triage.",
            "Build detection use-cases for new, unapproved sender infrastructure.",
        ],
        "security_architecture": [
            "Current control layering should prioritize enforced DMARC plus strict SPF governance.",
            "Establish clear ownership per sender service and lifecycle controls.",
            "Define policy baseline requiring explicit subdomain controls and quarterly review.",
        ],
        "security_engineering": [
            "Sequence hardening as inventory → DKIM coverage → SPF strictness → DMARC reject.",
            "Automate SPF flattening/validation checks to prevent lookup-limit drift.",
            "Embed CI guardrails for DNS config changes impacting email authentication.",
        ],
        "executive": [
            f"Current score ({e.score.total}/100) indicates {e.score.risk_level_badge.lower()} residual risk to brand trust.",
            "Top value lever is completing DMARC enforcement and sender governance standardization.",
            "Weekly KPI reporting should cover spoofing attempts blocked and policy drift exceptions.",
        ],
    }


def _assessment_confidence(e: EvidencePack) -> str:
    if not e.spf.exists and not e.dmarc.exists:
        return "Medium"
    if e.spf.lookup_count > 10 or e.dkim.missing:
        return "Medium"
    return "High"


def _tier_meaning(level: int) -> str:
    meanings = {
        1: "Tier 1 indicates critical exposure with limited prevention and high abuse feasibility.",
        2: "Tier 2 reflects weak controls with inconsistent enforcement and poor resilience.",
        3: "Tier 3 reflects transitional posture with partial enforcement and governance gaps.",
        4: "Tier 4 indicates mature implementation with strong baseline control reliability.",
        5: "Tier 5 indicates hardened posture with strict policy enforcement and continuous monitoring.",
    }
    return meanings.get(level, meanings[3])


def _likelihood(e: EvidencePack) -> str:
    if e.score.total <= 40:
        return "Highly Likely"
    if e.score.total <= 60:
        return "Likely"
    if e.score.total <= 80:
        return "Possible"
    return "Unlikely"


def _impact(e: EvidencePack) -> str:
    if e.score.total <= 40:
        return "Severe"
    if e.score.total <= 60:
        return "High"
    if e.score.total <= 80:
        return "Medium"
    return "Low"
