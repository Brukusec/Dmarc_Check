from __future__ import annotations

from audit.models import DMARCAnalysis


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        k, v = part.strip().split("=", 1)
        tags[k.strip().lower()] = v.strip()
    return tags


def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def analyze_dmarc(records: list[str]) -> DMARCAnalysis:
    if not records:
        return DMARCAnalysis(exists=False, risks=["No DMARC record found"])

    record = records[0]
    tags = parse_tags(record)
    risks: list[str] = []

    policy = tags.get("p", "none").lower()
    pct = _safe_int(tags.get("pct", "100"), 100)
    subdomain_policy = tags.get("sp")
    rua_present = bool(tags.get("rua", "").strip())
    ruf_present = bool(tags.get("ruf", "").strip())
    reporting_enabled = rua_present or ruf_present

    if policy == "reject" and pct == 100:
        enforcement = "strong"
        enforcement_level = "Full enforcement"
    elif policy in {"quarantine", "reject"}:
        enforcement = "moderate"
        enforcement_level = "Partial enforcement"
    else:
        enforcement = "none"
        enforcement_level = "Monitoring"

    if policy == "none":
        risks.append("DMARC policy is monitoring only (p=none)")
    if not reporting_enabled:
        risks.append("DMARC reporting not configured (rua/ruf missing)")
    if pct < 100:
        risks.append("DMARC pct is below 100")
    if subdomain_policy is None:
        risks.append("DMARC subdomain policy (sp=) missing")

    if tags.get("adkim", "r") == "r" and tags.get("aspf", "r") == "r":
        risks.append("DMARC alignment relaxed for both DKIM and SPF")

    return DMARCAnalysis(
        exists=True,
        record=record,
        tags=tags,
        enforcement=enforcement,
        policy=policy,
        pct=pct,
        subdomain_policy=subdomain_policy,
        rua_present=rua_present,
        ruf_present=ruf_present,
        enforcement_level=enforcement_level,
        reporting_enabled=reporting_enabled,
        risks=risks,
    )
