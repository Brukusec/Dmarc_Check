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


def analyze_dmarc(records: list[str]) -> DMARCAnalysis:
    if not records:
        return DMARCAnalysis(exists=False, risks=["No DMARC record found"])

    record = records[0]
    tags = parse_tags(record)
    risks: list[str] = []

    policy = tags.get("p", "none").lower()
    if policy == "reject":
        enforcement = "strong"
    elif policy == "quarantine":
        enforcement = "moderate"
    else:
        enforcement = "none"

    rua = tags.get("rua", "")
    reporting_enabled = bool(rua)
    if policy == "none" and not reporting_enabled:
        risks.append("DMARC p=none and no rua reporting endpoint")

    pct = int(tags.get("pct", "100") or "100")
    if pct < 100:
        risks.append("DMARC pct is below 100")

    if tags.get("adkim", "r") == "r" and tags.get("aspf", "r") == "r":
        risks.append("DMARC alignment relaxed for both DKIM and SPF")

    return DMARCAnalysis(
        exists=True,
        record=record,
        tags=tags,
        enforcement=enforcement,
        reporting_enabled=reporting_enabled,
        risks=risks,
    )
