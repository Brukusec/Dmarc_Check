from __future__ import annotations

from audit.models import DMARCAnalysis, DKIMAnalysis, MTASTSAnalysis, SPFAnalysis, TLSRPTAnalysis


def score(
    spf: SPFAnalysis,
    dmarc: DMARCAnalysis,
    dkim: DKIMAnalysis,
    mtasts: MTASTSAnalysis,
    tlsrpt: TLSRPTAnalysis,
    smtp_starttls_ratio: float,
    bimi_present: bool,
) -> dict[str, int | str | list[str]]:
    penalties: list[str] = []

    auth = _auth_score(spf, dmarc, dkim, penalties)
    transport = _transport_score(dmarc, tlsrpt, mtasts, smtp_starttls_ratio, penalties)
    hardening = _hardening_score(spf, bimi_present, penalties)

    total = max(0, min(100, auth + transport + hardening))
    tier_level, tier_label = maturity_tier(total)

    return {
        "dmarc_enforcement": _dmarc_component(dmarc),
        "dkim_alignment": _dkim_component(dkim),
        "spf_strength": _spf_component(spf),
        "sender_hygiene": _sender_hygiene_component(spf),
        "monitoring": _transport_monitoring_component(dmarc, tlsrpt, mtasts, smtp_starttls_ratio),
        "auth": auth,
        "transport": transport,
        "hardening": hardening,
        "total": total,
        "maturity_tier_level": tier_level,
        "maturity_tier": tier_label,
        "risk_level_badge": severity_band(total),
        "penalty_details": penalties,
    }


def _dmarc_component(dmarc: DMARCAnalysis) -> int:
    if not dmarc.exists:
        return 0
    score_value = {"none": 4, "quarantine": 12, "reject": 20}.get(dmarc.policy, 4)
    if dmarc.pct < 100:
        score_value -= 3
    if not dmarc.rua_present:
        score_value -= 2
    if dmarc.tags.get("adkim", "r") == "r":
        score_value -= 1
    if dmarc.tags.get("aspf", "r") == "r":
        score_value -= 1
    return max(0, min(20, score_value))


def _dkim_component(dkim: DKIMAnalysis) -> int:
    if dkim.missing:
        return 0
    present = len([selector for selector in dkim.selectors if selector.present])
    score_value = min(20, present * 5)
    if dkim.weak_selectors:
        score_value -= min(8, len(dkim.weak_selectors) * 4)
    return max(0, min(20, score_value))


def _spf_component(spf: SPFAnalysis) -> int:
    if not spf.exists:
        return 0
    score_value = 10
    if spf.hardfail:
        score_value += 6
    if spf.softfail:
        score_value -= 4
    if spf.lookup_count > 10:
        score_value -= 4
    return max(0, min(10, score_value))


def _auth_score(spf: SPFAnalysis, dmarc: DMARCAnalysis, dkim: DKIMAnalysis, penalties: list[str]) -> int:
    dmarc_score = _dmarc_component(dmarc)
    dkim_score = _dkim_component(dkim)
    spf_score = _spf_component(spf)

    if not dmarc.exists:
        penalties.append("DMARC missing.")
    if dmarc.policy == "none" and dmarc.pct < 100:
        penalties.append("DMARC p=none with pct<100 creates a false sense of enforcement.")
    if not dmarc.rua_present:
        penalties.append("DMARC rua missing (limited visibility).")
    if dmarc.tags.get("adkim", "r") == "r" or dmarc.tags.get("aspf", "r") == "r":
        penalties.append("DMARC relaxed alignment (adkim/aspf=r) is risky for sensitive domains.")
    if not spf.exists:
        penalties.append("SPF missing.")
    if spf.softfail and spf.lookup_count > 10:
        penalties.append("SPF uses ~all with high lookup pressure (>10 DNS lookups).")
    if dkim.missing:
        penalties.append("DKIM not detected.")

    return max(0, min(50, dmarc_score + dkim_score + spf_score))


def _transport_monitoring_component(
    dmarc: DMARCAnalysis,
    tlsrpt: TLSRPTAnalysis,
    mtasts: MTASTSAnalysis,
    smtp_starttls_ratio: float,
) -> int:
    score_value = 10
    if not dmarc.reporting_enabled:
        score_value -= 2
    if not tlsrpt.record:
        score_value -= 2
    if not mtasts.dns_record:
        score_value -= 3
    if smtp_starttls_ratio < 1.0:
        score_value -= 3
    return max(0, min(10, score_value))


def _transport_score(
    dmarc: DMARCAnalysis,
    tlsrpt: TLSRPTAnalysis,
    mtasts: MTASTSAnalysis,
    smtp_starttls_ratio: float,
    penalties: list[str],
) -> int:
    base = 40
    monitor = _transport_monitoring_component(dmarc, tlsrpt, mtasts, smtp_starttls_ratio)
    transport = max(0, min(40, base - ((10 - monitor) * 4)))

    if not mtasts.dns_record:
        penalties.append("MTA-STS missing for mail-enabled domain.")
    if not tlsrpt.record:
        penalties.append("TLS-RPT missing (no TLS failure telemetry).")
    if smtp_starttls_ratio < 1.0:
        penalties.append("One or more MX endpoints do not support STARTTLS or have probe failures.")

    return transport


def _sender_hygiene_component(spf: SPFAnalysis) -> int:
    score_value = 10
    if len(spf.third_party_senders) > 5:
        score_value -= 4
    if spf.ip4_count + spf.ip6_count > 12:
        score_value -= 2
    return max(0, min(10, score_value))


def _hardening_score(spf: SPFAnalysis, bimi_present: bool, penalties: list[str]) -> int:
    score_value = _sender_hygiene_component(spf)
    if bimi_present:
        score_value = min(10, score_value + 2)
    else:
        penalties.append("BIMI not present (optional brand-hardening control).")
    return max(0, min(10, score_value))


def maturity_tier(score_total: int) -> tuple[int, str]:
    if score_total <= 20:
        return 1, "Tier 1 (Critical Exposure)"
    if score_total <= 40:
        return 2, "Tier 2 (Weak)"
    if score_total <= 60:
        return 3, "Tier 3 (Transitional)"
    if score_total <= 80:
        return 4, "Tier 4 (Mature)"
    return 5, "Tier 5 (Hardened)"


def risk_level(score_total: int) -> str:
    return severity_band(score_total)


def severity_band(score_total: int) -> str:
    if score_total < 25:
        return "Critical"
    if score_total < 50:
        return "High"
    if score_total < 70:
        return "Medium"
    if score_total < 90:
        return "Low"
    return "Info"
