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

    dmarc_enforcement = _dmarc_enforcement_score(dmarc, penalties)
    dkim_alignment = _dkim_alignment_score(dkim, penalties)
    spf_strength = _spf_strength_score(spf, penalties)
    sender_hygiene = _sender_hygiene_score(spf, penalties)
    monitoring = _monitoring_score(dmarc, tlsrpt, mtasts, smtp_starttls_ratio, bimi_present, penalties)

    total = dmarc_enforcement + dkim_alignment + spf_strength + sender_hygiene + monitoring
    total = max(0, min(100, total))

    auth = max(0, min(50, dmarc_enforcement + dkim_alignment // 2 + spf_strength // 2))
    transport = max(0, min(40, monitoring))
    hardening = max(0, min(10, sender_hygiene // 2 + (2 if bimi_present else 0)))

    tier_level, tier_label = maturity_tier(total)

    return {
        "dmarc_enforcement": dmarc_enforcement,
        "dkim_alignment": dkim_alignment,
        "spf_strength": spf_strength,
        "sender_hygiene": sender_hygiene,
        "monitoring": monitoring,
        "auth": auth,
        "transport": transport,
        "hardening": hardening,
        "total": total,
        "maturity_tier_level": tier_level,
        "maturity_tier": tier_label,
        "risk_level_badge": risk_level(total),
        "penalty_details": penalties,
    }


def _dmarc_enforcement_score(dmarc: DMARCAnalysis, penalties: list[str]) -> int:
    score_value = 0
    if not dmarc.exists:
        penalties.append("DMARC missing: no anti-spoofing policy published.")
        return score_value

    policy_map = {"none": 8, "quarantine": 21, "reject": 30}
    score_value = policy_map.get(dmarc.policy, 8)

    if dmarc.policy == "none":
        penalties.append("DMARC p=none: monitoring only, no enforcement.")
    if dmarc.pct < 100:
        score_value = max(0, score_value - 4)
        penalties.append(f"DMARC pct={dmarc.pct}: partial enforcement coverage.")
    if not dmarc.subdomain_policy:
        score_value = max(0, score_value - 2)
        penalties.append("DMARC sp tag missing: subdomains may remain less protected.")

    return min(30, score_value)


def _dkim_alignment_score(dkim: DKIMAnalysis, penalties: list[str]) -> int:
    if dkim.missing:
        penalties.append("DKIM not detected for common selectors.")
        return 0

    present = len([selector for selector in dkim.selectors if selector.present])
    baseline = min(20, present * 5)
    if "No selectors found" not in dkim.coverage_note:
        baseline = max(baseline, 15)

    if dkim.weak_selectors:
        baseline = max(0, baseline - min(10, len(dkim.weak_selectors) * 5))
        penalties.append("Weak DKIM selectors detected; consider stronger keys and selector rotation.")

    return min(25, baseline + 5)


def _spf_strength_score(spf: SPFAnalysis, penalties: list[str]) -> int:
    if not spf.exists:
        penalties.append("SPF record missing.")
        return 0

    score_value = 20
    if spf.softfail:
        score_value -= 6
        penalties.append("SPF uses ~all softfail instead of strict -all.")
    if not spf.hardfail:
        score_value -= 4
    if spf.permerror:
        score_value -= 8
        penalties.append("SPF has potential permerror risk from lookup complexity.")
    if spf.lookup_count > 10:
        score_value -= 5
        penalties.append("SPF exceeds DNS lookup best-practice threshold.")

    return max(0, min(20, score_value))


def _sender_hygiene_score(spf: SPFAnalysis, penalties: list[str]) -> int:
    score_value = 15

    third_parties = len(spf.third_party_senders)
    if third_parties > 5:
        score_value -= 8
        penalties.append("Excessive third-party sender footprint in SPF include chain.")
    elif third_parties > 2:
        score_value -= 4

    hardcoded_ip_count = spf.ip4_count + spf.ip6_count
    if hardcoded_ip_count > 15:
        score_value -= 5
        penalties.append("High number of hardcoded SPF IP ranges indicates hygiene debt.")
    elif hardcoded_ip_count > 8:
        score_value -= 3

    return max(0, min(15, score_value))


def _monitoring_score(
    dmarc: DMARCAnalysis,
    tlsrpt: TLSRPTAnalysis,
    mtasts: MTASTSAnalysis,
    smtp_starttls_ratio: float,
    bimi_present: bool,
    penalties: list[str],
) -> int:
    score_value = 10

    if not dmarc.reporting_enabled:
        score_value -= 4
        penalties.append("DMARC aggregate/forensic reporting not fully configured.")
    if not tlsrpt.record:
        score_value -= 2
        penalties.append("TLS-RPT missing: limited transport visibility.")
    if not mtasts.dns_record:
        score_value -= 2
        penalties.append("MTA-STS missing: weaker SMTP downgrade resilience.")
    if smtp_starttls_ratio < 1.0:
        score_value -= 1
        penalties.append("STARTTLS not uniformly available across MX hosts.")
    if bimi_present:
        score_value += 1

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
    if score_total <= 20:
        return "Critical"
    if score_total <= 40:
        return "High"
    if score_total <= 60:
        return "Moderate"
    if score_total <= 80:
        return "Low"
    return "Hardened"


def severity_band(score_total: int) -> str:
    if score_total < 40:
        return "Critical"
    if score_total < 60:
        return "High"
    if score_total < 75:
        return "Medium"
    if score_total < 90:
        return "Low"
    return "Info"
