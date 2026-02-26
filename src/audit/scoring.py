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
    total = 100
    penalties: list[str] = []

    if not dmarc.exists:
        total -= 30
        penalties.append("-30 Missing DMARC")
    elif dmarc.policy == "none":
        total -= 20
        penalties.append("-20 DMARC p=none")

    if spf.softfail:
        total -= 10
        penalties.append("-10 SPF softfail (~all)")
    if spf.permerror:
        total -= 15
        penalties.append("-15 SPF permerror risk")
    if not spf.exists:
        total -= 20
        penalties.append("-20 Missing SPF")

    if dkim.missing:
        total -= 20
        penalties.append("-20 No DKIM discovered")
    elif dkim.weak_selectors:
        total -= 10
        penalties.append("-10 Weak DKIM selectors detected")

    if spf.ip4_count + spf.ip6_count > 15:
        total -= 5
        penalties.append("-5 Excessive SPF IP ranges")

    if not dmarc.reporting_enabled:
        total -= 10
        penalties.append("-10 No DMARC reporting configured")

    if smtp_starttls_ratio < 1.0:
        delta = int((1.0 - smtp_starttls_ratio) * 10)
        total -= delta
        penalties.append(f"-{delta} Incomplete STARTTLS deployment")

    if not mtasts.dns_record:
        total -= 5
        penalties.append("-5 Missing MTA-STS")
    if not tlsrpt.record:
        total -= 3
        penalties.append("-3 Missing TLS-RPT")
    if bimi_present:
        total += 2
        penalties.append("+2 BIMI present")

    total = max(0, min(100, total))
    auth = max(0, min(50, int(total * 0.5)))
    transport = max(0, min(40, int(total * 0.4)))
    hardening = max(0, min(10, total - auth - transport))

    return {
        "auth": auth,
        "transport": transport,
        "hardening": hardening,
        "total": total,
        "maturity_tier": maturity_tier(total),
        "penalty_details": penalties,
    }


def maturity_tier(score_total: int) -> str:
    if score_total < 20:
        return "Tier 1 (Critical)"
    if score_total < 40:
        return "Tier 2 (Weak)"
    if score_total < 60:
        return "Tier 3 (Moderate)"
    if score_total < 80:
        return "Tier 4 (Strong)"
    return "Tier 5 (Hardened)"


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
