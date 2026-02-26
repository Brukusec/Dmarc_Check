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
) -> dict[str, int]:
    auth = 50
    if not spf.exists:
        auth -= 20
    auth -= min(len(spf.risks) * 4, 12)
    if not dmarc.exists:
        auth -= 20
    elif dmarc.enforcement == "none":
        auth -= 10
    auth -= min(len(dmarc.risks) * 3, 9)
    if len([s for s in dkim.selectors if s.present]) == 0:
        auth -= 8
    auth = max(auth, 0)

    transport = 40
    if smtp_starttls_ratio < 1.0:
        transport -= int((1.0 - smtp_starttls_ratio) * 20)
    if not mtasts.dns_record:
        transport -= 8
    if mtasts.mode == "enforce":
        transport += 2
    if not tlsrpt.record:
        transport -= 5
    transport = max(min(transport, 40), 0)

    hardening = 10 if bimi_present else 6
    total = auth + transport + hardening
    return {"auth": auth, "transport": transport, "hardening": hardening, "total": total}


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
