from __future__ import annotations

from audit.models import (
    DMARCAnalysis,
    DKIMAnalysis,
    Finding,
    MTASTSAnalysis,
    SPFAnalysis,
    TLSRPTAnalysis,
)


def build_findings(
    spf: SPFAnalysis,
    dmarc: DMARCAnalysis,
    dkim: DKIMAnalysis,
    mtasts: MTASTSAnalysis,
    tlsrpt: TLSRPTAnalysis,
    smtp_starttls_ratio: float,
) -> list[Finding]:
    findings: list[Finding] = []

    if not spf.exists:
        findings.append(
            _f(
                "SPF_MISSING",
                "High",
                "SPF missing",
                "No SPF record was found.",
                "DNS TXT absent",
                "Publish SPF with strict -all.",
            )
        )
    for risk in spf.risks:
        sev = "High" if "+all" in risk else "Medium"
        findings.append(
            _f(
                "SPF_RISK",
                sev,
                "SPF risk detected",
                risk,
                spf.record or "n/a",
                "Harden SPF and reduce lookups.",
            )
        )

    if not dmarc.exists:
        findings.append(
            _f(
                "DMARC_MISSING",
                "Critical",
                "DMARC missing",
                "No DMARC record found.",
                "_dmarc TXT absent",
                "Publish DMARC with p=quarantine/reject and rua.",
            )
        )
    for risk in dmarc.risks:
        findings.append(
            _f(
                "DMARC_RISK",
                "Medium",
                "DMARC risk detected",
                risk,
                dmarc.record or "n/a",
                "Move toward full enforcement and reporting.",
            )
        )

    if dkim.missing:
        findings.append(
            _f(
                "DKIM_UNKNOWN",
                "Medium",
                "DKIM not discovered",
                dkim.coverage_note,
                "common selectors checked",
                "Confirm active selectors and rotate keys.",
            )
        )


    for selector in dkim.weak_selectors:
        findings.append(
            _f(
                "DKIM_WEAK_SELECTOR",
                "Medium",
                "Weak DKIM selector detected",
                f"Selector {selector} appears to use a weak RSA key length.",
                selector,
                "Rotate to 2048-bit (or stronger) DKIM keys.",
            )
        )

    if smtp_starttls_ratio < 1.0:
        findings.append(
            _f(
                "STARTTLS_PARTIAL",
                "High",
                "Incomplete STARTTLS",
                "Not all MX hosts advertise STARTTLS.",
                f"ratio={smtp_starttls_ratio:.2f}",
                "Enable STARTTLS on all MX hosts.",
            )
        )

    if not mtasts.dns_record:
        findings.append(
            _f(
                "MTASTS_MISSING",
                "Medium",
                "MTA-STS missing",
                "No MTA-STS DNS record found.",
                "_mta-sts TXT absent",
                "Deploy MTA-STS in enforce mode.",
            )
        )

    if not tlsrpt.record:
        findings.append(
            _f(
                "TLSRPT_MISSING",
                "Low",
                "TLS-RPT missing",
                "No TLS reporting record found.",
                "_smtp._tls TXT absent",
                "Publish TLS-RPT rua endpoint.",
            )
        )

    return findings


def _f(i: str, s: str, t: str, d: str, e: str, r: str) -> Finding:
    return Finding(id=i, severity=s, title=t, description=d, evidence=e, remediation=r)
