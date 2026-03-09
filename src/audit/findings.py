from __future__ import annotations

from audit.models import (
    DMARCAnalysis,
    DKIMAnalysis,
    Finding,
    MTASTSAnalysis,
    SMTPProbeResult,
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
    smtp_results: list[SMTPProbeResult] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    smtp_results = smtp_results or []

    if not spf.exists:
        findings.append(_f("SPF_MISSING", "High", "SPF missing", "No SPF record was found.", "DNS TXT absent", "Publish SPF with strict -all."))
    if spf.softfail and spf.lookup_count > 10:
        findings.append(
            _f(
                "SPF_SOFTFAIL_LOOKUP",
                "High",
                "SPF softfail with high complexity",
                "SPF uses ~all and exceeds 10 DNS lookups.",
                f"lookup_count={spf.lookup_count}; record={spf.record or 'n/a'}",
                "Flatten SPF includes, reduce third-party include depth, and migrate to -all.",
            )
        )
    for risk in spf.risks:
        sev = "High" if "+all" in risk else "Medium"
        findings.append(_f("SPF_RISK", sev, "SPF risk detected", risk, spf.record or "n/a", "Harden SPF and reduce lookups."))

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
    elif dmarc.policy == "none" and dmarc.pct < 100:
        findings.append(
            _f(
                "DMARC_FALSE_SENSE",
                "High",
                "DMARC false sense of security",
                "DMARC p=none with pct<100 does not enforce protection but can be misread as rollout progress.",
                dmarc.record or "n/a",
                "Move to p=quarantine/reject and pct=100 after validation.",
            )
        )

    if dmarc.exists and not dmarc.rua_present:
        findings.append(
            _f(
                "DMARC_RUA_MISSING",
                "Medium",
                "DMARC rua missing",
                "Aggregate reporting (rua) is absent, reducing visibility.",
                dmarc.record or "n/a",
                "Add rua mailbox for DMARC aggregate reports.",
            )
        )

    if dmarc.exists and (dmarc.tags.get("aspf", "r") == "r" or dmarc.tags.get("adkim", "r") == "r"):
        findings.append(
            _f(
                "DMARC_RELAXED_ALIGNMENT",
                "Medium",
                "Relaxed DMARC alignment",
                "aspf/adkim are relaxed (r); sensitive domains should prefer strict (s).",
                f"adkim={dmarc.tags.get('adkim', 'r')}; aspf={dmarc.tags.get('aspf', 'r')}",
                "Set aspf=s and adkim=s where operationally possible.",
            )
        )

    for risk in dmarc.risks:
        findings.append(_f("DMARC_RISK", "Medium", "DMARC risk detected", risk, dmarc.record or "n/a", "Move toward full enforcement and reporting."))

    if dkim.missing:
        findings.append(
            _f("DKIM_UNKNOWN", "High", "DKIM not discovered", dkim.coverage_note, "common selectors checked", "Confirm active selectors and sign all outbound streams.")
        )
    else:
        present_selectors = len([selector for selector in dkim.selectors if selector.present])
        if present_selectors < 2:
            findings.append(
                _f(
                    "DKIM_PARTIAL",
                    "Medium",
                    "Partial DKIM coverage",
                    "DKIM appears limited; only a subset of tested selectors responded.",
                    f"present_selectors={present_selectors}",
                    "Validate DKIM signing across all sender platforms and subdomains.",
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

    weak_tls = [result.mx_host for result in smtp_results if result.tls_version in {"TLSv1", "TLSv1.1"}]
    if weak_tls:
        findings.append(
            _f(
                "MX_WEAK_TLS",
                "High",
                "Weak MX TLS versions detected",
                "One or more MX hosts negotiate deprecated TLS versions.",
                ", ".join(weak_tls),
                "Upgrade MX TLS policy to TLS 1.2+ and modern ciphers.",
            )
        )

    if not mtasts.dns_record:
        findings.append(_f("MTASTS_MISSING", "Medium", "MTA-STS missing", "No MTA-STS DNS record found.", "_mta-sts TXT absent", "Deploy MTA-STS in enforce mode."))

    if not tlsrpt.record:
        findings.append(_f("TLSRPT_MISSING", "Medium", "TLS-RPT missing", "No TLS reporting record found.", "_smtp._tls TXT absent", "Publish TLS-RPT rua endpoint."))

    return findings


def _f(i: str, s: str, t: str, d: str, e: str, r: str) -> Finding:
    return Finding(id=i, severity=s, title=t, description=d, evidence=e, remediation=r)
