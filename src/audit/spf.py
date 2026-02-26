from __future__ import annotations

from collections.abc import Callable

from audit.models import SPFAnalysis

MECHS = ["include", "a", "mx", "ip4", "ip6", "exists", "redirect"]


def _parse_spf_record(record: str) -> list[str]:
    return [t.strip() for t in record.split() if t.strip()]


def _extract_domain(token: str, marker: str) -> str | None:
    if token.startswith(f"{marker}:"):
        return token.split(":", 1)[1].strip().lower().rstrip(".")
    if token.startswith(f"{marker}="):
        return token.split("=", 1)[1].strip().lower().rstrip(".")
    return None


def _is_third_party(candidate: str, base_domain: str) -> bool:
    return not (candidate == base_domain or candidate.endswith(f".{base_domain}"))


def analyze_spf(
    records: list[str],
    domain: str,
    lookup_spf_txt: Callable[[str], list[str]] | None = None,
) -> SPFAnalysis:
    if not records:
        return SPFAnalysis(exists=False, risks=["No SPF record found"])

    domain = domain.lower().rstrip(".")
    root_record = records[0]
    mechanisms = {k: 0 for k in MECHS}
    risks: list[str] = []
    resolved_records: dict[str, str] = {}
    include_chain: list[str] = []
    include_domains: set[str] = set()
    third_party: set[str] = set()
    visited: set[str] = set()
    lookup_count = 0
    qualifier: str | None = None
    redirect_domain: str | None = None
    ip4_count = 0
    ip6_count = 0

    def walk(current_domain: str, record: str) -> None:
        nonlocal lookup_count, qualifier, redirect_domain, ip4_count, ip6_count
        key_domain = current_domain.lower().rstrip(".")
        if key_domain in visited:
            risks.append(f"SPF include recursion detected at {key_domain}")
            return
        visited.add(key_domain)
        resolved_records[key_domain] = record

        tokens = _parse_spf_record(record)
        if not tokens or tokens[0].lower() != "v=spf1":
            risks.append(f"Invalid SPF syntax for {key_domain}")
            return

        for token in tokens[1:]:
            normalized = token.lstrip("+-~?")
            base = normalized.split(":", 1)[0].split("=", 1)[0]
            if base in mechanisms:
                mechanisms[base] += 1

            if base in {"include", "a", "mx", "exists", "redirect"}:
                lookup_count += 1
            if base == "ip4":
                ip4_count += 1
            if base == "ip6":
                ip6_count += 1

            if base == "all" and current_domain == domain:
                qualifier = token[0] if token and token[0] in "+-~?" else "+"

            include_domain = _extract_domain(normalized, "include")
            if include_domain:
                include_chain.append(f"{key_domain} -> {include_domain}")
                include_domains.add(include_domain)
                if _is_third_party(include_domain, domain):
                    third_party.add(include_domain)
                if lookup_spf_txt:
                    next_records = lookup_spf_txt(include_domain)
                    if next_records:
                        walk(include_domain, next_records[0])
                    else:
                        risks.append(f"SPF include target unresolved: {include_domain}")
                continue

            redirect_target = _extract_domain(normalized, "redirect")
            if redirect_target:
                redirect_domain = redirect_target
                if _is_third_party(redirect_target, domain):
                    third_party.add(redirect_target)
                if lookup_spf_txt:
                    next_records = lookup_spf_txt(redirect_target)
                    if next_records:
                        walk(redirect_target, next_records[0])
                    else:
                        risks.append(f"SPF redirect target unresolved: {redirect_target}")

    walk(domain, root_record)

    permerror = False
    if qualifier is None:
        permerror = True
        risks.append("SPF missing all qualifier (permerror-prone)")
    elif qualifier == "+":
        risks.append("SPF uses +all (permits any sender)")
    elif qualifier == "?":
        risks.append("SPF uses ?all (neutral, weak enforcement)")

    softfail = qualifier == "~"
    hardfail = qualifier == "-"
    if softfail:
        risks.append("SPF softfail (~all) allows non-authorized sources to pass softly")
    if hardfail:
        risks.append("SPF hardfail (-all) configured")

    if lookup_count > 10:
        permerror = True
        risks.append("SPF exceeds 10 DNS lookup limit")
    elif lookup_count >= 8:
        risks.append("SPF DNS lookups near limit")

    total_ip_ranges = ip4_count + ip6_count
    if total_ip_ranges > 15:
        risks.append("SPF has excessive hardcoded IP ranges (>15)")

    alignment_note = (
        f"Conceptual SPF alignment: MAIL FROM should align with header-from domain {domain}."
    )

    return SPFAnalysis(
        exists=True,
        record=root_record,
        lookup_count=lookup_count,
        qualifier=qualifier,
        mechanisms={k: v for k, v in mechanisms.items() if v > 0},
        resolved_records=resolved_records,
        include_chain=include_chain,
        include_domains=sorted(include_domains),
        redirect_domain=redirect_domain,
        softfail=softfail,
        hardfail=hardfail,
        permerror=permerror,
        ip4_count=ip4_count,
        ip6_count=ip6_count,
        third_party_senders=sorted(third_party),
        alignment_note=alignment_note,
        risks=risks,
    )
