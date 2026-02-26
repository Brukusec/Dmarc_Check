from __future__ import annotations

from audit.models import SPFAnalysis

MECHS = ["include", "a", "mx", "ip4", "ip6", "exists", "redirect"]


def analyze_spf(records: list[str]) -> SPFAnalysis:
    if not records:
        return SPFAnalysis(exists=False, risks=["No SPF record found"])

    record = records[0]
    tokens = record.split()
    mechanisms = {k: 0 for k in MECHS}
    lookup_count = 0
    qualifier = None
    risks: list[str] = []

    for t in tokens[1:]:
        key = t.split(":", 1)[0].split("=", 1)[0]
        bare = key.lstrip("+-~?")
        if bare in mechanisms:
            mechanisms[bare] += 1
        if bare in {"include", "a", "mx", "exists", "redirect"}:
            lookup_count += 1
        if bare == "all":
            qualifier = key[0] if key and key[0] in "+-~?" else "+"

    if qualifier == "+":
        risks.append("SPF uses +all (permits any sender)")
    elif qualifier == "?":
        risks.append("SPF uses ?all (neutral, weak enforcement)")
    elif qualifier is None:
        risks.append("SPF missing all qualifier")

    if lookup_count > 10:
        risks.append("SPF exceeds 10 DNS lookup limit")
    elif lookup_count >= 8:
        risks.append("SPF DNS lookups near limit")

    if mechanisms["include"] > 5:
        risks.append("SPF has many includes; review necessity")

    return SPFAnalysis(
        exists=True,
        record=record,
        lookup_count=lookup_count,
        qualifier=qualifier,
        mechanisms={k: v for k, v in mechanisms.items() if v > 0},
        risks=risks,
    )
