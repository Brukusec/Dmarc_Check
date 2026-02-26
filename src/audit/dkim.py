from __future__ import annotations

from audit.models import DKIMAnalysis, DKIMSelectorResult


def _key_length_hint(record: str) -> str | None:
    lowered = record.lower()
    if "k=rsa" in lowered:
        if "p=" in lowered and len(lowered.split("p=", 1)[1].split(";", 1)[0]) > 300:
            return "likely_2048_or_higher"
        return "likely_1024_or_lower"
    return None


def analyze_dkim(found: dict[str, list[str]], attempted_selectors: list[str]) -> DKIMAnalysis:
    selectors: list[DKIMSelectorResult] = []
    for sel in attempted_selectors:
        records = found.get(sel, [])
        if records:
            selectors.append(
                DKIMSelectorResult(
                    selector=sel,
                    present=True,
                    record=records[0],
                    key_length_hint=_key_length_hint(records[0]),
                )
            )
        else:
            selectors.append(DKIMSelectorResult(selector=sel, present=False))

    present_count = len([s for s in selectors if s.present])
    if present_count == 0:
        note = "unknown/partial coverage: no common selectors discovered"
    else:
        note = f"partial coverage: {present_count}/{len(selectors)} common selectors found"

    return DKIMAnalysis(selectors=selectors, coverage_note=note)
