from __future__ import annotations


def analyze_bimi(records: list[str]) -> dict[str, str | bool | None]:
    if not records:
        return {"present": False, "record": None}
    return {"present": True, "record": records[0]}
