from __future__ import annotations

from audit.models import TLSRPTAnalysis


def analyze_tlsrpt(records: list[str]) -> TLSRPTAnalysis:
    if not records:
        return TLSRPTAnalysis()
    record = records[0]
    rua: list[str] = []
    for part in record.split(";"):
        if part.strip().lower().startswith("rua="):
            rua = [x.strip() for x in part.split("=", 1)[1].split(",") if x.strip()]
    return TLSRPTAnalysis(record=record, rua=rua)
