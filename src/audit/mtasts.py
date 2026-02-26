from __future__ import annotations

from urllib.request import Request, urlopen

from audit.models import MTASTSAnalysis


def parse_mtasts_policy(policy_text: str) -> MTASTSAnalysis:
    mode = None
    max_age = None
    mx_patterns: list[str] = []
    for line in policy_text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        if key == "mode":
            mode = val
        elif key == "max_age":
            try:
                max_age = int(val)
            except ValueError:
                pass
        elif key == "mx":
            mx_patterns.append(val)
    return MTASTSAnalysis(
        mode=mode, max_age=max_age, mx_patterns=mx_patterns, policy_text=policy_text
    )


def analyze_mtasts(dns_records: list[str], domain: str, timeout: float = 5.0) -> MTASTSAnalysis:
    dns_record = dns_records[0] if dns_records else None
    try:
        req = Request(
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt", headers={"User-Agent": "audit/0.1"}
        )
        with urlopen(req, timeout=timeout) as resp:
            policy_text = resp.read().decode("utf-8", errors="replace")
            analysis = parse_mtasts_policy(policy_text)
            analysis.dns_record = dns_record
            return analysis
    except Exception:
        return MTASTSAnalysis(dns_record=dns_record)
