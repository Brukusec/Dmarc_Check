from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from audit.models import EvidencePack


def build_full_report(evidences: list[EvidencePack]) -> dict:
    severity_counter = Counter()
    issue_buckets: dict[str, dict] = {}

    for evidence in evidences:
        for finding in evidence.findings:
            severity_counter[finding.severity] += 1
            if finding.id not in issue_buckets:
                issue_buckets[finding.id] = {
                    "id": finding.id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "count": 0,
                    "domains": [],
                }
            issue_buckets[finding.id]["count"] += 1
            issue_buckets[finding.id]["domains"].append(evidence.domain)

    ordered_domains = sorted(evidences, key=lambda e: e.score.total)
    domain_summary = [
        {
            "domain": evidence.domain,
            "score": evidence.score.total,
            "tier": evidence.score.maturity_tier,
            "risk_level": evidence.score.risk_level_badge,
            "issue_count": len(evidence.findings),
            "report_name": evidence.report_name,
            "timestamp": evidence.timestamp.isoformat(),
        }
        for evidence in ordered_domains
    ]

    aggregated_issues = sorted(
        (
            {
                **item,
                "domains": sorted(set(item["domains"])),
            }
            for item in issue_buckets.values()
        ),
        key=lambda item: (item["count"], item["severity"]),
        reverse=True,
    )

    return {
        "domains_total": len(evidences),
        "issues_total": sum(len(e.findings) for e in evidences),
        "severity_totals": dict(severity_counter),
        "domain_summary": domain_summary,
        "aggregated_issues": aggregated_issues,
    }


def write_full_report(evidences: list[EvidencePack], out_file: Path) -> None:
    report = build_full_report(evidences)
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_aggregated_issues_csv(evidences: list[EvidencePack], out_file: Path) -> None:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["domain", "id", "severity", "title", "description", "evidence", "remediation"],
        )
        writer.writeheader()
        for evidence in evidences:
            for finding in evidence.findings:
                writer.writerow({"domain": evidence.domain, **finding.model_dump()})
