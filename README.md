# Email Domain Security Auditor

A production-focused defensive tool to assess email-domain authentication and transport posture.

## Safety & Authorized Use

**Authorized Use Only**: This project is intended only for defensive assessments of domains and infrastructure you own or are explicitly authorized to test.

The tool does **not** include capabilities for spoofing, phishing delivery, bypassing SPF/DKIM/DMARC, malicious header crafting, or persuasive phishing content generation.

Safe mode defaults are always enabled.

## Features

- Discovery: MX, A/AAAA, PTR, SPF, DMARC, DKIM (small static selector list), BIMI
- Transport checks: SMTP EHLO + STARTTLS support, TLS certificate metadata
- Policy checks: MTA-STS and TLS-RPT parsing
- Scoring: transparent 0-100 model with weighted categories
- Reporting: JSON evidence pack + HTML report + optional CSV findings
- CLI commands: `scan`, `batch`, `diff`, `report`

## Install

```bash
pip install -e .
```

## Usage

```bash
audit scan example.com --format both
audit batch --input domains.txt --format both
audit diff --old old/evidence.json --new new/evidence.json
audit report --evidence out/evidence.json --html out/report.html
```

## Sample JSON Evidence Shape

```json
{
  "tool": "Email Domain Security Auditor",
  "version": "0.1.0",
  "safe_mode": true,
  "domain": "example.com",
  "dns": {"mx": [], "spf": [], "dmarc": []},
  "score": {"auth": 32, "transport": 24, "hardening": 6, "total": 62},
  "findings": [
    {"id": "DMARC_MISSING", "severity": "Critical", "title": "DMARC missing"}
  ]
}
```

## Known Limitations

- SMTP probing depends on network reachability and target MX responsiveness.
- DKIM discovery is intentionally limited to safe static selectors, so coverage is best-effort.
- DANE TLSA checks report presence only; no full DNSSEC chain validation is performed.
- Batch mode is sequential in this version (no async concurrency yet).
