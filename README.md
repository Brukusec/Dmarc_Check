# Email Security Posture Assessment (Windows Desktop)

A production-ready, defensive Python desktop application for assessing domain email security posture across SPF, DKIM, and DMARC.

## Security Scope

This tool is defensive-only and intended for authorized domain assessments.
It does **not** provide offensive exploitation or phishing enablement.

## Features

- Modern desktop GUI built with **PySide6**
- Single-domain and bulk-domain assessment modes
- TXT/CSV import for bulk domains
- Recursive SPF include/redirect resolution with DNS lookup accounting
- Graceful timeout/error handling; one domain failure does not stop batch execution
- Weighted security scoring (0–100) and maturity tier mapping
- Per-domain HTML report generation using:
  - `report_{domain}_{YYYYMMDD}.html`
  - lowercased/sanitized domain filename handling for Windows
- Optional JSON companion outputs
- Live run progress, table results, and execution log panel
- Windows executable packaging via PyInstaller (`--onefile --noconsole`)

## Project Structure

```text
Dmarc_Check/
├─ main.py
├─ requirements.txt
├─ pyproject.toml
├─ README.md
├─ src/
│  └─ audit/
│     ├─ desktop/
│     │  ├─ __init__.py
│     │  ├─ app.py                  # PySide6 desktop GUI
│     │  └─ assessment.py           # Assessment orchestration + per-domain output
│     ├─ dns.py
│     ├─ spf.py
│     ├─ dkim.py
│     ├─ dmarc.py
│     ├─ scoring.py                 # weighted scoring engine + tier/risk mapping
│     ├─ models.py
│     └─ report/
│        ├─ renderer.py
│        └─ templates/
│           └─ report.html.j2       # multi-section governance report template
└─ tests/
```

## GUI Layout

### SECTION A – INPUT
- Toggle: Single Domain / Bulk Domains
- Single mode: one domain text field
- Bulk mode: multiline domain input + TXT/CSV import
- Checkboxes:
  - Resolve SPF includes and redirect
  - Generate JSON output
  - Generate PDF output (optional placeholder log)

### SECTION B – OUTPUT
- Output folder selector + browse button
- Report format selector (HTML/JSON/Both)
- Live filename preview:
  - `report_example.com_20260226.html`

### SECTION C – EXECUTION
- Run Assessment button
- Progress bar
- Live result table with columns:
  - Domain, Score, Tier, SPF, DKIM, DMARC, Status, Open Report

### SECTION D – LOGS
- Scrollable execution log panel
- Logs DNS lookup summaries, output generation, and errors

## Scoring Model

Weighted 0–100 scoring:

- DMARC enforcement: **30%**
- DKIM presence & alignment: **25%**
- SPF strictness: **20%**
- Sender hygiene: **15%**
- Monitoring configuration: **10%**

Tier mapping:

- Tier 1 (0–20) Critical Exposure
- Tier 2 (21–40) Weak
- Tier 3 (41–60) Transitional
- Tier 4 (61–80) Mature
- Tier 5 (81–100) Hardened

## Report Contents (Per Domain)

Each report includes:

1. Cover Page
2. Extended Executive Summary
3. Security Posture Dashboard
4. Technical Analysis (SPF tree, lookup count, third-party includes, DMARC parse, DKIM detection)
5. Impact Analysis (likelihood vs impact matrix)
6. Remediation Roadmap (0–30, 30–60, governance)
7. Appendix (raw DNS records, resolution trace, parsing output)

## Local Development

```bash
pip install -r requirements.txt
pip install -e .
python main.py
```

## Build Windows Executable (Portable)

1. Ensure dependencies are installed:

```bash
pip install -r requirements.txt
```

2. Build onefile executable:

```bash
pyinstaller --onefile --noconsole --icon=app.ico --name EmailSecurityAssessment --paths src main.py
```

> If `app.ico` is not available yet, remove the `--icon=app.ico` flag temporarily.

3. Output artifact:

- `dist/EmailSecurityAssessment.exe`

This executable is standalone and does not require Python on the end-user machine.

## Required PyInstaller Command

```bash
pyinstaller --onefile --noconsole --icon=app.ico main.py
```

(Recommended in this repository to include `--paths src` so imports resolve consistently in build environments.)
