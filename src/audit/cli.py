from __future__ import annotations

import csv
import json
import random
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from audit import __version__
from audit.bimi import analyze_bimi
from audit.dkim import analyze_dkim
from audit.dmarc import analyze_dmarc
from audit.dns import COMMON_SELECTORS, DNSClient
from audit.findings import build_findings
from audit.models import EvidencePack, ScoreBreakdown
from audit.mtasts import analyze_mtasts
from audit.report.renderer import build_executive_json, render_html
from audit.scoring import score
from audit.smtp_probe import probe_mx
from audit.spf import analyze_spf
from audit.tlsrpt import analyze_tlsrpt

app = typer.Typer(help="Email Domain Security Auditor (defensive).")


def _report_name(domain: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    rand = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"EMAIL-SEC-{domain}-{stamp}-{rand}"



def _scan(domain: str, resolver: str | None, timeout: float, mx_probe: bool) -> EvidencePack:
    client = DNSClient(nameserver=resolver, timeout=timeout)
    dns = client.discover(domain)
    spf = analyze_spf(dns.spf, domain, client.query_spf_txt)
    dmarc = analyze_dmarc(dns.dmarc)
    dkim = analyze_dkim(dns.dkim, COMMON_SELECTORS)
    mtasts = analyze_mtasts(dns.mtasts, domain, timeout=timeout)
    tlsrpt = analyze_tlsrpt(dns.tlsrpt)
    bimi = analyze_bimi(dns.bimi)

    smtp_results = [probe_mx(mx.host, timeout=timeout) for mx in dns.mx] if mx_probe else []
    if smtp_results:
        ratio = len([r for r in smtp_results if r.starttls]) / len(smtp_results)
    else:
        ratio = 0.0

    findings = build_findings(spf, dmarc, dkim, mtasts, tlsrpt, ratio)
    sc = score(spf, dmarc, dkim, mtasts, tlsrpt, ratio, bool(bimi["present"]))

    return EvidencePack(
        version=__version__,
        report_name=_report_name(domain),
        timestamp=datetime.now(timezone.utc),
        domain=domain,
        resolver=(resolver or "system"),
        runtime={"timeout": timeout, "mx_probe": mx_probe},
        dns=dns,
        spf=spf,
        dmarc=dmarc,
        dkim=dkim,
        smtp=smtp_results,
        mtasts=mtasts,
        tlsrpt=tlsrpt,
        findings=findings,
        score=ScoreBreakdown(**sc),
    )


def _write_outputs(evidence: EvidencePack, out_dir: Path, fmt: str, csv_out: bool = False) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = out_dir / "evidence.json"
    payload = evidence.model_dump_json(indent=2)
    evidence_path.write_text(payload, encoding="utf-8")
    (out_dir / "report.json").write_text(payload, encoding="utf-8")
    executive_payload = build_executive_json(evidence)
    (out_dir / "report_structured.json").write_text(
        json.dumps(executive_payload, indent=2), encoding="utf-8"
    )

    if fmt in {"html", "both"}:
        render_html(evidence, out_dir / "report.html")
    if csv_out:
        with (out_dir / "findings.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["id", "severity", "title", "description", "evidence", "remediation"]
            )
            writer.writeheader()
            for row in evidence.findings:
                writer.writerow(row.model_dump())


@app.command("scan")
def scan(
    domain: str,
    out: Annotated[Path, typer.Option("--out")] = Path("out"),
    format: Annotated[str, typer.Option("--format")] = "both",
    timeout: Annotated[float, typer.Option("--timeout")] = 6.0,
    resolver: Annotated[str | None, typer.Option("--resolver")] = None,
    mx_probe: Annotated[bool, typer.Option("--mx-probe/--no-mx-probe")] = True,
    csv_output: Annotated[bool, typer.Option("--csv")] = False,
) -> None:
    """Scan one domain."""
    evidence = _scan(domain, resolver, timeout, mx_probe)
    _write_outputs(evidence, out, format, csv_output)
    typer.echo(f"Scan complete. Score={evidence.score.total}/100")


@app.command("batch")
def batch(
    input: Annotated[Path, typer.Option("--input")],
    out: Annotated[Path, typer.Option("--out")] = Path("out"),
    format: Annotated[str, typer.Option("--format")] = "both",
    timeout: Annotated[float, typer.Option("--timeout")] = 6.0,
    resolver: Annotated[str | None, typer.Option("--resolver")] = None,
    mx_probe: Annotated[bool, typer.Option("--mx-probe/--no-mx-probe")] = True,
) -> None:
    """Scan multiple domains from a text file."""
    domains = [
        d.strip()
        for d in input.read_text(encoding="utf-8").splitlines()
        if d.strip() and not d.startswith("#")
    ]
    for domain in domains:
        evidence = _scan(domain, resolver, timeout, mx_probe)
        _write_outputs(evidence, out / domain, format)
        typer.echo(f"{domain}: {evidence.score.total}/100")


@app.command("diff")
def diff(
    old: Annotated[Path, typer.Option("--old")],
    new: Annotated[Path, typer.Option("--new")],
) -> None:
    """Show score and finding changes between two evidence packs."""
    old_e = EvidencePack.model_validate_json(old.read_text(encoding="utf-8"))
    new_e = EvidencePack.model_validate_json(new.read_text(encoding="utf-8"))
    delta = new_e.score.total - old_e.score.total
    typer.echo(f"Score delta: {delta:+}")

    old_titles = {f.title for f in old_e.findings}
    new_titles = {f.title for f in new_e.findings}
    added = sorted(new_titles - old_titles)
    removed = sorted(old_titles - new_titles)
    if added:
        typer.echo("Added findings:")
        for t in added:
            typer.echo(f"  + {t}")
    if removed:
        typer.echo("Resolved findings:")
        for t in removed:
            typer.echo(f"  - {t}")


@app.command("report")
def report(
    evidence: Annotated[Path, typer.Option("--evidence")],
    html: Annotated[Path, typer.Option("--html")],
) -> None:
    """Re-render report from evidence file."""
    try:
        e = EvidencePack.model_validate_json(evidence.read_text(encoding="utf-8"))
    except ValidationError as exc:
        raise typer.Exit(f"Invalid evidence file: {exc}")
    render_html(e, html)
    typer.echo(f"Report written: {html}")


if __name__ == "__main__":
    app()
