from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from audit.models import EvidencePack


def render_html(evidence: EvidencePack, out_path: Path) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape())
    tpl = env.get_template("report.html.j2")
    out = tpl.render(e=evidence, top5=evidence.findings[:5])
    out_path.write_text(out, encoding="utf-8")
