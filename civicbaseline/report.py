from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from civicbaseline.models import AssessmentResult, Status


def _templates_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(_templates_dir()),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["now"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return env


def render_markdown(result: AssessmentResult) -> str:
    return _env().get_template("report.md.j2").render(result=result, Status=Status)


def render_html(result: AssessmentResult) -> str:
    return _env().get_template("report.html.j2").render(result=result, Status=Status)


def result_to_dict(result: AssessmentResult) -> dict:
    return json.loads(result.model_dump_json())


def write_reports(result: AssessmentResult, out_dir: str | Path, formats: list[str]) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    wanted = {item.strip() for item in formats}
    if "md" in wanted or "markdown" in wanted:
        path = out / "report.md"
        path.write_text(render_markdown(result), encoding="utf-8")
        written.append(path)
    if "html" in wanted:
        path = out / "report.html"
        path.write_text(render_html(result), encoding="utf-8")
        written.append(path)
    if "json" in wanted:
        path = out / "report.json"
        path.write_text(json.dumps(result_to_dict(result), indent=2), encoding="utf-8")
        written.append(path)
    if "sarif" in wanted:
        from civicbaseline.sarif import render_sarif

        path = out / "report.sarif"
        path.write_text(render_sarif(result), encoding="utf-8")
        written.append(path)
    return written
