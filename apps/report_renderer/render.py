from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from packages.common.canonical import canonical_json_bytes, sha256_hex
from packages.contracts.validation import validate_payload
from packages.verification.claims import require_verified_report

TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"
TEMPLATE_REVISION = "report-v2"


@dataclass(frozen=True, slots=True)
class RenderedReport:
    path: Path
    report_json_hash: str
    rendered_html_hash: str
    template_revision: str


def render_report(report: dict[str, Any], output_path: Path) -> RenderedReport:
    validate_payload("report.schema.json", report)
    require_verified_report(report)
    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_ROOT),
        autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        newline_sequence="\n",
    )
    template = environment.get_template("report_v1.html.j2")
    document = template.render(report=report, template_revision=TEMPLATE_REVISION)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    return RenderedReport(
        path=output_path,
        report_json_hash=sha256_hex(canonical_json_bytes(report)),
        rendered_html_hash=sha256_hex(document),
        template_revision=TEMPLATE_REVISION,
    )


def render_minimal_report(report: dict[str, Any], output_path: Path) -> Path:
    return render_report(report, output_path).path
