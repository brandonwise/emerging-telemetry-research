from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def render_minimal_report(report: dict[str, Any], output_path: Path) -> Path:
    """Safe fallback renderer; production uses reviewed Jinja templates."""
    title = html.escape(str(report.get("title", "Threat Radar Report")))
    payload = html.escape(json.dumps(report, indent=2, sort_keys=True))
    document = f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\">
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>{title}</title><style>body{{font-family:system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f4f6;padding:1rem;border-radius:.5rem}}</style></head>
<body><h1>{title}</h1><pre>{payload}</pre></body></html>"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    return output_path
