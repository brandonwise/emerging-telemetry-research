from copy import deepcopy
from pathlib import Path

from apps.report_renderer.render import render_report
from packages.pipeline.frozen import run_frozen_fixture


def test_report_escapes_source_derived_text_and_has_restrictive_csp(tmp_path: Path) -> None:
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path / "baseline",
    )
    report = deepcopy(result.report)
    report["findings"][0]["title"] = "CVE update <script>alert(1)</script>"
    report["findings"][0]["tags"] = ["supply_chain"]
    report["findings"][0]["source_evidence"] = [
        {
            "evidence_id": "ev_hostile_excerpt",
            "source_id": "brave-web",
            "source_type": "website",
            "title": "Source <img src=x onerror=alert(1)>",
            "url": "https://security.example/source",
            "published_at": None,
            "retrieved_at": "2026-07-22T12:00:00Z",
            "excerpt": "Observed <script>callTool()</script> in source text.",
            "source_handle": None,
        }
    ]
    rendered = render_report(report, tmp_path / "escaped.html")
    html = rendered.path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<script>callTool()</script>" not in html
    assert "default-src 'none'" in html
    assert "remote assets" not in html
