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
    rendered = render_report(report, tmp_path / "escaped.html")
    html = rendered.path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "default-src 'none'" in html
    assert "remote assets" not in html
