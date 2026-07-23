from copy import deepcopy
from pathlib import Path

import pytest

from apps.report_renderer.render import render_report
from packages.pipeline.frozen import run_frozen_fixture
from packages.verification.claims import require_verified_report, verify_report_claims


def test_unsupported_claim_is_rejected_and_cannot_render(tmp_path: Path) -> None:
    baseline = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path / "baseline",
    )
    report = deepcopy(baseline.report)
    report["findings"][0]["claims"][0]["text"] = "Unsupported claim."
    report["findings"][0]["known"][0] = "Unsupported claim."
    result = verify_report_claims(
        report,
        baseline.evidence_packet,
        verifier_revision="test",
    )
    assert result.passed is False
    with pytest.raises(ValueError, match="unverified"):
        require_verified_report(result.report)
    with pytest.raises(ValueError, match="unverified"):
        render_report(result.report, tmp_path / "blocked.html")
