from pathlib import Path

from packages.evaluation.harness import run_acceptance_suite


def test_final_acceptance_demonstrations_pass(tmp_path: Path) -> None:
    result = run_acceptance_suite(
        Path("tests/fixtures/vertical_slice"),
        tmp_path,
    )
    assert result["passed"] is True
