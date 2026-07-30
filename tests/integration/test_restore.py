from pathlib import Path

from scripts.verify_restore import verify_frozen_restore


def test_immutable_evidence_backup_restore_replays_byte_for_byte(tmp_path: Path) -> None:
    result = verify_frozen_restore(
        Path("tests/fixtures/vertical_slice/flash-manifest.json"),
        tmp_path,
    )
    assert result["passed"] is True


def test_restore_verification_is_repeatable_in_the_same_output_root(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/vertical_slice/flash-manifest.json")

    first = verify_frozen_restore(fixture, tmp_path)
    second = verify_frozen_restore(fixture, tmp_path)

    assert first["passed"] is True
    assert second == first
