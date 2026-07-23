from pathlib import Path

from scripts.verify_restore import verify_frozen_restore


def test_immutable_evidence_backup_restore_replays_byte_for_byte(tmp_path: Path) -> None:
    result = verify_frozen_restore(
        Path("tests/fixtures/vertical_slice/flash-manifest.json"),
        tmp_path,
    )
    assert result["passed"] is True
