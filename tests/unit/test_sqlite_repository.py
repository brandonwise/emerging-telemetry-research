from pathlib import Path

import pytest

from packages.storage.repository import IdempotencyConflict
from packages.storage.sqlite import SQLiteRepository


@pytest.mark.asyncio
async def test_sqlite_repository_is_durable_and_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "radar.db"
    first = SQLiteRepository(path)
    record = {"report_id": "rp_test", "status": "verified"}
    stored = await first.put_idempotent(
        "reports",
        "idem_abcdefghijklmnopqrstuvwxyz012345",
        record,
        "rp_test",
        record,
    )
    await first.close()
    second = SQLiteRepository(path)

    replay = await second.put_idempotent(
        "reports",
        "idem_abcdefghijklmnopqrstuvwxyz012345",
        record,
        "rp_test",
        record,
    )

    assert stored == record
    assert replay == record
    assert await second.get("reports", "rp_test") == record
    assert await second.available() is True


@pytest.mark.asyncio
async def test_sqlite_repository_rejects_idempotency_conflict(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "radar.db")
    await repository.put_idempotent(
        "runs",
        "idem_abcdefghijklmnopqrstuvwxyz012345",
        {"run_id": "run_one"},
        "run_one",
        {"run_id": "run_one"},
    )

    with pytest.raises(IdempotencyConflict):
        await repository.put_idempotent(
            "runs",
            "idem_abcdefghijklmnopqrstuvwxyz012345",
            {"run_id": "run_two"},
            "run_two",
            {"run_id": "run_two"},
        )
