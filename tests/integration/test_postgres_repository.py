import os
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
import pytest

from packages.storage.repository import IdempotencyConflict, PostgresRepository


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_migrations_and_atomic_idempotency_against_postgres() -> None:
    database_url = os.getenv("RADAR_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("RADAR_TEST_DATABASE_URL is not configured")
    database_name = urlsplit(database_url).path.removeprefix("/")
    if not database_name.endswith("_test"):
        pytest.fail("RADAR_TEST_DATABASE_URL must target a database ending in _test")

    with psycopg.connect(database_url, autocommit=True) as connection:
        for migration in sorted(Path("migrations").glob("*.sql")):
            connection.execute(migration.read_text(encoding="utf-8"))
        tables = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                """
            ).fetchall()
        }
        triggers = {
            str(row[0])
            for row in connection.execute(
                """
                SELECT trigger_name
                FROM information_schema.triggers
                WHERE trigger_schema = 'public'
                """
            ).fetchall()
        }
    assert {"runs", "raw_artifacts", "evidence_items", "api_idempotency", "api_records"} <= tables
    assert {"raw_artifacts_immutable", "evidence_items_immutable", "api_records_append_only"} <= (
        triggers
    )

    repository = PostgresRepository(database_url)
    record = {
        "run_id": "run_postgres_fixture",
        "status": "planned",
    }
    request = {"mode": "shadow"}
    first = await repository.put_idempotent(
        "runs",
        "postgres_idempotency_fixture_0001",
        request,
        "run_postgres_fixture",
        record,
    )
    replay = await repository.put_idempotent(
        "runs",
        "postgres_idempotency_fixture_0001",
        request,
        "run_postgres_fixture",
        {**record, "ignored_on_retry": True},
    )
    assert replay == first
    with pytest.raises(IdempotencyConflict):
        await repository.put_idempotent(
            "runs",
            "postgres_idempotency_fixture_0001",
            {"mode": "changed"},
            "run_postgres_fixture",
            record,
        )
    await repository.close()
