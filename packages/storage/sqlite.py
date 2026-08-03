from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any

from packages.common.canonical import canonical_json_bytes, sha256_hex
from packages.storage.repository import (
    IdempotencyConflict,
    RepositoryUnavailable,
)

COLLECTIONS = {
    "runs",
    "artifacts",
    "observations",
    "assessments",
    "evidence",
    "reports",
    "deliveries",
}


class SQLiteRepository:
    """Portable durable repository with the same immutable contract as PostgreSQL."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    async def available(self) -> bool:
        try:
            with self._connection() as connection:
                connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True

    async def close(self) -> None:
        return None

    async def put_idempotent(
        self,
        collection: str,
        idempotency_key: str,
        request_payload: dict[str, Any],
        record_key: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        _validate_collection(collection)
        request_hash = sha256_hex(canonical_json_bytes(request_payload))
        record_hash = sha256_hex(canonical_json_bytes(record))
        payload_text = canonical_json_bytes(record).decode("utf-8")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_idempotency = connection.execute(
                """
                SELECT request_hash
                FROM research_idempotency
                WHERE scope = ? AND idempotency_key = ?
                """,
                (collection, idempotency_key),
            ).fetchone()
            if existing_idempotency is not None:
                if str(existing_idempotency["request_hash"]) != request_hash:
                    raise IdempotencyConflict(f"idempotency key conflict in {collection}")
                replay = connection.execute(
                    """
                    SELECT payload
                    FROM research_records
                    WHERE collection = ? AND idempotency_key = ?
                    """,
                    (collection, idempotency_key),
                ).fetchone()
                if replay is None:
                    raise RepositoryUnavailable("idempotency record is incomplete")
                connection.commit()
                return _json_object(str(replay["payload"]))

            existing_record = connection.execute(
                """
                SELECT payload_hash, payload
                FROM research_records
                WHERE collection = ? AND record_key = ?
                """,
                (collection, record_key),
            ).fetchone()
            if existing_record is not None:
                if str(existing_record["payload_hash"]) != record_hash:
                    raise IdempotencyConflict(f"immutable record conflict in {collection}")
                connection.execute(
                    """
                    INSERT INTO research_idempotency (
                      scope, idempotency_key, request_hash
                    ) VALUES (?, ?, ?)
                    """,
                    (collection, idempotency_key, request_hash),
                )
                connection.commit()
                return _json_object(str(existing_record["payload"]))

            connection.execute(
                """
                INSERT INTO research_idempotency (
                  scope, idempotency_key, request_hash
                ) VALUES (?, ?, ?)
                """,
                (collection, idempotency_key, request_hash),
            )
            connection.execute(
                """
                INSERT INTO research_records (
                  collection, record_key, payload, payload_hash, idempotency_key
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (collection, record_key, payload_text, record_hash, idempotency_key),
            )
            connection.commit()
        return deepcopy(record)

    async def get(self, collection: str, key: str) -> dict[str, Any] | None:
        _validate_collection(collection)
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM research_records
                WHERE collection = ? AND record_key = ?
                """,
                (collection, key),
            ).fetchone()
        return _json_object(str(row["payload"])) if row is not None else None

    async def evidence_ids(self) -> set[str]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT record_key FROM research_records WHERE collection = 'evidence'"
            ).fetchall()
        return {str(row["record_key"]) for row in rows}

    async def source_health_records(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM research_records
                WHERE collection = 'reports'
                ORDER BY created_at DESC
                LIMIT 100
                """
            ).fetchall()
        return [
            dict(item)
            for row in rows
            for item in _json_object(str(row["payload"])).get("source_health", [])
            if isinstance(item, dict)
        ]

    async def usage_records(self, run_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM research_records
                WHERE collection = 'runs' AND record_key = ?
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            return []
        payload = _json_object(str(row["payload"]))
        usage = payload.get("usage", [])
        return [dict(item) for item in usage if isinstance(item, dict)]

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS research_meta (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO research_meta (key, value)
                  VALUES ('schema_version', '1');
                CREATE TABLE IF NOT EXISTS research_idempotency (
                  scope TEXT NOT NULL,
                  idempotency_key TEXT NOT NULL,
                  request_hash TEXT NOT NULL,
                  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  PRIMARY KEY (scope, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS research_records (
                  collection TEXT NOT NULL,
                  record_key TEXT NOT NULL,
                  payload TEXT NOT NULL,
                  payload_hash TEXT NOT NULL,
                  idempotency_key TEXT NOT NULL,
                  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  PRIMARY KEY (collection, record_key),
                  UNIQUE (collection, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS research_records_created_idx
                  ON research_records (collection, created_at DESC);
                """
            )
            version = connection.execute(
                "SELECT value FROM research_meta WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or str(version["value"]) != "1":
                raise RepositoryUnavailable("unsupported SQLite repository schema")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _validate_collection(value: str) -> None:
    if value not in COLLECTIONS:
        raise ValueError("unknown repository collection")


def _json_object(value: str) -> dict[str, Any]:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise RepositoryUnavailable("repository returned a non-object payload")
    return payload
