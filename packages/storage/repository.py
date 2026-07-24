from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Protocol

from psycopg import AsyncConnection
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from packages.common.canonical import canonical_json_bytes, sha256_hex


class IdempotencyConflict(RuntimeError):
    pass


class RepositoryUnavailable(RuntimeError):
    pass


class RadarRepository(Protocol):
    async def available(self) -> bool: ...

    async def close(self) -> None: ...

    async def put_idempotent(
        self,
        collection: str,
        idempotency_key: str,
        request_payload: dict[str, Any],
        record_key: str,
        record: dict[str, Any],
    ) -> dict[str, Any]: ...

    async def get(self, collection: str, key: str) -> dict[str, Any] | None: ...

    async def evidence_ids(self) -> set[str]: ...

    async def source_health_records(self) -> list[dict[str, Any]]: ...

    async def usage_records(self, run_id: str) -> list[dict[str, Any]]: ...


@dataclass(slots=True)
class MemoryRepository:
    """Explicit test adapter; production application construction never selects it implicitly."""

    runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    observations: dict[str, dict[str, Any]] = field(default_factory=dict)
    assessments: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    reports: dict[str, dict[str, Any]] = field(default_factory=dict)
    deliveries: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_health: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    _idempotency: dict[tuple[str, str], str] = field(default_factory=dict)

    async def available(self) -> bool:
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
        payload_hash = sha256_hex(canonical_json_bytes(request_payload))
        identity = (collection, idempotency_key)
        existing_hash = self._idempotency.get(identity)
        if existing_hash is not None and existing_hash != payload_hash:
            raise IdempotencyConflict(f"idempotency key conflict in {collection}")
        target = self._collection(collection)
        existing_record = target.get(record_key)
        if existing_hash is not None:
            if existing_record is None:
                raise RepositoryUnavailable("idempotency record is incomplete")
            return deepcopy(existing_record)
        if existing_record is not None and existing_record != record:
            raise IdempotencyConflict(f"immutable record conflict in {collection}")
        self._idempotency[identity] = payload_hash
        target.setdefault(record_key, deepcopy(record))
        return deepcopy(target[record_key])

    async def get(self, collection: str, key: str) -> dict[str, Any] | None:
        value = self._collection(collection).get(key)
        return deepcopy(value) if value is not None else None

    async def evidence_ids(self) -> set[str]:
        return set(self.evidence)

    async def source_health_records(self) -> list[dict[str, Any]]:
        return deepcopy(self.source_health)

    async def usage_records(self, run_id: str) -> list[dict[str, Any]]:
        return deepcopy(self.usage.get(run_id, []))

    def _collection(self, name: str) -> dict[str, dict[str, Any]]:
        allowed = {
            "runs": self.runs,
            "artifacts": self.artifacts,
            "observations": self.observations,
            "assessments": self.assessments,
            "evidence": self.evidence,
            "reports": self.reports,
            "deliveries": self.deliveries,
        }
        try:
            return allowed[name]
        except KeyError as exc:
            raise ValueError(f"unknown repository collection: {name}") from exc


class PostgresRepository:
    """Durable, atomic API boundary backed by PostgreSQL."""

    def __init__(self, connection_string: str) -> None:
        if not connection_string:
            raise ValueError("PostgreSQL connection string is required")
        self._pool: AsyncConnectionPool[AsyncConnection[dict[str, Any]]] = AsyncConnectionPool(
            connection_string,
            min_size=1,
            max_size=10,
            open=False,
            kwargs={"row_factory": dict_row},
        )

    async def open(self) -> None:
        await self._pool.open(wait=True, timeout=10)

    async def close(self) -> None:
        await self._pool.close()

    async def available(self) -> bool:
        try:
            if self._pool.closed:
                await self.open()
            async with self._pool.connection() as connection:
                await connection.execute("SELECT 1")
        except Exception:
            return False
        return True

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
        if self._pool.closed:
            await self.open()
        async with self._pool.connection() as connection, connection.transaction():
            inserted = await connection.execute(
                """
                INSERT INTO api_idempotency (scope, idempotency_key, request_hash)
                VALUES (%s, %s, %s)
                ON CONFLICT (scope, idempotency_key) DO NOTHING
                RETURNING request_hash
                """,
                (collection, idempotency_key, request_hash),
            )
            inserted_row = await inserted.fetchone()
            if inserted_row is None:
                existing = await connection.execute(
                    """
                    SELECT request_hash
                    FROM api_idempotency
                    WHERE scope = %s AND idempotency_key = %s
                    FOR UPDATE
                    """,
                    (collection, idempotency_key),
                )
                existing_row = await existing.fetchone()
                if existing_row is None or existing_row["request_hash"] != request_hash:
                    raise IdempotencyConflict(f"idempotency key conflict in {collection}")
                replay = await connection.execute(
                    """
                    SELECT payload
                    FROM api_records
                    WHERE collection = %s
                      AND idempotency_key = %s
                    """,
                    (collection, idempotency_key),
                )
                replay_row = await replay.fetchone()
                if replay_row is None:
                    raise RepositoryUnavailable("idempotency record is incomplete")
                return _json_object(replay_row["payload"])

            await connection.execute(
                """
                INSERT INTO api_records (
                  collection, record_key, payload, payload_hash, idempotency_key
                )
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (collection, record_key) DO NOTHING
                """,
                (
                    collection,
                    record_key,
                    Jsonb(record),
                    record_hash,
                    idempotency_key,
                ),
            )
            selected = await connection.execute(
                """
                SELECT payload, payload_hash
                FROM api_records
                WHERE collection = %s AND record_key = %s
                """,
                (collection, record_key),
            )
            selected_row = await selected.fetchone()
            if selected_row is None or selected_row["payload_hash"] != record_hash:
                raise IdempotencyConflict(f"immutable record conflict in {collection}")
            return _json_object(selected_row["payload"])

    async def get(self, collection: str, key: str) -> dict[str, Any] | None:
        _validate_collection(collection)
        if self._pool.closed:
            await self.open()
        async with self._pool.connection() as connection:
            result = await connection.execute(
                """
                SELECT payload
                FROM api_records
                WHERE collection = %s AND record_key = %s
                """,
                (collection, key),
            )
            row = await result.fetchone()
        return _json_object(row["payload"]) if row is not None else None

    async def evidence_ids(self) -> set[str]:
        if self._pool.closed:
            await self.open()
        async with self._pool.connection() as connection:
            result = await connection.execute(
                "SELECT record_key FROM api_records WHERE collection = 'evidence'"
            )
            rows = await result.fetchall()
        return {str(row["record_key"]) for row in rows}

    async def source_health_records(self) -> list[dict[str, Any]]:
        if self._pool.closed:
            await self.open()
        async with self._pool.connection() as connection:
            result = await connection.execute(
                """
                SELECT source_id, status::text AS status, last_success_at,
                       freshness_seconds, error_rate
                FROM source_health
                ORDER BY checked_at DESC, source_id
                LIMIT 1000
                """
            )
            rows = await result.fetchall()
        return [dict(row) for row in rows]

    async def usage_records(self, run_id: str) -> list[dict[str, Any]]:
        if self._pool.closed:
            await self.open()
        async with self._pool.connection() as connection:
            result = await connection.execute(
                """
                SELECT source_id, agent_id, provider, model, input_tokens,
                       output_tokens, cached_tokens, tool_calls, latency_ms,
                       estimated_currency
                FROM model_usage
                WHERE run_id = %s
                ORDER BY usage_id
                """,
                (run_id,),
            )
            rows = await result.fetchall()
        return [_normalize_numbers(dict(row)) for row in rows]


class UnavailableRepository:
    """Fail-closed repository used when no production database is configured."""

    async def available(self) -> bool:
        return False

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
        del collection, idempotency_key, request_payload, record_key, record
        raise RepositoryUnavailable("repository is not configured")

    async def get(self, collection: str, key: str) -> dict[str, Any] | None:
        del collection, key
        raise RepositoryUnavailable("repository is not configured")

    async def evidence_ids(self) -> set[str]:
        raise RepositoryUnavailable("repository is not configured")

    async def source_health_records(self) -> list[dict[str, Any]]:
        raise RepositoryUnavailable("repository is not configured")

    async def usage_records(self, run_id: str) -> list[dict[str, Any]]:
        del run_id
        raise RepositoryUnavailable("repository is not configured")


def _validate_collection(value: str) -> None:
    allowed = {
        "runs",
        "artifacts",
        "observations",
        "assessments",
        "evidence",
        "reports",
        "deliveries",
    }
    if value not in allowed:
        raise ValueError("unknown repository collection")


def _json_object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RepositoryUnavailable("repository returned a non-object payload")
    return dict(value)


def _normalize_numbers(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: float(item) if isinstance(item, Decimal) else item
        for key, item in value.items()
    }
