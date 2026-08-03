from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packages.common.canonical import format_timestamp, stable_id
from packages.missions.compiler import compile_mission, load_mission
from packages.security_gateway.permissions import harden_private_path

CADENCE_DELTA = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
}


@dataclass(frozen=True, slots=True)
class ScheduledMission:
    schedule_id: str
    mission_path: str
    mission_id: str
    mission_name: str
    cadence: str
    enabled: bool
    next_run_at: str
    last_started_at: str | None
    last_succeeded_at: str | None
    last_error: str | None

    def to_contract(self) -> dict[str, object]:
        return asdict(self)


class MissionScheduleStore:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        harden_private_path(self.path.parent)
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS mission_schedules (
                  schedule_id TEXT PRIMARY KEY,
                  mission_path TEXT NOT NULL UNIQUE,
                  mission_id TEXT NOT NULL,
                  mission_name TEXT NOT NULL,
                  cadence TEXT NOT NULL,
                  enabled INTEGER NOT NULL,
                  next_run_at TEXT NOT NULL,
                  lease_until TEXT,
                  last_started_at TEXT,
                  last_succeeded_at TEXT,
                  last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS mission_schedules_due_idx
                  ON mission_schedules (enabled, next_run_at, lease_until);
                """
            )
        harden_private_path(self.path)

    def add(
        self,
        mission_path: Path,
        *,
        run_now: bool = False,
        now: datetime | None = None,
    ) -> ScheduledMission:
        path = mission_path.resolve()
        mission = load_mission(path)
        compiled = compile_mission(mission)
        if not compiled.collection_authorized:
            raise ValueError("only an approved active mission can be scheduled")
        cadence = str(mission.payload["output"]["cadence"])
        if cadence not in CADENCE_DELTA:
            raise ValueError("manual missions cannot be scheduled")
        current = _utc(now)
        next_run = current if run_now else current + CADENCE_DELTA[cadence]
        schedule_id = stable_id("sc", mission.mission_id, str(path))
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO mission_schedules (
                  schedule_id, mission_path, mission_id, mission_name, cadence,
                  enabled, next_run_at, lease_until, last_started_at,
                  last_succeeded_at, last_error
                ) VALUES (?, ?, ?, ?, ?, 1, ?, NULL, NULL, NULL, NULL)
                ON CONFLICT(schedule_id) DO UPDATE SET
                  mission_path=excluded.mission_path,
                  mission_id=excluded.mission_id,
                  mission_name=excluded.mission_name,
                  cadence=excluded.cadence,
                  enabled=1,
                  next_run_at=excluded.next_run_at,
                  lease_until=NULL,
                  last_error=NULL
                """,
                (
                    schedule_id,
                    str(path),
                    mission.mission_id,
                    mission.name,
                    cadence,
                    format_timestamp(next_run),
                ),
            )
        scheduled = self.get(schedule_id)
        assert scheduled is not None
        return scheduled

    def list(self) -> tuple[ScheduledMission, ...]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM mission_schedules ORDER BY mission_name, schedule_id"
            ).fetchall()
        return tuple(_scheduled(row) for row in rows)

    def get(self, schedule_id: str) -> ScheduledMission | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM mission_schedules WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
        return _scheduled(row) if row is not None else None

    def set_enabled(self, schedule_id: str, *, enabled: bool) -> ScheduledMission:
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE mission_schedules SET enabled = ?, lease_until = NULL "
                "WHERE schedule_id = ?",
                (int(enabled), schedule_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("schedule not found")
        scheduled = self.get(schedule_id)
        assert scheduled is not None
        return scheduled

    def claim_due(
        self,
        *,
        now: datetime | None = None,
        lease_seconds: int = 900,
        limit: int = 20,
    ) -> tuple[ScheduledMission, ...]:
        if not 30 <= lease_seconds <= 3600 or not 1 <= limit <= 100:
            raise ValueError("schedule claim limits are invalid")
        current = _utc(now)
        now_text = format_timestamp(current)
        lease_text = format_timestamp(current + timedelta(seconds=lease_seconds))
        claimed: list[ScheduledMission] = []
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT * FROM mission_schedules
                WHERE enabled = 1 AND next_run_at <= ?
                  AND (lease_until IS NULL OR lease_until <= ?)
                ORDER BY next_run_at, schedule_id
                LIMIT ?
                """,
                (now_text, now_text, limit),
            ).fetchall()
            for row in rows:
                connection.execute(
                    "UPDATE mission_schedules SET lease_until = ?, last_started_at = ? "
                    "WHERE schedule_id = ?",
                    (lease_text, now_text, str(row["schedule_id"])),
                )
                claimed.append(
                    _scheduled(
                        {
                            **dict(row),
                            "lease_until": lease_text,
                            "last_started_at": now_text,
                        }
                    )
                )
            connection.commit()
        return tuple(claimed)

    def complete(
        self,
        schedule_id: str,
        *,
        succeeded: bool,
        error: str | None = None,
        now: datetime | None = None,
    ) -> ScheduledMission:
        current = _utc(now)
        scheduled = self.get(schedule_id)
        if scheduled is None:
            raise ValueError("schedule not found")
        next_run = (
            current + CADENCE_DELTA[scheduled.cadence]
            if succeeded
            else current + timedelta(minutes=5)
        )
        bounded_error = None if succeeded else " ".join((error or "run failed").split())[:500]
        with self._connection() as connection:
            connection.execute(
                """
                UPDATE mission_schedules
                SET next_run_at = ?, lease_until = NULL,
                    last_succeeded_at = CASE WHEN ? = 1 THEN ? ELSE last_succeeded_at END,
                    last_error = ?
                WHERE schedule_id = ?
                """,
                (
                    format_timestamp(next_run),
                    int(succeeded),
                    format_timestamp(current),
                    bounded_error,
                    schedule_id,
                ),
            )
        completed = self.get(schedule_id)
        assert completed is not None
        return completed

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _scheduled(row: sqlite3.Row | dict[str, object]) -> ScheduledMission:
    return ScheduledMission(
        schedule_id=str(row["schedule_id"]),
        mission_path=str(row["mission_path"]),
        mission_id=str(row["mission_id"]),
        mission_name=str(row["mission_name"]),
        cadence=str(row["cadence"]),
        enabled=bool(row["enabled"]),
        next_run_at=str(row["next_run_at"]),
        last_started_at=_optional(row["last_started_at"]),
        last_succeeded_at=_optional(row["last_succeeded_at"]),
        last_error=_optional(row["last_error"]),
    )


def _optional(value: object) -> str | None:
    return str(value) if value is not None else None


def _utc(value: datetime | None) -> datetime:
    result = value or datetime.now(UTC)
    if result.tzinfo is None:
        raise ValueError("scheduler timestamps must include a timezone")
    return result.astimezone(UTC)
