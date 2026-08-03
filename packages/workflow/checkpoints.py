from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from packages.common.canonical import canonical_json_bytes, sha256_hex
from packages.security_gateway.permissions import harden_private_path


class CheckpointConflict(RuntimeError):
    pass


class SQLiteCheckpointStore:
    """Durable, content-validated checkpoints for portable graph execution."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        harden_private_path(self.path.parent)
        self._lock = threading.Lock()
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS workflow_checkpoints (
                  workflow_id TEXT NOT NULL,
                  node_id TEXT NOT NULL,
                  input_hash TEXT NOT NULL,
                  output_json TEXT NOT NULL,
                  output_hash TEXT NOT NULL,
                  attempts INTEGER NOT NULL CHECK (attempts > 0),
                  completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  PRIMARY KEY (workflow_id, node_id)
                );
                """
            )
        harden_private_path(self.path)

    def load(
        self,
        workflow_id: str,
        node_id: str,
        input_hash: str,
    ) -> tuple[dict[str, Any], int] | None:
        with self._lock, self._connection() as connection:
            row = connection.execute(
                """
                SELECT input_hash, output_json, output_hash, attempts
                FROM workflow_checkpoints
                WHERE workflow_id = ? AND node_id = ?
                """,
                (workflow_id, node_id),
            ).fetchone()
        if row is None:
            return None
        if str(row["input_hash"]) != input_hash:
            raise CheckpointConflict(f"checkpoint input changed for node {node_id}")
        output = json.loads(str(row["output_json"]))
        if not isinstance(output, dict):
            raise CheckpointConflict(f"checkpoint output is invalid for node {node_id}")
        if sha256_hex(canonical_json_bytes(output)) != str(row["output_hash"]):
            raise CheckpointConflict(f"checkpoint output hash mismatch for node {node_id}")
        return output, int(row["attempts"])

    def save(
        self,
        workflow_id: str,
        node_id: str,
        input_hash: str,
        output: dict[str, Any],
        attempts: int,
    ) -> None:
        output_bytes = canonical_json_bytes(output)
        output_hash = sha256_hex(output_bytes)
        with self._lock, self._connection() as connection:
            existing = connection.execute(
                """
                SELECT input_hash, output_hash
                FROM workflow_checkpoints
                WHERE workflow_id = ? AND node_id = ?
                """,
                (workflow_id, node_id),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["input_hash"]) != input_hash
                    or str(existing["output_hash"]) != output_hash
                ):
                    raise CheckpointConflict(f"immutable checkpoint conflict for node {node_id}")
                return
            connection.execute(
                """
                INSERT INTO workflow_checkpoints (
                  workflow_id, node_id, input_hash, output_json, output_hash, attempts
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    workflow_id,
                    node_id,
                    input_hash,
                    output_bytes.decode("utf-8"),
                    output_hash,
                    attempts,
                ),
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()
