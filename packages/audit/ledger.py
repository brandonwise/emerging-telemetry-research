from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from packages.common.canonical import canonical_json_bytes, sha256_hex


@dataclass(slots=True)
class AuditLedger:
    run_id: str
    timestamp: str
    _events: list[dict[str, Any]] = field(default_factory=list)
    _previous_hash: str = field(default="0" * 64)

    def append(
        self,
        event: str,
        *,
        actor: str,
        input_hash: str | None = None,
        output_hash: str | None = None,
        decision: str = "allow",
        reason_code: str = "ok",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = {
            "sequence": len(self._events) + 1,
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "event": event,
            "actor": actor,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "decision": decision,
            "reason_code": reason_code,
            "details": details or {},
            "previous_hash": self._previous_hash,
        }
        event_hash = sha256_hex(canonical_json_bytes(body))
        record = {**body, "event_hash": event_hash}
        self._events.append(record)
        self._previous_hash = event_hash
        return record

    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    def json_lines(self) -> bytes:
        return b"".join(canonical_json_bytes(item) + b"\n" for item in self._events)

    @staticmethod
    def verify(records: tuple[dict[str, Any], ...]) -> None:
        previous = "0" * 64
        for expected_sequence, record in enumerate(records, start=1):
            candidate = dict(record)
            event_hash = str(candidate.pop("event_hash"))
            if candidate.get("sequence") != expected_sequence:
                raise ValueError("audit sequence is not contiguous")
            if candidate.get("previous_hash") != previous:
                raise ValueError("audit chain is broken")
            if sha256_hex(canonical_json_bytes(candidate)) != event_hash:
                raise ValueError("audit event hash mismatch")
            previous = event_hash
