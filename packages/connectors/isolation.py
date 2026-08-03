from __future__ import annotations

import json
import multiprocessing
import os
import time
from datetime import datetime
from multiprocessing.connection import Connection
from typing import Any

import psutil

from packages.common.canonical import canonical_json_bytes
from packages.connectors.tier0 import parse_tier0
from packages.contracts.validation import validate_payload


class IsolatedParserError(RuntimeError):
    pass


def parse_tier0_contracts_isolated(
    source_id: str,
    content: bytes,
    observed_at: datetime,
    *,
    timeout_seconds: float = 15,
    maximum_output_bytes: int = 16_777_216,
    maximum_memory_bytes: int = 536_870_912,
) -> tuple[dict[str, Any], ...]:
    if not 0 < timeout_seconds <= 120:
        raise ValueError("parser timeout must be between zero and 120 seconds")
    if not 1_024 <= maximum_output_bytes <= 67_108_864:
        raise ValueError("parser output limit is invalid")
    if not 67_108_864 <= maximum_memory_bytes <= 2_147_483_648:
        raise ValueError("parser memory limit is invalid")
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker,
        args=(sender, source_id, content, observed_at, maximum_memory_bytes),
        daemon=True,
    )
    process.start()
    sender.close()
    try:
        deadline = time.monotonic() + timeout_seconds
        while not receiver.poll(0.05):
            if time.monotonic() >= deadline:
                process.terminate()
                process.join(timeout=2)
                raise IsolatedParserError("isolated parser timed out")
            if process.pid is None:
                raise IsolatedParserError("isolated parser did not start")
            try:
                child = psutil.Process(process.pid)
                if child.memory_info().rss > maximum_memory_bytes:
                    process.terminate()
                    process.join(timeout=2)
                    raise IsolatedParserError("isolated parser exceeded memory policy")
                cpu = child.cpu_times()
                if cpu.user + cpu.system > 10:
                    process.terminate()
                    process.join(timeout=2)
                    raise IsolatedParserError("isolated parser exceeded CPU policy")
            except psutil.NoSuchProcess:
                if not receiver.poll(0.1):
                    raise IsolatedParserError("isolated parser exited without output") from None
        try:
            encoded = receiver.recv_bytes(maxlength=maximum_output_bytes)
        except OSError as exc:
            raise IsolatedParserError("isolated parser output exceeded policy") from exc
    finally:
        receiver.close()
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
    try:
        result = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IsolatedParserError("isolated parser returned invalid output") from exc
    if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
        raise IsolatedParserError("isolated parser returned an invalid envelope")
    if result["ok"] is not True:
        raise IsolatedParserError(str(result.get("error", "isolated parser failed"))[:300])
    items = result.get("observations")
    if not isinstance(items, list) or len(items) > 100_000:
        raise IsolatedParserError("isolated parser returned an invalid observation list")
    observations: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise IsolatedParserError("isolated parser returned a non-object observation")
        validate_payload("observation.schema.json", item)
        observations.append(item)
    return tuple(observations)


def _worker(
    sender: Connection,
    source_id: str,
    content: bytes,
    observed_at: datetime,
    maximum_memory_bytes: int,
) -> None:
    try:
        _apply_resource_limits(maximum_memory_bytes)
        os.environ.clear()
        observations = [item.to_contract() for item in parse_tier0(source_id, content, observed_at)]
        sender.send_bytes(
            canonical_json_bytes({"ok": True, "observations": observations})
        )
    except Exception as exc:
        sender.send_bytes(
            canonical_json_bytes(
                {
                    "ok": False,
                    "error": f"isolated parser failed: {type(exc).__name__}",
                }
            )
        )
    finally:
        sender.close()


def _apply_resource_limits(maximum_memory_bytes: int) -> None:
    if os.name == "nt":
        return
    try:
        import resource

        setrlimit = getattr(resource, "setrlimit", None)
        cpu_limit = getattr(resource, "RLIMIT_CPU", None)
        address_space_limit = getattr(resource, "RLIMIT_AS", None)
        if not callable(setrlimit) or cpu_limit is None or address_space_limit is None:
            return
        setrlimit(cpu_limit, (10, 10))
        setrlimit(
            address_space_limit,
            (maximum_memory_bytes, maximum_memory_bytes),
        )
    except (ImportError, OSError, ValueError):
        return
