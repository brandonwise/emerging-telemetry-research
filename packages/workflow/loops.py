from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from packages.common.canonical import canonical_json_bytes, sha256_hex

LoopState = dict[str, Any]
LoopHandler = Callable[[int, LoopState], "LoopDecision"]


@dataclass(frozen=True, slots=True)
class LoopDecision:
    state: LoopState
    complete: bool
    reason: str


@dataclass(frozen=True, slots=True)
class LoopExecution:
    state: LoopState
    manifest: dict[str, Any]


def execute_bounded_loop(
    initial_state: LoopState,
    handler: LoopHandler,
    *,
    maximum_iterations: int,
) -> LoopExecution:
    if not 1 <= maximum_iterations <= 100:
        raise ValueError("maximum loop iterations must be between one and 100")
    state = dict(initial_state)
    seen = {sha256_hex(canonical_json_bytes(state))}
    steps: list[dict[str, Any]] = []
    for iteration in range(1, maximum_iterations + 1):
        decision = handler(iteration, dict(state))
        if not isinstance(decision.state, dict) or not decision.reason:
            raise TypeError("loop handler returned an invalid decision")
        state = dict(decision.state)
        state_hash = sha256_hex(canonical_json_bytes(state))
        steps.append(
            {
                "iteration": iteration,
                "state_sha256": state_hash,
                "reason": decision.reason[:300],
                "complete": decision.complete,
            }
        )
        if decision.complete:
            return LoopExecution(
                state,
                {"status": "completed", "iterations": iteration, "steps": steps},
            )
        if state_hash in seen:
            raise RuntimeError("bounded loop repeated a prior state without completing")
        seen.add(state_hash)
    return LoopExecution(
        state,
        {"status": "limit_reached", "iterations": maximum_iterations, "steps": steps},
    )
