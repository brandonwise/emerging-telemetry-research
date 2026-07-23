from __future__ import annotations

from dataclasses import dataclass

from packages.common.canonical import stable_id


@dataclass(frozen=True, slots=True)
class DeadLetter:
    dead_letter_id: str
    run_id: str
    original_step_id: str
    step_name: str
    input_ref: str
    input_hash: str
    error_code: str
    status: str


@dataclass(frozen=True, slots=True)
class ReplayStep:
    step_id: str
    run_id: str
    step_name: str
    input_ref: str
    input_hash: str
    idempotency_key: str
    replay_of: str


def build_replay_step(dead_letter: DeadLetter, *, policy_revision: str) -> ReplayStep:
    if dead_letter.status != "claimed":
        raise ValueError("dead letter must be claimed before replay")
    if not policy_revision:
        raise ValueError("policy revision is required")
    replay_identity = stable_id(
        "replay",
        dead_letter.dead_letter_id,
        dead_letter.input_hash,
        policy_revision,
        length=48,
    )
    return ReplayStep(
        step_id=stable_id("step", replay_identity),
        run_id=dead_letter.run_id,
        step_name=dead_letter.step_name,
        input_ref=dead_letter.input_ref,
        input_hash=dead_letter.input_hash,
        idempotency_key=replay_identity,
        replay_of=dead_letter.dead_letter_id,
    )
