import pytest

from packages.workflow.dead_letters import DeadLetter, build_replay_step


def test_dead_letter_replay_is_deterministic_and_input_preserving() -> None:
    item = DeadLetter(
        dead_letter_id="dead_fixture",
        run_id="run_fixture",
        original_step_id="step_original",
        step_name="sanitize",
        input_ref="raw/sha256/fixture",
        input_hash="a" * 64,
        error_code="parser_timeout",
        status="claimed",
    )
    first = build_replay_step(item, policy_revision="policy-v2")
    second = build_replay_step(item, policy_revision="policy-v2")
    assert first == second
    assert first.input_hash == item.input_hash
    assert first.replay_of == item.dead_letter_id


def test_unclaimed_dead_letter_cannot_be_replayed() -> None:
    item = DeadLetter(
        dead_letter_id="dead_fixture",
        run_id="run_fixture",
        original_step_id="step_original",
        step_name="sanitize",
        input_ref="raw/sha256/fixture",
        input_hash="a" * 64,
        error_code="parser_timeout",
        status="pending",
    )
    with pytest.raises(ValueError, match="claimed"):
        build_replay_step(item, policy_revision="policy-v2")
