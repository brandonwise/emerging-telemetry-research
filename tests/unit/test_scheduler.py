from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from packages.missions.compiler import activate_mission, draft_mission, write_mission
from packages.scheduler.runtime import MissionScheduleStore

NOW = datetime(2026, 8, 3, 14, tzinfo=UTC)


def _active_mission(tmp_path: Path) -> Path:
    draft = draft_mission(
        "Find product documentation changes that affect customer onboarding reliability.",
        cadence="daily",
    )
    active = activate_mission(
        draft,
        approved_by="Research owner",
        approval_id="schedule-test-approval",
        approved_at=NOW,
    ).mission
    return write_mission(active, tmp_path / "mission.active.yaml")


def test_scheduler_claims_once_and_recovers_failed_or_abandoned_runs(tmp_path: Path) -> None:
    store = MissionScheduleStore(tmp_path / "private/schedules.db")
    scheduled = store.add(_active_mission(tmp_path), run_now=True, now=NOW)

    first = store.claim_due(now=NOW, lease_seconds=60)
    duplicate = store.claim_due(now=NOW, lease_seconds=60)

    assert [item.schedule_id for item in first] == [scheduled.schedule_id]
    assert duplicate == ()

    abandoned = store.claim_due(now=NOW + timedelta(seconds=61), lease_seconds=60)
    assert [item.schedule_id for item in abandoned] == [scheduled.schedule_id]

    failed = store.complete(
        scheduled.schedule_id,
        succeeded=False,
        error="temporary upstream failure with bounded detail",
        now=NOW + timedelta(seconds=62),
    )
    assert failed.last_error == "temporary upstream failure with bounded detail"
    assert store.claim_due(now=NOW + timedelta(minutes=4)) == ()
    assert len(store.claim_due(now=NOW + timedelta(minutes=7))) == 1


def test_scheduler_success_respects_cadence_and_can_be_paused(tmp_path: Path) -> None:
    store = MissionScheduleStore(tmp_path / "schedules.db")
    scheduled = store.add(_active_mission(tmp_path), run_now=True, now=NOW)
    store.claim_due(now=NOW)

    completed = store.complete(scheduled.schedule_id, succeeded=True, now=NOW)

    assert completed.next_run_at == "2026-08-04T14:00:00Z"
    assert completed.last_succeeded_at == "2026-08-03T14:00:00Z"
    paused = store.set_enabled(scheduled.schedule_id, enabled=False)
    assert paused.enabled is False
    assert store.claim_due(now=NOW + timedelta(days=2)) == ()
