import json
import os
from pathlib import Path

import pytest

from packages.onboarding.generator import SUPPORTED_PLATFORMS, generate_setup
from scripts.setup_openclaw_agents import expected_agents


@pytest.mark.parametrize("platform", SUPPORTED_PLATFORMS)
def test_platform_setup_generates_runnable_adapter(
    tmp_path: Path,
    platform: str,
) -> None:
    destination = tmp_path / platform

    generated = generate_setup(
        platform=platform,
        output_root=destination,
        templates_root=Path("integrations/templates"),
    )

    assert generated.platform == platform
    if os.name != "nt":
        assert (destination / "run-research.sh").stat().st_mode & 0o100
    assert (destination / "run-research.ps1").is_file()
    assert (destination / "research.env.example").is_file()
    manifest = json.loads(
        (destination / "telemetry-research-adapter.json").read_text(encoding="utf-8")
    )
    assert manifest["platform"] == platform
    assert manifest["external_delivery_enabled"] is False
    if platform == "claude-code":
        assert (destination / "CLAUDE.md").is_file()
        assert (destination / ".claude/skills/telemetry-research/SKILL.md").is_file()
    if platform == "codex":
        assert (destination / "AGENTS.md").is_file()
        assert (destination / ".agents/skills/telemetry-research/SKILL.md").is_file()


def test_setup_refuses_to_overwrite_existing_adapter(tmp_path: Path) -> None:
    destination = tmp_path / "generic"
    destination.mkdir()
    (destination / "run-research.sh").write_text("owned by user\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        generate_setup(
            platform="generic",
            output_root=destination,
            templates_root=Path("integrations/templates"),
        )


def test_openclaw_setup_preserves_default_model_unless_explicitly_selected(
    tmp_path: Path,
) -> None:
    defaults = expected_agents(tmp_path)
    selected = expected_agents(tmp_path, model="provider/approved-model")

    assert all(agent.model is None for agent in defaults)
    assert all(agent.model == "provider/approved-model" for agent in selected)
