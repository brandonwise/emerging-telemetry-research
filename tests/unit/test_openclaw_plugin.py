import json
import shutil
import subprocess
from pathlib import Path


def test_boundary_plugin_manifest_and_javascript_are_valid() -> None:
    root = Path("openclaw/plugins/threat-radar-boundary")
    manifest = json.loads((root / "openclaw.plugin.json").read_text(encoding="utf-8"))
    assert manifest["id"] == "threat-radar-boundary"
    assert manifest["enabledByDefault"] is False
    node = shutil.which("node")
    assert node
    completed = subprocess.run(  # noqa: S603
        [node, "--check", str(root / "index.js")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_delivery_tool_has_no_destination_parameter() -> None:
    source = Path("openclaw/plugins/threat-radar-boundary/index.js").read_text(encoding="utf-8")
    delivery_block = source.split("const DELIVERY_PARAMETERS", 1)[1].split(
        "function pluginConfig",
        1,
    )[0]
    assert "destination" not in delivery_block
    assert "discordChannelId" not in delivery_block
