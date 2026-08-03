import json
import shutil
import subprocess
from pathlib import Path


def test_boundary_plugin_manifest_and_javascript_are_valid() -> None:
    root = Path("openclaw/plugins/telemetry-research-boundary")
    manifest = json.loads((root / "openclaw.plugin.json").read_text(encoding="utf-8"))
    assert manifest["id"] == "telemetry-research-boundary"
    assert manifest["enabledByDefault"] is False
    assert manifest["contracts"]["tools"] == [
        "research_flow_start",
        "research_flow_finish",
        "research_delivery_send",
    ]
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
    source = Path("openclaw/plugins/telemetry-research-boundary/index.js").read_text(
        encoding="utf-8"
    )
    assert 'from "openclaw/plugin-sdk/plugin-entry"' in source
    assert 'from "openclaw/plugin-sdk/tool-results"' in source
    delivery_block = source.split("const DELIVERY_PARAMETERS", 1)[1].split(
        "function pluginConfig",
        1,
    )[0]
    assert "destination" not in delivery_block
    assert "discordChannelId" not in delivery_block
    assert 'htmlPath.slice(0, -5) + ".delivery.json"' in source
    assert "deliveryPlan.idempotency_key !== params.idempotency_key" in source
    assert "deliveryPlan.summary !== params.summary" in source
    assert "deliveryPlan.destination !== expectedDestination" in source
    assert 'code: "DELIVERY_PLAN_MISMATCH"' in source
    assert "openKeyedStore" not in source
    assert '".delivery-receipts"' in source
    assert 'flag: "wx"' in source
    assert 'status: "pending"' in source
    assert 'status: "delivered"' in source
    assert '"DELIVERY_STATUS_UNKNOWN"' in source
