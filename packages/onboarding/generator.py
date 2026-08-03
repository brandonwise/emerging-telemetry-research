from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_PLATFORMS = (
    "openclaw",
    "claude-code",
    "codex",
    "perplexity",
    "generic",
)
DEFAULT_TEMPLATES_ROOT = Path(__file__).resolve().parents[2] / "integrations" / "templates"
PLATFORM_ADAPTER = {
    "openclaw": "openclaw",
    "claude-code": "claude",
    "codex": "codex",
    "perplexity": "openai-compatible",
    "generic": "auto",
}


@dataclass(frozen=True, slots=True)
class GeneratedSetup:
    platform: str
    output_root: Path
    files: tuple[Path, ...]


def generate_setup(
    *,
    platform: str,
    output_root: Path,
    templates_root: Path,
    force: bool = False,
) -> GeneratedSetup:
    if platform not in SUPPORTED_PLATFORMS:
        raise ValueError("unsupported platform")
    source = (templates_root / platform).resolve()
    if not source.is_dir():
        raise ValueError(f"integration template is missing: {platform}")
    destination = output_root.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    for source_path in sorted(source.rglob("*")):
        if source_path.is_dir():
            continue
        relative = source_path.relative_to(source)
        target = destination / relative
        if target.exists() and not force:
            raise ValueError(f"refusing to overwrite {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)
        if target.suffix == ".sh":
            target.chmod(0o750)
        created.append(target)
    common = templates_root / "common"
    for source_path in sorted(common.rglob("*")):
        if source_path.is_dir():
            continue
        relative = source_path.relative_to(common)
        target = destination / relative
        if target.exists() and not force:
            raise ValueError(f"refusing to overwrite {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)
        if target.suffix == ".sh":
            target.chmod(0o750)
        created.append(target)
    manifest = destination / "telemetry-research-adapter.json"
    if manifest.exists() and not force:
        raise ValueError(f"refusing to overwrite {manifest}")
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "platform": platform,
                "agent_adapter": PLATFORM_ADAPTER[platform],
                "private_config": ".emerging-telemetry-research/config.env",
                "optional_overrides": "research.env",
                "external_delivery_enabled": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    created.append(manifest)
    return GeneratedSetup(platform, destination, tuple(created))
