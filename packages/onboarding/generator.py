from __future__ import annotations

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
    return GeneratedSetup(platform, destination, tuple(created))
