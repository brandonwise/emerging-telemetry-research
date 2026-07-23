from __future__ import annotations

import json
import py_compile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    failures: list[str] = []

    for path in sorted(ROOT.rglob("*.json")):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            failures.append(f"JSON {path.relative_to(ROOT)}: {exc}")

    for path in sorted([*ROOT.rglob("*.yaml"), *ROOT.rglob("*.yml"), *ROOT.rglob("*.lobster")]):
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            failures.append(f"YAML {path.relative_to(ROOT)}: {exc}")

    for path in sorted(ROOT.rglob("*.py")):
        try:
            py_compile.compile(str(path), doraise=True)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"Python {path.relative_to(ROOT)}: {exc}")

    required = [
        "README.md",
        "IMPLEMENTATION_PLAN.md",
        "OPENCLAW_BUILD_PROMPT.md",
        "SECURITY.md",
        "THREAT_MODEL.md",
        "EVALS.md",
        "docs/index.html",
        "docs/sample-daily-brief.html",
    ]
    for relative in required:
        if not (ROOT / relative).is_file():
            failures.append(f"Missing required file: {relative}")

    if failures:
        raise SystemExit("Validation failed:\n- " + "\n- ".join(failures))
    print("Repository scaffold validation passed.")


if __name__ == "__main__":
    main()
