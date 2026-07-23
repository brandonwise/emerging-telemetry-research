from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from packages.common.canonical import canonical_json_bytes, sha256_hex
from packages.pipeline.frozen import run_frozen_fixture


def verify_frozen_restore(fixture: Path, output_root: Path) -> dict[str, Any]:
    original = run_frozen_fixture(fixture, output_root / "original")
    backup = output_root / "backup" / "objects"
    restored_objects = output_root / "restored-objects"
    shutil.copytree(output_root / "original" / "objects", backup)
    shutil.copytree(backup, restored_objects)
    restored = run_frozen_fixture(
        fixture,
        output_root / "restored",
        object_store_root=restored_objects,
    )
    result: dict[str, Any] = {
        "report_json_match": (
            original.report_json_path.read_bytes() == restored.report_json_path.read_bytes()
        ),
        "report_html_match": (
            original.rendered.path.read_bytes() == restored.rendered.path.read_bytes()
        ),
        "audit_log_match": (
            original.audit_path.read_bytes() == restored.audit_path.read_bytes()
        ),
        "restored_report_sha256": sha256_hex(restored.report_json_path.read_bytes()),
    }
    result["passed"] = all(
        result[key]
        for key in ("report_json_match", "report_html_match", "audit_log_match")
    )
    result_path = output_root / "restore-results.json"
    result_path.write_bytes(canonical_json_bytes(result) + b"\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path("tests/fixtures/vertical_slice/flash-manifest.json"),
    )
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    result = verify_frozen_restore(arguments.fixture, arguments.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["passed"] is not True:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
