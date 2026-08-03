from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path
from typing import Any


def _run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - argv is constructed from local build artifacts.
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _executable(environment: Path, name: str) -> Path:
    directory = "Scripts" if os.name == "nt" else "bin"
    suffix = ".exe" if os.name == "nt" else ""
    return environment / directory / f"{name}{suffix}"


def _json_output(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("smoke command did not return a JSON object")
    return value


def smoke(wheel: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="emerging-telemetry-research-wheel-") as temporary:
        root = Path(temporary)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(environment)
        python = _executable(environment, "python")
        pip = [str(python), "-m", "pip"]
        _run([*pip, "install", "--disable-pip-version-check", str(wheel.resolve())])

        resource_result = _run(
            [
                str(python),
                "-c",
                (
                    "from pathlib import Path; "
                    "import packages.missions.runtime as runtime; "
                    "root=Path(runtime.__file__).resolve().parents[2]; "
                    "required=('config/models.yaml','schemas/mission.schema.json',"
                    "'missions/developer-product-opportunities/mission.yaml',"
                    "'integrations/templates/generic/GENERIC_SETUP.md',"
                    "'fixtures/vertical_slice/early-manifest.json',"
                    "'apps/setup/templates/index.html',"
                    "'apps/setup/static/setup.css'); "
                    "missing=[item for item in required if not (root/item).is_file()]; "
                    "assert not missing, missing; print(root)"
                ),
            ],
            cwd=root,
        )
        package_root = Path(resource_result.stdout.strip())
        mission = package_root / "missions/developer-product-opportunities/mission.yaml"
        signals = package_root / "missions/developer-product-opportunities/fixture-signals.json"
        report_root = root / "reports"
        primary = _executable(environment, "emerging-telemetry-research")
        short_alias = _executable(environment, "telemetry-research")

        _run([str(primary), "--help"], cwd=root)
        _run([str(short_alias), "--help"], cwd=root)
        _run([str(primary), "onboard", "--help"], cwd=root)
        harnesses = _json_output(
            _run([str(primary), "setup", "harnesses", "--json"], cwd=root)
        )
        if harnesses.get("model_calls_executed") is not False:
            raise RuntimeError("harness discovery unexpectedly executed model calls")
        validation = _json_output(
            _run([str(primary), "mission", "validate", str(mission), "--json"], cwd=root)
        )
        execution = _json_output(
            _run(
                [
                    str(primary),
                    "mission",
                    "run",
                    str(mission),
                    "--signals",
                    str(signals),
                    "--output",
                    str(report_root),
                    "--json",
                ],
                cwd=root,
            )
        )
        for key in ("report_json", "report_html", "run_manifest"):
            if not Path(str(execution[key])).is_file():
                raise RuntimeError(f"wheel smoke did not create {key}")
        return {
            "status": "passed",
            "wheel": wheel.name,
            "mission_id": validation["mission_id"],
            "report_id": execution["report_id"],
            "short_alias": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke-test an Emerging Telemetry Research wheel")
    parser.add_argument("--wheel", type=Path)
    arguments = parser.parse_args()
    wheels = sorted(Path("dist").glob("emerging_telemetry_research-*.whl"))
    wheel = arguments.wheel or (wheels[-1] if wheels else None)
    if wheel is None or not wheel.is_file():
        raise SystemExit("build an emerging_telemetry_research wheel first or pass --wheel")
    print(json.dumps(smoke(wheel), sort_keys=True))


if __name__ == "__main__":
    main()
