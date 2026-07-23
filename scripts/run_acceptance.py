from __future__ import annotations

import argparse
import json
from pathlib import Path

from packages.evaluation.harness import run_acceptance_suite


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path("tests/fixtures/vertical_slice"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_acceptance_suite(args.fixtures, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["passed"] is not True:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
