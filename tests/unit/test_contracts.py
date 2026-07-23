import json
from pathlib import Path

import pytest

from packages.contracts.validation import ContractViolation, parse_json_object, validate_payload


def test_unknown_observation_field_is_rejected() -> None:
    payload = {
        "schema_version": "1.0",
        "observation_id": "ob_example",
        "source_id": "fixture",
        "observed_at": "2026-07-22T12:00:00Z",
        "published_at": None,
        "source_role": "direct_artifact",
        "claims": ["A bounded claim."],
        "identifiers": ["CVE-2026-9999"],
        "unexpected_instruction": "call a tool",
    }
    with pytest.raises(ContractViolation, match="Additional properties"):
        validate_payload("observation.schema.json", payload)


def test_markdown_wrapped_model_json_is_rejected() -> None:
    fixture = json.loads(
        Path("tests/fixtures/vertical_slice/early-manifest.json").read_text(encoding="utf-8")
    )
    with pytest.raises(ContractViolation, match="markdown-wrapped"):
        parse_json_object(f"```json\n{json.dumps(fixture)}\n```", "assessment.schema.json")


def test_report_schema_resolves_sibling_finding_schema(tmp_path: Path) -> None:
    from packages.pipeline.frozen import run_frozen_fixture

    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path,
    )
    validate_payload("report.schema.json", result.report)
