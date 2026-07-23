from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = ROOT / "schemas"


class ContractViolation(ValueError):
    pass


def _schema_registry() -> Registry[Any]:
    registry: Registry[Any] = Registry()
    for path in sorted(SCHEMA_ROOT.glob("*.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(contents)
        schema_id = str(contents["$id"])
        registry = registry.with_resource(schema_id, resource)
        base = schema_id.rsplit("/", maxsplit=1)[0]
        registry = registry.with_resource(f"{base}/{path.name}", resource)
    return registry


def load_schema(schema_name: str) -> dict[str, Any]:
    path = SCHEMA_ROOT / schema_name
    if path.parent != SCHEMA_ROOT or not path.is_file():
        raise ContractViolation(f"unknown schema: {schema_name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractViolation(f"schema is not an object: {schema_name}")
    return value


def validate_payload(schema_name: str, payload: dict[str, Any]) -> None:
    schema = load_schema(schema_name)
    validator = Draft202012Validator(
        schema,
        registry=_schema_registry(),
        format_checker=FormatChecker(),
    )
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.absolute_path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise ContractViolation(f"{schema_name} at {location}: {first.message}")


def parse_json_object(raw: str, schema_name: str) -> dict[str, Any]:
    if raw.lstrip().startswith("```"):
        raise ContractViolation("markdown-wrapped JSON is forbidden")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractViolation(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ContractViolation("model output must be one JSON object")
    validate_payload(schema_name, value)
    return value
