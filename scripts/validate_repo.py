from __future__ import annotations

import json
import py_compile
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
IGNORED_PARTS = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "reports"}


class ArchitectureVisualParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.duplicate_ids: set[str] = set()
        self.anchor_targets: set[str] = set()
        self.node_ids: set[str] = set()
        self.edge_targets: list[tuple[str | None, str | None]] = []
        self.edge_without_marker = 0
        self.edge_after_node = 0
        self.section_count = 0
        self.svg_count = 0
        self.svg_title_count = 0
        self.svg_desc_count = 0
        self.forbidden_elements: set[str] = set()
        self.remote_assets: set[str] = set()
        self._svg_depth = 0
        self._svg_node_seen = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attrs)
        identifier = values.get("id")
        if identifier is not None:
            if identifier in self.ids:
                self.duplicate_ids.add(identifier)
            self.ids.add(identifier)
        href = values.get("href")
        if tag == "a" and href is not None and href.startswith("#"):
            self.anchor_targets.add(href[1:])
        if tag == "section":
            self.section_count += 1
        if tag == "svg":
            self.svg_count += 1
            self._svg_depth += 1
            self._svg_node_seen = False
        elif self._svg_depth and tag == "title":
            self.svg_title_count += 1
        elif self._svg_depth and tag == "desc":
            self.svg_desc_count += 1
        if self._svg_depth and tag == "g" and identifier is not None:
            self.node_ids.add(identifier)
            self._svg_node_seen = True
        if self._svg_depth and tag in {"path", "line", "polyline"}:
            source = values.get("data-from")
            target = values.get("data-to")
            if source is not None or target is not None:
                self.edge_targets.append((source, target))
                if values.get("marker-end") is None:
                    self.edge_without_marker += 1
                if self._svg_node_seen:
                    self.edge_after_node += 1
        if tag in {"script", "foreignobject"}:
            self.forbidden_elements.add(tag)
        for attribute in ("src", "href"):
            value = values.get(attribute)
            if value is not None and value.startswith(("http://", "https://", "//")):
                self.remote_assets.add(value)

    def handle_endtag(self, tag: str) -> None:
        if tag == "svg":
            self._svg_depth -= 1
            self._svg_node_seen = False


def repository_files(pattern: str) -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob(pattern)
        if not any(part in IGNORED_PARTS for part in path.relative_to(ROOT).parts)
    )


def load_yaml(relative: str) -> dict[str, Any]:
    value = yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{relative} must contain an object")
    return value


def check_release_gates(failures: list[str]) -> None:
    sources = load_yaml("config/sources.yaml")
    schedules = load_yaml("config/schedules.yaml")
    report = load_yaml("config/report.yaml")
    embeddings = load_yaml("config/embeddings.yaml")
    terms = load_yaml("config/source-terms.yaml")
    approval_text = (ROOT / "THREAT_MODEL_APPROVAL.md").read_text(encoding="utf-8")
    approval_pending = "Status: approved" not in approval_text

    source_items = sources.get("sources", [])
    if not isinstance(source_items, list):
        failures.append("config/sources.yaml sources must be a list")
        return
    enabled_sources = [
        str(source.get("id"))
        for source in source_items
        if isinstance(source, dict) and source.get("enabled") is True
    ]
    if sources.get("defaults", {}).get("enabled") is not False:
        failures.append("Source defaults must fail closed")
    if approval_pending and enabled_sources:
        failures.append(
            "Threat model is pending but sources are enabled: " + ", ".join(enabled_sources)
        )
    if approval_pending and schedules.get("enabled") is not False:
        failures.append("Threat model is pending but scheduled workflows are enabled")

    publication = report.get("publication", {})
    discord = report.get("discord", {})
    if approval_pending and publication.get("external_delivery_enabled") is not False:
        failures.append("Threat model is pending but external delivery is enabled")
    if approval_pending and discord.get("enabled") is not False:
        failures.append("Threat model is pending but Discord delivery is enabled")
    if approval_pending and publication.get("shadow_mode") is not True:
        failures.append("Unapproved deployments must remain in shadow mode")
    if (
        not approval_pending
        and publication.get("external_delivery_enabled") is True
        and publication.get("shadow_mode") is not False
    ):
        failures.append("Approved external delivery cannot be labeled shadow mode")

    semantic = embeddings.get("semantic_clustering", {})
    if semantic.get("enabled") is True and semantic.get("mode") != "shadow":
        failures.append("Local semantic clustering must remain in shadow mode")
    if semantic.get("enabled") is True and semantic.get("provider") != "ollama":
        failures.append("Local semantic clustering must use the loopback Ollama adapter")

    source_terms = terms.get("sources", {})
    default_terms_status = terms.get("default_status")
    configured_source_ids = {
        str(source.get("id"))
        for source in source_items
        if isinstance(source, dict) and source.get("id")
    }
    explicit_terms_ids = set(source_terms) if isinstance(source_terms, dict) else set()
    missing_terms = sorted(configured_source_ids - explicit_terms_ids)
    if missing_terms:
        failures.append("Sources omit explicit legal metadata: " + ", ".join(missing_terms))
    for source in source_items:
        if not isinstance(source, dict) or source.get("enabled") is not True:
            continue
        source_id = str(source.get("id"))
        if not source.get("collection_approval_id"):
            failures.append(f"Enabled source {source_id} has no approval reference")
        record = source_terms.get(source_id, {}) if isinstance(source_terms, dict) else {}
        status_value = record.get("status", default_terms_status)
        if status_value != "approved":
            failures.append(f"Enabled source {source_id} has no approved terms record")


def check_contracts(failures: list[str]) -> None:
    for path in repository_files("schemas/*.json"):
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            if schema.get("type") == "object" and schema.get("additionalProperties") is not False:
                failures.append(f"Schema must reject unknown fields: {path.relative_to(ROOT)}")
        except Exception as exc:
            failures.append(f"JSON Schema {path.relative_to(ROOT)}: {exc}")

    try:
        contract = load_yaml("openapi/openapi.yaml")
        if contract.get("openapi") != "3.1.0":
            failures.append("OpenAPI contract must remain version 3.1.0")
        security_schemes = contract.get("components", {}).get("securitySchemes", {})
        if security_schemes.get("mutualTLS", {}).get("type") != "mutualTLS":
            failures.append("OpenAPI contract must require mutual TLS")
        for path_item in contract.get("paths", {}).values():
            if not isinstance(path_item, dict):
                continue
            for operation in path_item.values():
                if (
                    isinstance(operation, dict)
                    and "operationId" in operation
                    and not operation.get("x-radar-roles")
                ):
                    failures.append(
                        f"OpenAPI operation {operation['operationId']} has no role boundary"
                    )
    except Exception as exc:
        failures.append(f"OpenAPI contract: {exc}")


def check_migrations(failures: list[str]) -> None:
    migration_text = "\n".join(
        path.read_text(encoding="utf-8").lower() for path in repository_files("migrations/*.sql")
    )
    found = set(re.findall(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([a-z_]+)", migration_text))
    required_table_groups = {
        "runs": {"runs"},
        "steps": {"steps", "workflow_steps"},
        "source registry": {"source_registry"},
        "source cursors": {"source_cursors"},
        "source health": {"source_health"},
        "artifacts": {"raw_artifacts"},
        "observations": {"observations"},
        "entities": {"entities"},
        "clusters": {"clusters"},
        "assessments": {"assessments"},
        "evidence": {"evidence", "evidence_items"},
        "reports": {"reports"},
        "usage": {"usage_records", "model_usage"},
        "deliveries": {"deliveries"},
        "policy decisions": {"policy_decisions"},
        "security events": {"security_events"},
        "dead letters": {"dead_letters"},
    }
    missing = sorted(
        label for label, aliases in required_table_groups.items() if aliases.isdisjoint(found)
    )
    if missing:
        failures.append("Migrations omit required tables: " + ", ".join(missing))
    if "skip locked" not in migration_text:
        failures.append("Durable claim work must use PostgreSQL SKIP LOCKED")
    has_immutable_evidence = (
        "reject_row_mutation" in migration_text and "evidence_items_immutable" in migration_text
    )
    if not has_immutable_evidence:
        failures.append("Immutable evidence tables need database-enforced mutation rejection")


def check_supply_chain(failures: list[str]) -> None:
    action_pin = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[a-f0-9]{40}$")
    for workflow in repository_files(".github/workflows/*.yml"):
        for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            match = re.fullmatch(r"-?\s*uses:\s*(.+)", stripped)
            if match is None:
                continue
            action = match.group(1).split("#", 1)[0].strip()
            if action.startswith("./"):
                continue
            if not action_pin.fullmatch(action):
                failures.append(
                    f"GitHub Action is not commit pinned: "
                    f"{workflow.relative_to(ROOT)}:{line_number}"
                )

    compose = load_yaml("infra/docker-compose.yml")
    for name, service in compose.get("services", {}).items():
        image = service.get("image") if isinstance(service, dict) else None
        if not image or image.endswith(":latest") or ":" not in image:
            failures.append(f"Container image for {name} is not version pinned")

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for line in dockerfile.splitlines():
        if not line.startswith("FROM "):
            continue
        image = line.split()[1]
        if ":" not in image or image.endswith(":latest"):
            failures.append(f"Dockerfile base image is not version pinned: {image}")

    plugin_manifest = json.loads(
        (ROOT / "openclaw/plugins/threat-radar-boundary/openclaw.plugin.json").read_text(
            encoding="utf-8"
        )
    )
    schema = plugin_manifest.get("configSchema", {})
    if schema.get("additionalProperties") is not False:
        failures.append("OpenClaw boundary plugin config must reject unknown fields")
    if schema.get("properties", {}).get("externalDeliveryEnabled", {}).get("default") is not False:
        failures.append("OpenClaw boundary plugin delivery must default off")

    node = shutil.which("node")
    if node:
        result = subprocess.run(  # noqa: S603
            [node, "--check", str(ROOT / "openclaw/plugins/threat-radar-boundary/index.js")],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            failures.append("OpenClaw boundary plugin syntax: " + result.stderr.strip())


def check_architecture_visual(failures: list[str]) -> None:
    path = ROOT / "docs/architecture-visual.html"
    parser = ArchitectureVisualParser()
    try:
        parser.feed(path.read_text(encoding="utf-8"))
        parser.close()
    except (OSError, ValueError) as exc:
        failures.append(f"Architecture visual could not be parsed: {exc}")
        return
    if parser.section_count != 10 or parser.svg_count != 10:
        failures.append(
            "Architecture visual must contain exactly ten sections and ten SVG diagrams"
        )
    if parser.svg_title_count != parser.svg_count or parser.svg_desc_count != parser.svg_count:
        failures.append("Every architecture SVG must contain one title and one description")
    if parser.duplicate_ids:
        failures.append(
            "Architecture visual contains duplicate IDs: " + ", ".join(sorted(parser.duplicate_ids))
        )
    missing_anchors = sorted(parser.anchor_targets - parser.ids)
    if missing_anchors:
        failures.append(
            "Architecture visual contains broken anchors: " + ", ".join(missing_anchors)
        )
    broken_edges = sorted(
        f"{source or '<missing>'}->{target or '<missing>'}"
        for source, target in parser.edge_targets
        if source not in parser.node_ids or target not in parser.node_ids
    )
    if broken_edges:
        failures.append(
            "Architecture visual contains connectors with missing endpoints: "
            + ", ".join(broken_edges)
        )
    if parser.edge_without_marker:
        failures.append("Every directed architecture connector must have an arrow marker")
    if parser.edge_after_node:
        failures.append("Architecture connectors must be drawn before nodes")
    if parser.forbidden_elements:
        failures.append(
            "Architecture visual contains forbidden elements: "
            + ", ".join(sorted(parser.forbidden_elements))
        )
    if parser.remote_assets:
        failures.append("Architecture visual must not load remote assets")


def check_universal_runtime_visual(failures: list[str]) -> None:
    path = ROOT / "docs/universal-agent-runtime.html"
    parser = ArchitectureVisualParser()
    try:
        text = path.read_text(encoding="utf-8")
        parser.feed(text)
        parser.close()
    except (OSError, ValueError) as exc:
        failures.append(f"Universal runtime visual could not be parsed: {exc}")
        return
    if parser.svg_count != 1:
        failures.append("Universal runtime visual must contain exactly one SVG")
    if parser.svg_title_count != 1 or parser.svg_desc_count != 1:
        failures.append("Universal runtime SVG must contain one title and one description")
    if parser.duplicate_ids:
        failures.append(
            "Universal runtime visual contains duplicate IDs: "
            + ", ".join(sorted(parser.duplicate_ids))
        )
    broken_edges = sorted(
        f"{source or '<missing>'}->{target or '<missing>'}"
        for source, target in parser.edge_targets
        if source not in parser.node_ids or target not in parser.node_ids
    )
    if broken_edges:
        failures.append(
            "Universal runtime visual contains connectors with missing endpoints: "
            + ", ".join(broken_edges)
        )
    if parser.edge_without_marker:
        failures.append("Every universal runtime connector must have an arrow marker")
    if parser.edge_after_node:
        failures.append("Universal runtime connectors must be drawn before nodes")
    if parser.forbidden_elements:
        failures.append(
            "Universal runtime visual contains forbidden elements: "
            + ", ".join(sorted(parser.forbidden_elements))
        )
    if parser.remote_assets:
        failures.append("Universal runtime visual must not load remote assets")
    required_labels = {
        "X researchers",
        "Reddit security",
        "TikTok security",
        "GitHub security",
        "OpenClaw",
        "Codex",
        "Claude",
        "Perplexity",
        "Hard gate",
    }
    missing_labels = sorted(label for label in required_labels if label not in text)
    if missing_labels:
        failures.append(
            "Universal runtime visual omits required labels: " + ", ".join(missing_labels)
        )


def check_motion_architecture(failures: list[str]) -> None:
    path = ROOT / "docs/architecture-motion.html"
    parser = ArchitectureVisualParser()
    try:
        text = path.read_text(encoding="utf-8")
        parser.feed(text)
        parser.close()
    except (OSError, ValueError) as exc:
        failures.append(f"Animated architecture could not be parsed: {exc}")
        return
    if parser.svg_count != 1:
        failures.append("Animated architecture must contain exactly one SVG")
    if parser.svg_title_count != 1 or parser.svg_desc_count != 1:
        failures.append("Animated architecture SVG must contain one title and one description")
    if parser.duplicate_ids:
        failures.append(
            "Animated architecture contains duplicate IDs: "
            + ", ".join(sorted(parser.duplicate_ids))
        )
    if parser.forbidden_elements:
        failures.append(
            "Animated architecture contains forbidden elements: "
            + ", ".join(sorted(parser.forbidden_elements))
        )
    if parser.remote_assets:
        failures.append("Animated architecture must not load remote assets")
    if text.count("<animateMotion") < 8:
        failures.append("Animated architecture must animate the end-to-end runtime path")
    if text.count('class="phase"') != 6:
        failures.append("Animated architecture must explain exactly six runtime phases")
    required_fragments = {
        'id="motion"': "an accessible motion toggle",
        "@media (prefers-reduced-motion: reduce)": "reduced-motion behavior",
        "architecture-visual.html": "a link to the complete architecture",
    }
    for fragment, description in required_fragments.items():
        if fragment not in text:
            failures.append(f"Animated architecture must include {description}")
    if re.search(r"<(?:linearGradient|radialGradient|filter)\b", text, re.IGNORECASE):
        failures.append("Animated architecture must not use SVG gradients or filters")


def main() -> None:
    failures: list[str] = []

    for path in repository_files("*.json"):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            failures.append(f"JSON {path.relative_to(ROOT)}: {exc}")

    yaml_paths = [
        *repository_files("*.yaml"),
        *repository_files("*.yml"),
        *repository_files("*.lobster"),
    ]
    for path in sorted(set(yaml_paths)):
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            failures.append(f"YAML {path.relative_to(ROOT)}: {exc}")

    for path in repository_files("*.py"):
        try:
            py_compile.compile(str(path), doraise=True)
        except Exception as exc:
            failures.append(f"Python {path.relative_to(ROOT)}: {exc}")

    required = [
        "README.md",
        "IMPLEMENTATION_PLAN.md",
        "OPENCLAW_BUILD_PROMPT.md",
        "SECURITY.md",
        "THREAT_MODEL.md",
        "THREAT_MODEL_APPROVAL.md",
        "EVALS.md",
        "docs/SETUP.md",
        "docs/EXTENDING.md",
        "docs/architecture-motion.html",
        "docs/index.html",
        "docs/sample-daily-brief.html",
        "docs/universal-agent-runtime.html",
        "openapi/openapi.yaml",
        "scripts/setup_openclaw_agents.py",
        "openclaw/plugins/threat-radar-boundary/openclaw.plugin.json",
        "openclaw/workflows/frozen-acceptance.lobster",
    ]
    for relative in required:
        if not (ROOT / relative).is_file():
            failures.append(f"Missing required file: {relative}")

    check_release_gates(failures)
    check_contracts(failures)
    check_migrations(failures)
    check_supply_chain(failures)
    check_architecture_visual(failures)
    check_motion_architecture(failures)
    check_universal_runtime_visual(failures)

    if failures:
        raise SystemExit("Validation failed:\n- " + "\n- ".join(failures))
    print("Repository contracts, security gates, and supply-chain validation passed.")


if __name__ == "__main__":
    main()
