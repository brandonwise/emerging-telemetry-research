from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from packages.common.canonical import canonical_json_bytes, format_timestamp, sha256_hex, stable_id
from packages.contracts.validation import validate_payload
from packages.security_gateway.canonicalize import canonicalize_text
from packages.workflow.graph import plan_graph

MISSION_SCHEMA = "mission.schema.json"
BUILTIN_MISSIONS_ROOT = Path(__file__).resolve().parents[2] / "missions"
ROLE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "specialist": (),
    "impact": (),
    "skeptic": (),
    "citation_verifier": ("specialist", "impact", "skeptic"),
    "coordinator": ("citation_verifier",),
}
ALLOWED_TEMPLATE_FIELDS = {"objective", "keywords", "exclusions"}
TEMPLATE_FIELD_PATTERN = re.compile(r"\{([a-z_]+)\}")
TERM_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9+#._-]{1,79}")
SLUG_PATTERN = re.compile(r"[^a-z0-9]+")
DRAFT_STOP_WORDS = {
    "about",
    "after",
    "against",
    "allow",
    "allows",
    "and",
    "are",
    "carry",
    "data",
    "define",
    "different",
    "emerging",
    "find",
    "for",
    "from",
    "have",
    "into",
    "like",
    "outcome",
    "outcomes",
    "research",
    "scrape",
    "similar",
    "someone",
    "that",
    "their",
    "they",
    "this",
    "through",
    "want",
    "what",
    "with",
    "workflow",
}


@dataclass(frozen=True, slots=True)
class QueryPlan:
    source_id: str
    surface: str
    adapter: str
    query: str
    freshness: str
    maximum_results: int

    def to_contract(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "surface": self.surface,
            "adapter": self.adapter,
            "query": self.query,
            "freshness": self.freshness,
            "maximum_results": self.maximum_results,
        }


@dataclass(frozen=True, slots=True)
class MissionDefinition:
    payload: dict[str, Any]
    source_path: Path | None = None

    @property
    def mission_id(self) -> str:
        return str(self.payload["mission_id"])

    @property
    def name(self) -> str:
        return str(self.payload["name"])

    @property
    def objective(self) -> str:
        return str(self.payload["objective"])

    def to_contract(self) -> dict[str, Any]:
        return copy.deepcopy(self.payload)


@dataclass(frozen=True, slots=True)
class CompiledMission:
    definition: MissionDefinition
    mission_sha256: str
    graph: dict[str, Any]
    queries: tuple[QueryPlan, ...]
    collection_authorized: bool
    manifest: dict[str, Any]

    def to_contract(self) -> dict[str, Any]:
        return copy.deepcopy(self.manifest)


@dataclass(frozen=True, slots=True)
class MissionActivation:
    mission: MissionDefinition
    receipt: dict[str, Any]


def load_mission(path: Path) -> MissionDefinition:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("mission file must contain one object")
    payload = {str(key): item for key, item in value.items()}
    validate_payload(MISSION_SCHEMA, payload)
    _validate_semantics(payload)
    return MissionDefinition(payload=payload, source_path=path.resolve())


def mission_from_payload(payload: dict[str, Any]) -> MissionDefinition:
    value = copy.deepcopy(payload)
    validate_payload(MISSION_SCHEMA, value)
    _validate_semantics(value)
    return MissionDefinition(payload=value)


def compile_mission(mission: MissionDefinition) -> CompiledMission:
    payload = mission.to_contract()
    validate_payload(MISSION_SCHEMA, payload)
    _validate_semantics(payload)
    graph = plan_graph(ROLE_DEPENDENCIES).to_contract()
    governance = _mapping(payload, "governance")
    maximum_queries = int(governance["maximum_queries_per_run"])
    maximum_results = int(governance["maximum_results_per_query"])
    scope = _mapping(payload, "scope")
    objective_words = mission.objective.split()[:24]
    template_values = {
        "objective": " ".join(objective_words),
        "keywords": " ".join(str(item) for item in scope["include_terms"][:12]),
        "exclusions": " ".join(
            f"-{_query_term(str(item))}" for item in scope["exclude_terms"][:10]
        ),
    }
    queries: list[QueryPlan] = []
    for source in _object_list(payload, "sources"):
        if not bool(source["enabled"]):
            continue
        for template in source["query_templates"]:
            query = _expand_query(str(template), template_values)
            queries.append(
                QueryPlan(
                    source_id=str(source["source_id"]),
                    surface=str(source["surface"]),
                    adapter=str(source["adapter"]),
                    query=query,
                    freshness=_freshness_code(str(source["freshness"])),
                    maximum_results=maximum_results,
                )
            )
    if len(queries) > maximum_queries:
        queries = queries[:maximum_queries]
    collection_authorized = str(governance["collection_mode"]) == "active" and all(
        str(source["approval"]["status"]) == "approved"
        and bool(source["approval"].get("approval_id"))
        for source in _object_list(payload, "sources")
        if bool(source["enabled"])
    )
    mission_sha256 = sha256_hex(canonical_json_bytes(payload))
    manifest = {
        "schema_version": "1.0",
        "mission_id": mission.mission_id,
        "mission_name": mission.name,
        "objective": mission.objective,
        "mission_sha256": mission_sha256,
        "collection_authorized": collection_authorized,
        "external_delivery_enabled": False,
        "query_plan": [query.to_contract() for query in queries],
        "graph": graph,
        "roles": copy.deepcopy(_mapping(payload, "workflow")["roles"]),
        "scoring": copy.deepcopy(payload["scoring"]),
        "vocabulary": copy.deepcopy(payload["vocabulary"]),
        "evidence": copy.deepcopy(payload["evidence"]),
        "output": copy.deepcopy(payload["output"]),
    }
    return CompiledMission(
        definition=mission,
        mission_sha256=mission_sha256,
        graph=graph,
        queries=tuple(queries),
        collection_authorized=collection_authorized,
        manifest=manifest,
    )


def draft_mission(
    objective: str,
    *,
    name: str | None = None,
    outcome_noun: str | None = None,
    window_hours: int = 168,
    cadence: str = "daily",
) -> MissionDefinition:
    normalized = canonicalize_text(objective.strip()).text
    if not 12 <= len(normalized) <= 1200:
        raise ValueError("objective must contain 12-1200 characters")
    if not 1 <= window_hours <= 2160:
        raise ValueError("window hours must be between 1 and 2160")
    if cadence not in {"manual", "hourly", "daily", "weekly"}:
        raise ValueError("cadence must be manual, hourly, daily, or weekly")
    keywords = _keywords(normalized)
    noun = _normalize_noun(outcome_noun or _infer_noun(normalized))
    plural = _pluralize(noun)
    mission_name = _mission_name(name, noun, keywords)
    slug = _slugify(mission_name)
    freshness = "day" if window_hours <= 48 else "week" if window_hours <= 336 else "month"
    source_prefix = slug[:38].rstrip("-")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "mission_id": f"ms_{slug}",
        "name": mission_name,
        "objective": normalized,
        "description": f"Researches {plural} that directly support the stated objective.",
        "vocabulary": {
            "singular": noun,
            "plural": plural,
            "collection": f"{noun.title()} research",
            "empty_result": f"No {plural} met the evidence and priority thresholds.",
        },
        "scope": {
            "include_terms": keywords,
            "exclude_terms": [],
            "window_hours": window_hours,
            "languages": ["en"],
            "geographies": [],
        },
        "sources": [
            _draft_source(
                f"{source_prefix}-web",
                "web",
                ["{objective}", "{keywords} emerging {exclusions}"],
                freshness,
            ),
            _draft_source(
                f"{source_prefix}-news",
                "news",
                ["{keywords} announcement change {exclusions}"],
                freshness,
            ),
            _draft_source(
                f"{source_prefix}-github",
                "github",
                ["site:github.com {keywords} {exclusions}"],
                freshness,
            ),
            _draft_source(
                f"{source_prefix}-reddit",
                "reddit",
                ["site:reddit.com {keywords} {exclusions}"],
                freshness,
            ),
        ],
        "evidence": {
            "minimum_independent_sources": 2,
            "require_citations": True,
            "maximum_evidence_age_hours": window_hours,
        },
        "scoring": {
            "dimensions": [
                _dimension("outcome_alignment", "Outcome alignment", 25, "objective_alignment"),
                _dimension("evidence_strength", "Evidence strength", 25, "evidence_strength"),
                _dimension("momentum", "Momentum", 20, "momentum"),
                _dimension("recency", "Recency", 15, "recency"),
                _dimension("actionability", "Actionability", 15, "actionability"),
            ],
            "thresholds": {"urgent": 82, "high": 68, "standard": 45},
        },
        "workflow": {
            "roles": _draft_roles(normalized, noun),
            "maximum_parallel_roles": 3,
        },
        "output": {
            "cadence": cadence,
            "formats": ["json", "html"],
            "maximum_outcomes": 20,
            "delivery": "local_only",
        },
        "governance": {
            "collection_mode": "plan",
            "human_approval_required": True,
            "external_delivery_enabled": False,
            "maximum_queries_per_run": 12,
            "maximum_results_per_query": 20,
        },
        "evaluation": {
            "success_metric": f"useful_{slug}_rate",
            "minimum_useful_outcome_rate": 0.6,
            "minimum_source_diversity": 3,
        },
    }
    return mission_from_payload(payload)


def activate_mission(
    mission: MissionDefinition,
    *,
    approved_by: str,
    approval_id: str,
    approved_at: datetime | None = None,
) -> MissionActivation:
    if len(approved_by.strip()) < 2 or len(approval_id.strip()) < 4:
        raise ValueError("activation requires approved_by and approval_id")
    base = compile_mission(mission)
    payload = mission.to_contract()
    governance = _mapping(payload, "governance")
    governance["collection_mode"] = "active"
    governance["activation"] = {
        "approved_by": approved_by.strip(),
        "approval_id": approval_id.strip(),
        "approved_at": format_timestamp(approved_at or datetime.now(UTC)),
        "base_sha256": base.mission_sha256,
    }
    for source in _object_list(payload, "sources"):
        if bool(source["enabled"]):
            source["approval"] = {"status": "approved", "approval_id": approval_id.strip()}
    governance["activation"]["approved_sha256"] = _approved_payload_sha256(payload)
    activated = mission_from_payload(payload)
    compiled = compile_mission(activated)
    if not compiled.collection_authorized:
        raise ValueError("activated mission did not satisfy collection authorization")
    receipt = {
        "schema_version": "1.0",
        "receipt_id": stable_id("ma", mission.mission_id, compiled.mission_sha256),
        "mission_id": mission.mission_id,
        "approved_by": approved_by.strip(),
        "approval_id": approval_id.strip(),
        "approved_at": governance["activation"]["approved_at"],
        "base_sha256": base.mission_sha256,
        "activated_sha256": compiled.mission_sha256,
        "rollback_mission": mission.to_contract(),
    }
    return MissionActivation(mission=activated, receipt=receipt)


def rollback_mission(receipt: dict[str, Any]) -> MissionDefinition:
    rollback = receipt.get("rollback_mission")
    if not isinstance(rollback, dict):
        raise ValueError("activation receipt has no rollback mission")
    mission = mission_from_payload(rollback)
    expected = receipt.get("base_sha256")
    if not isinstance(expected, str) or compile_mission(mission).mission_sha256 != expected:
        raise ValueError("activation receipt rollback hash does not match")
    return mission


def write_mission(
    mission: MissionDefinition,
    path: Path,
    *,
    force: bool = False,
) -> Path:
    destination = path.resolve()
    if destination.exists() and not force:
        raise ValueError(f"refusing to overwrite {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(mission.to_contract(), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return destination


def write_activation_receipt(receipt: dict[str, Any], path: Path, *, force: bool = False) -> Path:
    destination = path.resolve()
    if destination.exists() and not force:
        raise ValueError(f"refusing to overwrite {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _validate_semantics(payload: dict[str, Any]) -> None:
    sources = _object_list(payload, "sources")
    source_ids = [str(source["source_id"]) for source in sources]
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("mission source IDs must be unique")
    for source in sources:
        for template in source["query_templates"]:
            fields = set(TEMPLATE_FIELD_PATTERN.findall(str(template)))
            if not fields.issubset(ALLOWED_TEMPLATE_FIELDS):
                raise ValueError("query template contains an unsupported field")
    scoring = _mapping(payload, "scoring")
    dimensions = scoring["dimensions"]
    dimension_ids = [str(item["dimension_id"]) for item in dimensions]
    if len(dimension_ids) != len(set(dimension_ids)):
        raise ValueError("mission scoring dimension IDs must be unique")
    weight_total = sum(float(item["weight"]) for item in dimensions)
    if abs(weight_total - 100.0) > 0.001:
        raise ValueError("mission scoring weights must sum to 100")
    thresholds = scoring["thresholds"]
    if not float(thresholds["urgent"]) > float(thresholds["high"]) > float(
        thresholds["standard"]
    ):
        raise ValueError("mission thresholds must descend from urgent to standard")
    roles = _mapping(payload, "workflow")["roles"]
    dependencies = {
        str(role["role_id"]): tuple(str(item) for item in role["depends_on"])
        for role in roles
    }
    if dependencies != ROLE_DEPENDENCIES:
        raise ValueError("mission workflow must preserve the proven five-role review graph")
    plan_graph(dependencies)
    governance = _mapping(payload, "governance")
    if str(governance["collection_mode"]) == "active":
        activation = governance.get("activation")
        if not isinstance(activation, dict):
            raise ValueError("active mission requires an activation approval")
        if activation.get("approved_sha256") != _approved_payload_sha256(payload):
            raise ValueError("active mission does not match its approved content hash")
        for source in sources:
            if bool(source["enabled"]) and (
                str(source["approval"]["status"]) != "approved"
                or not source["approval"].get("approval_id")
            ):
                raise ValueError("active mission has an unapproved source")


def _approved_payload_sha256(payload: dict[str, Any]) -> str:
    sealed = copy.deepcopy(payload)
    governance = _mapping(sealed, "governance")
    activation = governance.get("activation")
    if not isinstance(activation, dict):
        raise ValueError("active mission requires activation metadata")
    activation.pop("approved_sha256", None)
    return sha256_hex(canonical_json_bytes(sealed))


def _draft_source(
    source_id: str,
    surface: str,
    query_templates: list[str],
    freshness: str,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "surface": surface,
        "adapter": "brave_surface_search",
        "enabled": True,
        "query_templates": query_templates,
        "freshness": freshness,
        "approval": {"status": "draft", "approval_id": None},
        "retention_days": 1,
    }


def _dimension(dimension_id: str, label: str, weight: int, feature: str) -> dict[str, Any]:
    return {
        "dimension_id": dimension_id,
        "label": label,
        "weight": weight,
        "feature": feature,
    }


def _draft_roles(objective: str, noun: str) -> list[dict[str, Any]]:
    return [
        {
            "role_id": "specialist",
            "purpose": (
                f"Analyze the domain evidence for each {noun} against this objective: {objective}"
            ),
            "depends_on": [],
        },
        {
            "role_id": "impact",
            "purpose": (
                f"Judge the likely value, reach, and timing of each {noun} without inventing "
                "missing context."
            ),
            "depends_on": [],
        },
        {
            "role_id": "skeptic",
            "purpose": (
                f"Try to disprove each proposed {noun}; flag copied sourcing, stale evidence, "
                "hype, and weak alignment."
            ),
            "depends_on": [],
        },
        {
            "role_id": "citation_verifier",
            "purpose": (
                "Verify every material claim against allowed evidence and reject unsupported "
                "certainty or false source independence."
            ),
            "depends_on": ["specialist", "impact", "skeptic"],
        },
        {
            "role_id": "coordinator",
            "purpose": (
                f"Synthesize the bounded reviews into a concise {noun} recommendation while "
                "leaving ranking and publication authority in code."
            ),
            "depends_on": ["citation_verifier"],
        },
    ]


def _keywords(objective: str) -> list[str]:
    values: list[str] = []
    for match in TERM_PATTERN.findall(objective):
        term = match.lower().strip("._-")
        if len(term) < 3 or term in DRAFT_STOP_WORDS or term in values:
            continue
        values.append(term)
        if len(values) == 12:
            break
    return values or ["change", "signal", "evidence"]


def _infer_noun(objective: str) -> str:
    lower = objective.lower()
    for needle, noun in (
        ("opportunit", "opportunity"),
        ("lead", "lead"),
        ("risk", "risk"),
        ("trend", "trend"),
        ("competitor", "competitive signal"),
        ("customer", "customer signal"),
        ("research", "research finding"),
    ):
        if needle in lower:
            return noun
    return "insight"


def _normalize_noun(value: str) -> str:
    noun = " ".join(value.lower().split())
    if not re.fullmatch(r"[a-z][a-z -]{1,39}", noun):
        raise ValueError("outcome noun must contain 2-40 lowercase letters, spaces, or hyphens")
    return noun


def _pluralize(noun: str) -> str:
    if noun.endswith("y") and not noun.endswith(("ay", "ey", "iy", "oy", "uy")):
        return noun[:-1] + "ies"
    if noun.endswith(("s", "x", "z", "ch", "sh")):
        return noun + "es"
    return noun + "s"


def _mission_name(name: str | None, noun: str, keywords: list[str]) -> str:
    if name is not None:
        value = " ".join(name.split())
        if not 4 <= len(value) <= 100:
            raise ValueError("mission name must contain 4-100 characters")
        return value
    subject = " ".join(keywords[:4]).title()
    return f"{subject} {noun.title()} Research"[:100]


def _slugify(value: str) -> str:
    slug = SLUG_PATTERN.sub("-", value.lower()).strip("-")[:56].rstrip("-")
    if len(slug) < 3:
        slug = "custom-mission"
    return slug


def _expand_query(template: str, values: dict[str, str]) -> str:
    query = template
    for field in ALLOWED_TEMPLATE_FIELDS:
        query = query.replace("{" + field + "}", values[field])
    words = query.split()
    query = " ".join(words[:50]).strip()
    if not query or len(query) > 400:
        raise ValueError("compiled query must contain 1-50 words and at most 400 characters")
    return query


def _query_term(value: str) -> str:
    words = TERM_PATTERN.findall(value)
    return "-".join(words[:6]).lower() or "excluded"


def _freshness_code(value: str) -> str:
    return {"day": "pd", "week": "pw", "month": "pm"}[value]


def _mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload[key]
    if not isinstance(value, dict):
        raise ValueError(f"mission {key} must be an object")
    return value


def _object_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload[key]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"mission {key} must be an array of objects")
    return value
