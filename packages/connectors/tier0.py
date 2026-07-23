from __future__ import annotations

import csv
import json
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from packages.common.canonical import parse_timestamp
from packages.connectors.base import ObservationDraft, safe_source_text

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


class ConnectorParseError(ValueError):
    pass


def parse_tier0(
    source_id: str,
    content: bytes,
    observed_at: datetime,
) -> tuple[ObservationDraft, ...]:
    parsers: dict[str, Callable[[bytes, datetime], tuple[ObservationDraft, ...]]] = {
        "cisa-kev": _parse_cisa_kev,
        "cve-list-v5": _parse_cve_v5,
        "nvd-cve": _parse_nvd,
        "first-epss": _parse_epss,
        "osv": _parse_osv,
        "github-advisories": _parse_github_advisories,
    }
    try:
        parser = parsers[source_id]
    except KeyError as exc:
        raise ConnectorParseError(f"no Tier 0 parser for {source_id}") from exc
    return parser(content, observed_at)


def _json(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorParseError("invalid JSON feed") from exc
    if not isinstance(value, dict):
        raise ConnectorParseError("feed root must be an object")
    return value


def _parse_cisa_kev(content: bytes, observed_at: datetime) -> tuple[ObservationDraft, ...]:
    root = _json(content)
    results: list[ObservationDraft] = []
    for item in _object_list(root.get("vulnerabilities")):
        cve = _cve(item.get("cveID"))
        if not cve:
            continue
        vendor = safe_source_text(item.get("vendorProject"), 200)
        product = safe_source_text(item.get("product"), 200)
        due_date = safe_source_text(item.get("dueDate"), 40)
        claim = f"{cve} appears in CISA's Known Exploited Vulnerabilities catalog."
        if due_date:
            claim += f" The remediation due date is {due_date}."
        affected: tuple[dict[str, str | None], ...] = ()
        if product:
            name = f"{vendor} {product}".strip() if vendor else product
            affected = ({"type": "product", "name": name, "version_range": None},)
        results.append(
            ObservationDraft(
                source_id="cisa-kev",
                source_role="authoritative_advisory",
                observed_at=observed_at,
                published_at=_optional_date(item.get("dateAdded")),
                claims=(claim,),
                identifiers=(cve,),
                affected=affected,
                known_exploited=True,
            )
        )
    return tuple(results)


def _parse_cve_v5(content: bytes, observed_at: datetime) -> tuple[ObservationDraft, ...]:
    root = _json(content)
    containers = root.get("containers")
    metadata = root.get("cveMetadata")
    records = [root] if isinstance(metadata, dict) else _object_list(root.get("records"))
    results: list[ObservationDraft] = []
    for record in records:
        record_metadata = record.get("cveMetadata")
        if not isinstance(record_metadata, dict):
            continue
        cve = _cve(record_metadata.get("cveId"))
        if not cve:
            continue
        state = safe_source_text(record_metadata.get("state"), 40)
        claim = f"{cve} is present in CVE List V5"
        if state:
            claim += f" with state {state.upper()}"
        claim += "."
        results.append(
            ObservationDraft(
                source_id="cve-list-v5",
                source_role="authoritative_advisory",
                observed_at=observed_at,
                published_at=_optional_timestamp(record_metadata.get("datePublished")),
                claims=(claim,),
                identifiers=(cve,),
            )
        )
    if containers is not None and not results:
        raise ConnectorParseError("CVE List record omitted cveMetadata")
    return tuple(results)


def _parse_nvd(content: bytes, observed_at: datetime) -> tuple[ObservationDraft, ...]:
    root = _json(content)
    results: list[ObservationDraft] = []
    for wrapper in _object_list(root.get("vulnerabilities")):
        item = wrapper.get("cve")
        if not isinstance(item, dict):
            continue
        cve = _cve(item.get("id"))
        if not cve:
            continue
        score = _nvd_score(item.get("metrics"))
        claim = f"NVD published a record for {cve}."
        if score is not None:
            claim = f"NVD reports a CVSS base score of {score:g} for {cve}."
        results.append(
            ObservationDraft(
                source_id="nvd-cve",
                source_role="authoritative_advisory",
                observed_at=observed_at,
                published_at=_optional_timestamp(item.get("published")),
                claims=(claim,),
                identifiers=(cve,),
                cvss_base_score=score,
            )
        )
    return tuple(results)


def _parse_epss(content: bytes, observed_at: datetime) -> tuple[ObservationDraft, ...]:
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConnectorParseError("invalid EPSS CSV encoding") from exc
    rows = csv.DictReader(line for line in decoded.splitlines() if not line.startswith("#"))
    results: list[ObservationDraft] = []
    for row in rows:
        cve = _cve(row.get("cve"))
        if not cve:
            continue
        try:
            probability = float(row["epss"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ConnectorParseError("invalid EPSS probability") from exc
        if not 0 <= probability <= 1:
            raise ConnectorParseError("EPSS probability outside [0, 1]")
        results.append(
            ObservationDraft(
                source_id="first-epss",
                source_role="independent_confirmation",
                observed_at=observed_at,
                published_at=None,
                claims=(f"FIRST EPSS assigns {cve} a probability of {probability:.4f}.",),
                identifiers=(cve,),
                epss_probability=probability,
            )
        )
    return tuple(results)


def _parse_osv(content: bytes, observed_at: datetime) -> tuple[ObservationDraft, ...]:
    root = _json(content)
    items = _object_list(root.get("vulns"))
    if not items and "id" in root:
        items = [root]
    results: list[ObservationDraft] = []
    for item in items:
        osv_id = safe_source_text(item.get("id"), 100)
        if not osv_id:
            continue
        identifiers = [osv_id.upper()]
        for alias in _string_list(item.get("aliases")):
            cve = _cve(alias)
            if cve:
                identifiers.append(cve)
        affected: list[dict[str, str | None]] = []
        fixed: list[str] = []
        for affected_item in _object_list(item.get("affected")):
            package = affected_item.get("package")
            if isinstance(package, dict):
                ecosystem = safe_source_text(package.get("ecosystem"), 100)
                name = safe_source_text(package.get("name"), 300)
                if name:
                    package_name = f"{ecosystem}:{name}" if ecosystem else name
                    affected.append(
                        {"type": "package", "name": package_name, "version_range": None}
                    )
            for range_item in _object_list(affected_item.get("ranges")):
                for event in _object_list(range_item.get("events")):
                    value = safe_source_text(event.get("fixed"), 200)
                    if value:
                        fixed.append(value)
        cve_names = [item for item in identifiers if item.startswith("CVE-")]
        target = cve_names[0] if cve_names else identifiers[0]
        results.append(
            ObservationDraft(
                source_id="osv",
                source_role="authoritative_advisory",
                observed_at=observed_at,
                published_at=_optional_timestamp(item.get("published")),
                claims=(f"OSV advisory {identifiers[0]} references {target}.",),
                identifiers=tuple(dict.fromkeys(identifiers)),
                affected=tuple(affected),
                fixed_versions=tuple(dict.fromkeys(fixed)),
            )
        )
    return tuple(results)


def _parse_github_advisories(
    content: bytes,
    observed_at: datetime,
) -> tuple[ObservationDraft, ...]:
    root = _json(content)
    data = root.get("data")
    advisories: list[dict[str, Any]] = []
    if isinstance(data, dict):
        security_advisories = data.get("securityAdvisories")
        if isinstance(security_advisories, dict):
            advisories = _object_list(security_advisories.get("nodes"))
    if not advisories:
        advisories = _object_list(root.get("advisories"))
    results: list[ObservationDraft] = []
    for item in advisories:
        ghsa = safe_source_text(item.get("ghsaId"), 100)
        if not ghsa:
            continue
        identifiers = [ghsa.upper()]
        for identifier in _object_list(item.get("identifiers")):
            value = safe_source_text(identifier.get("value"), 100)
            if value:
                identifiers.append(value.upper())
        cve_names = [value for value in identifiers if CVE_PATTERN.fullmatch(value)]
        target = cve_names[0] if cve_names else ghsa.upper()
        results.append(
            ObservationDraft(
                source_id="github-advisories",
                source_role="authoritative_advisory",
                observed_at=observed_at,
                published_at=_optional_timestamp(item.get("publishedAt")),
                claims=(f"GitHub advisory {ghsa.upper()} references {target}.",),
                identifiers=tuple(dict.fromkeys(identifiers)),
            )
        )
    return tuple(results)


def _object_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _cve(value: object) -> str | None:
    text = safe_source_text(value, 40)
    if not text or not CVE_PATTERN.fullmatch(text):
        return None
    return text.upper()


def _optional_timestamp(value: object) -> datetime | None:
    text = safe_source_text(value, 80)
    return parse_timestamp(text) if text else None


def _optional_date(value: object) -> datetime | None:
    text = safe_source_text(value, 40)
    return parse_timestamp(f"{text}T00:00:00Z") if text else None


def _nvd_score(value: object) -> float | None:
    if not isinstance(value, dict):
        return None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = _object_list(value.get(key))
        for metric in metrics:
            cvss_data = metric.get("cvssData")
            if not isinstance(cvss_data, dict):
                continue
            score = cvss_data.get("baseScore")
            if isinstance(score, (int, float)) and 0 <= float(score) <= 10:
                return float(score)
    return None
