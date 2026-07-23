from __future__ import annotations

import re
from dataclasses import dataclass

from packages.common.canonical import stable_id

CVE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.I)
GHSA_PART = r"[23456789CFGHJMPQRVWX]{4}"
GHSA = re.compile(rf"^GHSA-{GHSA_PART}-{GHSA_PART}-{GHSA_PART}$", re.I)
PURL = re.compile(r"^pkg:([a-z0-9.+-]+)/([^@?#]+)", re.I)


@dataclass(frozen=True, slots=True)
class Entity:
    entity_id: str
    type: str
    canonical_name: str
    aliases: tuple[str, ...] = ()

    def to_contract(self) -> dict[str, object]:
        return {
            "entity_id": self.entity_id,
            "type": self.type,
            "canonical_name": self.canonical_name,
            "aliases": list(self.aliases),
        }


def normalize_identifier(value: str) -> Entity:
    stripped = value.strip()
    if match := CVE.fullmatch(stripped):
        canonical = f"CVE-{match.group(1)}-{match.group(2)}".upper()
        return Entity(stable_id("en", "cve", canonical), "cve", canonical)
    if GHSA.fullmatch(stripped):
        canonical = stripped.upper()
        return Entity(stable_id("en", "ghsa", canonical), "ghsa", canonical)
    if match := PURL.match(stripped):
        ecosystem = match.group(1).lower()
        name = match.group(2).lower()
        canonical = f"pkg:{ecosystem}/{name}"
        return Entity(stable_id("en", "package", canonical), "package", canonical)
    upper = stripped.upper()
    if upper.startswith("OSV-"):
        return Entity(stable_id("en", "osv", upper), "osv", upper)
    raise ValueError(f"unsupported identifier: {value}")


def normalize_entities(identifiers: list[str]) -> tuple[Entity, ...]:
    resolved: dict[str, Entity] = {}
    for identifier in identifiers:
        entity = normalize_identifier(identifier)
        resolved[entity.entity_id] = entity
    return tuple(sorted(resolved.values(), key=lambda item: (item.type, item.canonical_name)))
