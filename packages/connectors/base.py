from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from packages.common.canonical import stable_id
from packages.security_gateway.canonicalize import canonicalize_text


@dataclass(frozen=True, slots=True)
class FetchRequest:
    source_id: str
    url: str
    headers: dict[str, str]
    cursor: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class RawArtifact:
    source_id: str
    canonical_uri: str
    retrieved_at: datetime
    content_type: str
    content: bytes
    response_headers: dict[str, str]


@dataclass(frozen=True, slots=True)
class ObservationDraft:
    source_id: str
    source_role: str
    observed_at: datetime
    published_at: datetime | None
    claims: tuple[str, ...]
    identifiers: tuple[str, ...]
    affected: tuple[dict[str, str | None], ...] = ()
    cvss_base_score: float | None = None
    epss_probability: float | None = None
    known_exploited: bool = False
    fixed_versions: tuple[str, ...] = ()

    def to_contract(self) -> dict[str, Any]:
        observed = self.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        published = (
            self.published_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
            if self.published_at
            else None
        )
        identity = stable_id(
            "ob",
            self.source_id,
            observed,
            "|".join(self.identifiers),
            "|".join(self.claims),
        )
        return {
            "schema_version": "1.0",
            "observation_id": identity,
            "source_id": self.source_id,
            "observed_at": observed,
            "published_at": published,
            "source_role": self.source_role,
            "claims": list(self.claims),
            "identifiers": list(self.identifiers),
            "affected": list(self.affected),
            "cvss_base_score": self.cvss_base_score,
            "epss_probability": self.epss_probability,
            "known_exploited": self.known_exploited,
            "fixed_versions": list(self.fixed_versions),
        }


class SourceAdapter(Protocol):
    source_id: str
    source_class: str
    trust_tier: int

    async def plan(self, cursor: dict[str, Any] | None) -> list[FetchRequest]: ...
    async def fetch(self, request: FetchRequest) -> RawArtifact: ...
    async def checkpoint(self, artifact: RawArtifact) -> dict[str, Any]: ...
    async def health(self) -> dict[str, Any]: ...


def safe_source_text(value: object, maximum: int = 1200) -> str | None:
    if not isinstance(value, str):
        return None
    result = canonicalize_text(value.strip())
    if result.injection_pattern_count or not result.text:
        return None
    return result.text[:maximum]
