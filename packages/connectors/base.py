from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


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


class SourceAdapter(Protocol):
    source_id: str
    source_class: str
    trust_tier: int

    async def plan(self, cursor: dict[str, Any] | None) -> list[FetchRequest]: ...
    async def fetch(self, request: FetchRequest) -> RawArtifact: ...
    async def checkpoint(self, artifact: RawArtifact) -> dict[str, Any]: ...
    async def health(self) -> dict[str, Any]: ...
