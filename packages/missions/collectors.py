from __future__ import annotations

import os
from importlib import metadata
from typing import Any, Protocol

from packages.discovery.clients import BraveSearchClient, DiscoverySignal
from packages.missions.compiler import QueryPlan

COLLECTOR_ENTRY_POINT_GROUP = "emerging_telemetry_research.mission_collectors"


class MissionCollector(Protocol):
    async def collect(self, query: QueryPlan) -> tuple[DiscoverySignal, ...]: ...


class BraveSurfaceCollector:
    def __init__(self, client: BraveSearchClient) -> None:
        self.client = client

    async def collect(self, query: QueryPlan) -> tuple[DiscoverySignal, ...]:
        return await self.client.search(
            query.query,
            freshness=query.freshness,
            count=query.maximum_results,
            source_id=query.source_id,
        )


class MissionCollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[str, MissionCollector] = {}

    @classmethod
    def with_brave(
        cls,
        client: BraveSearchClient,
        *,
        plugin_allowlist: set[str] | None = None,
    ) -> MissionCollectorRegistry:
        registry = cls()
        registry.register("brave_surface_search", BraveSurfaceCollector(client))
        registry.load_allowed_plugins(
            plugin_allowlist if plugin_allowlist is not None else configured_plugin_allowlist()
        )
        return registry

    def register(self, adapter_id: str, collector: MissionCollector) -> None:
        if not _valid_adapter_id(adapter_id):
            raise ValueError("collector adapter ID is invalid")
        if adapter_id in self._collectors:
            raise ValueError(f"collector is already registered: {adapter_id}")
        if not callable(getattr(collector, "collect", None)):
            raise ValueError("collector must expose an async collect method")
        self._collectors[adapter_id] = collector

    def require(self, adapter_id: str) -> MissionCollector:
        try:
            return self._collectors[adapter_id]
        except KeyError as exc:
            raise ValueError(f"live runtime has no registered collector for: {adapter_id}") from exc

    def load_allowed_plugins(self, allowlist: set[str]) -> None:
        if not allowlist:
            return
        discovered = {
            entry.name: entry
            for entry in metadata.entry_points(group=COLLECTOR_ENTRY_POINT_GROUP)
        }
        missing = sorted(allowlist - set(discovered))
        if missing:
            raise ValueError(
                "allowlisted collector plugins are not installed: " + ", ".join(missing)
            )
        for adapter_id in sorted(allowlist):
            loaded = discovered[adapter_id].load()
            collector: Any = (
                loaded()
                if isinstance(loaded, type) or not hasattr(loaded, "collect")
                else loaded
            )
            self.register(adapter_id, collector)

    @property
    def adapter_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._collectors))


def configured_plugin_allowlist() -> set[str]:
    raw = os.environ.get("ETR_COLLECTOR_PLUGIN_ALLOWLIST", "")
    values = {item.strip() for item in raw.split(",") if item.strip()}
    invalid = sorted(item for item in values if not _valid_adapter_id(item))
    if invalid:
        raise ValueError("collector plugin allowlist contains invalid IDs: " + ", ".join(invalid))
    return values


def _valid_adapter_id(value: str) -> bool:
    return (
        3 <= len(value) <= 100
        and value[0].isalnum()
        and all(
            character.islower() or character.isdigit() or character in "_.-"
            for character in value
        )
    )
