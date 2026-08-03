from __future__ import annotations

import os
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from importlib import metadata
from typing import Any, Protocol
from urllib.parse import urlsplit

from packages.connectors.base import safe_source_text
from packages.discovery.clients import BraveSearchClient, DiscoverySignal
from packages.missions.compiler import QueryPlan
from packages.missions.isolation import (
    parse_feed_items_isolated,
    sanitize_artifact_isolated,
)
from packages.safe_fetch.service import SafeFetchRequest, SafeFetchService
from packages.security_gateway.url_policy import canonicalize_url

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


class WebsitePageCollector:
    def __init__(self, fetch_service: SafeFetchService | None = None) -> None:
        self.fetch_service = fetch_service or SafeFetchService()

    async def collect(self, query: QueryPlan) -> tuple[DiscoverySignal, ...]:
        target_url, host = _target(query)
        fetched = await self.fetch_service.fetch(
            SafeFetchRequest(
                source_id=query.source_id,
                url=target_url,
                allowed_hosts=(host,),
                allowed_content_types=("text/html", "text/plain"),
                max_response_bytes=2_000_000,
                rate_limit_per_minute=12,
            )
        )
        decision = sanitize_artifact_isolated(
            fetched.content,
            fetched.content_type,
            maximum_bytes=2_000_000,
            maximum_excerpt_characters=2_000,
        )
        summary = safe_source_text(decision.bounded_excerpt, 2_000)
        if summary is None:
            return ()
        return (
            DiscoverySignal(
                source_id=query.source_id,
                source_type="website",
                title=f"Approved page on {host}",
                url=fetched.final_url,
                summary=summary,
                published_at=None,
                identifiers=(),
                source_handle=host,
            ),
        )


class RssFeedCollector:
    def __init__(self, fetch_service: SafeFetchService | None = None) -> None:
        self.fetch_service = fetch_service or SafeFetchService()

    async def collect(self, query: QueryPlan) -> tuple[DiscoverySignal, ...]:
        target_url, host = _target(query)
        fetched = await self.fetch_service.fetch(
            SafeFetchRequest(
                source_id=query.source_id,
                url=target_url,
                allowed_hosts=(host,),
                allowed_content_types=(
                    "application/atom+xml",
                    "application/rss+xml",
                    "application/xml",
                    "text/xml",
                ),
                max_response_bytes=2_000_000,
                rate_limit_per_minute=12,
            )
        )
        signals: list[DiscoverySignal] = []
        items = parse_feed_items_isolated(
            fetched.content,
            fetched.content_type,
            maximum_bytes=2_000_000,
            maximum_items=query.maximum_results,
        )
        for item in items:
            try:
                canonical_link = canonicalize_url(item.link)
            except ValueError:
                continue
            if urlsplit(canonical_link).hostname != host:
                continue
            signals.append(
                DiscoverySignal(
                    source_id=query.source_id,
                    source_type="rss",
                    title=item.title,
                    url=canonical_link,
                    summary=item.summary,
                    published_at=_feed_date(item.published),
                    identifiers=(),
                    source_handle=host,
                )
            )
            if len(signals) >= query.maximum_results:
                break
        return tuple(signals)


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
        return cls.with_builtins(client, plugin_allowlist=plugin_allowlist)

    @classmethod
    def with_builtins(
        cls,
        client: BraveSearchClient | None = None,
        *,
        plugin_allowlist: set[str] | None = None,
    ) -> MissionCollectorRegistry:
        registry = cls()
        if client is not None:
            registry.register("brave_surface_search", BraveSurfaceCollector(client))
        registry.register("website_page", WebsitePageCollector())
        registry.register("rss_feed", RssFeedCollector())
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


def _target(query: QueryPlan) -> tuple[str, str]:
    if query.target_url is None:
        raise ValueError(f"{query.adapter} source requires an approved URL")
    target_url = canonicalize_url(query.target_url)
    host = urlsplit(target_url).hostname
    if host is None:
        raise ValueError("approved source URL has no hostname")
    return target_url, host


def _feed_date(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
