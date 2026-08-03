from __future__ import annotations

import json
import multiprocessing
import os
import time
from dataclasses import asdict, dataclass
from multiprocessing.connection import Connection
from typing import Any

import psutil
from defusedxml import ElementTree

from packages.common.canonical import canonical_json_bytes
from packages.connectors.base import safe_source_text
from packages.security_gateway.canonicalize import sanitize_html
from packages.security_gateway.gateway import (
    ContentSecurityGateway,
    GatewayDecision,
    TextArtifactMalwareScanner,
)


class IsolatedSourceParserError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class IsolatedFeedItem:
    title: str
    summary: str
    link: str
    published: str | None


def sanitize_artifact_isolated(
    content: bytes,
    content_type: str,
    *,
    maximum_bytes: int = 2_000_000,
    maximum_excerpt_characters: int = 2_000,
) -> GatewayDecision:
    result = _run_isolated(
        "gateway",
        content,
        content_type=content_type,
        maximum_bytes=maximum_bytes,
        maximum_excerpt_characters=maximum_excerpt_characters,
    )
    raw = result.get("decision")
    if not isinstance(raw, dict):
        raise IsolatedSourceParserError("isolated content gateway returned no decision")
    patterns = raw.get("detected_patterns")
    if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
        raise IsolatedSourceParserError("isolated content gateway returned invalid patterns")
    try:
        return GatewayDecision(
            original_hash=_required_string(raw, "original_hash", maximum=64),
            sanitized_hash=_required_string(raw, "sanitized_hash", maximum=64),
            sanitized_text=_required_string(raw, "sanitized_text", maximum=maximum_bytes),
            bounded_excerpt=_required_string(
                raw,
                "bounded_excerpt",
                maximum=maximum_excerpt_characters,
            ),
            content_risk=_required_string(raw, "content_risk", maximum=20),
            disposition=_required_string(raw, "disposition", maximum=30),
            model_access=_required_bool(raw, "model_access"),
            detected_patterns=tuple(patterns),
            removed_zero_width=_required_count(raw, "removed_zero_width"),
            bidi_control_count=_required_count(raw, "bidi_control_count"),
            hidden_text_count=_required_count(raw, "hidden_text_count"),
            active_content_count=_required_count(raw, "active_content_count"),
            malware_scan_status=_required_string(raw, "malware_scan_status", maximum=40),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise IsolatedSourceParserError(
            "isolated content gateway returned an invalid decision"
        ) from exc


def parse_feed_items_isolated(
    content: bytes,
    content_type: str,
    *,
    maximum_bytes: int = 2_000_000,
    maximum_items: int = 100,
) -> tuple[IsolatedFeedItem, ...]:
    if not 1 <= maximum_items <= 1_000:
        raise ValueError("feed item limit must be between one and 1,000")
    result = _run_isolated(
        "feed",
        content,
        content_type=content_type,
        maximum_bytes=maximum_bytes,
        maximum_excerpt_characters=2_000,
        maximum_items=maximum_items,
    )
    raw_items = result.get("items")
    if not isinstance(raw_items, list) or len(raw_items) > maximum_items:
        raise IsolatedSourceParserError("isolated feed parser returned an invalid item list")
    parsed: list[IsolatedFeedItem] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise IsolatedSourceParserError("isolated feed parser returned a non-object item")
        published = raw.get("published")
        if published is not None and not isinstance(published, str):
            raise IsolatedSourceParserError("isolated feed parser returned an invalid date")
        parsed.append(
            IsolatedFeedItem(
                title=_required_string(raw, "title", maximum=240),
                summary=_required_string(raw, "summary", maximum=2_000),
                link=_required_string(raw, "link", maximum=2_048),
                published=published,
            )
        )
    return tuple(parsed)


def _run_isolated(
    operation: str,
    content: bytes,
    *,
    content_type: str,
    maximum_bytes: int,
    maximum_excerpt_characters: int,
    maximum_items: int = 0,
    timeout_seconds: float = 15,
    maximum_output_bytes: int = 8_388_608,
    maximum_memory_bytes: int = 536_870_912,
) -> dict[str, Any]:
    if not 0 < timeout_seconds <= 120:
        raise ValueError("parser timeout must be between zero and 120 seconds")
    if not 1_024 <= maximum_bytes <= 10_485_760 or len(content) > maximum_bytes:
        raise ValueError("source artifact exceeds parser byte policy")
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker,
        args=(
            sender,
            operation,
            content,
            content_type,
            maximum_bytes,
            maximum_excerpt_characters,
            maximum_items,
            maximum_memory_bytes,
        ),
        daemon=True,
    )
    process.start()
    sender.close()
    try:
        deadline = time.monotonic() + timeout_seconds
        while not receiver.poll(0.05):
            if time.monotonic() >= deadline:
                process.terminate()
                process.join(timeout=2)
                raise IsolatedSourceParserError("isolated source parser timed out")
            if process.pid is None:
                raise IsolatedSourceParserError("isolated source parser did not start")
            try:
                child = psutil.Process(process.pid)
                if child.memory_info().rss > maximum_memory_bytes:
                    process.terminate()
                    process.join(timeout=2)
                    raise IsolatedSourceParserError(
                        "isolated source parser exceeded memory policy"
                    )
                cpu = child.cpu_times()
                if cpu.user + cpu.system > 10:
                    process.terminate()
                    process.join(timeout=2)
                    raise IsolatedSourceParserError("isolated source parser exceeded CPU policy")
            except psutil.NoSuchProcess:
                if not receiver.poll(0.1):
                    raise IsolatedSourceParserError(
                        "isolated source parser exited without output"
                    ) from None
        try:
            encoded = receiver.recv_bytes(maxlength=maximum_output_bytes)
        except OSError as exc:
            raise IsolatedSourceParserError(
                "isolated source parser output exceeded policy"
            ) from exc
    finally:
        receiver.close()
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
    try:
        result = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IsolatedSourceParserError("isolated source parser returned invalid output") from exc
    if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
        raise IsolatedSourceParserError("isolated source parser returned an invalid envelope")
    if result["ok"] is not True:
        raise IsolatedSourceParserError(str(result.get("error", "source parser failed"))[:300])
    return result


def _worker(
    sender: Connection,
    operation: str,
    content: bytes,
    content_type: str,
    maximum_bytes: int,
    maximum_excerpt_characters: int,
    maximum_items: int,
    maximum_memory_bytes: int,
) -> None:
    try:
        _apply_resource_limits(maximum_memory_bytes)
        os.environ.clear()
        gateway = ContentSecurityGateway(
            maximum_bytes=maximum_bytes,
            maximum_excerpt_characters=maximum_excerpt_characters,
            malware_scanner=TextArtifactMalwareScanner(),
        )
        decision = gateway.process(content, content_type)
        if operation == "gateway":
            payload: dict[str, Any] = {"ok": True, "decision": asdict(decision)}
        elif operation == "feed":
            payload = {
                "ok": True,
                "items": _parse_feed_items(content, maximum_items),
            }
        else:
            raise ValueError("unsupported source parser operation")
        sender.send_bytes(canonical_json_bytes(payload))
    except Exception as exc:
        sender.send_bytes(
            canonical_json_bytes(
                {
                    "ok": False,
                    "error": f"isolated source parser failed: {type(exc).__name__}",
                }
            )
        )
    finally:
        sender.close()


def _parse_feed_items(content: bytes, maximum_items: int) -> list[dict[str, str | None]]:
    root = ElementTree.fromstring(content)
    items: list[dict[str, str | None]] = []
    for item in root.iter():
        if _local_name(str(item.tag)) not in {"item", "entry"}:
            continue
        title = safe_source_text(_child_text(item, "title"), 240)
        summary_html = _child_text(item, "description", "summary", "content")
        summary = safe_source_text(sanitize_html(summary_html or "").text, 2_000)
        link = _feed_link(item)
        if title is None or summary is None or link is None:
            continue
        items.append(
            {
                "title": title,
                "summary": summary,
                "link": link[:2_048],
                "published": _child_text(item, "pubdate", "published", "updated"),
            }
        )
        if len(items) >= maximum_items:
            break
    return items


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _child_text(item: Any, *names: str) -> str | None:
    allowed = set(names)
    for child in item:
        if _local_name(str(child.tag)) in allowed and child.text:
            return str(child.text)
    return None


def _feed_link(item: Any) -> str | None:
    for child in item:
        if _local_name(str(child.tag)) != "link":
            continue
        href = child.attrib.get("href")
        if href:
            return str(href)
        if child.text:
            return str(child.text)
    return None


def _required_string(value: dict[str, Any], key: str, *, maximum: int) -> str:
    item = value[key]
    if not isinstance(item, str) or len(item) > maximum:
        raise ValueError(f"invalid {key}")
    return item


def _required_bool(value: dict[str, Any], key: str) -> bool:
    item = value[key]
    if not isinstance(item, bool):
        raise ValueError(f"invalid {key}")
    return item


def _required_count(value: dict[str, Any], key: str) -> int:
    item = value[key]
    if not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 10_000_000:
        raise ValueError(f"invalid {key}")
    return item


def _apply_resource_limits(maximum_memory_bytes: int) -> None:
    if os.name == "nt":
        return
    try:
        import resource

        setrlimit = getattr(resource, "setrlimit", None)
        cpu_limit = getattr(resource, "RLIMIT_CPU", None)
        address_space_limit = getattr(resource, "RLIMIT_AS", None)
        if not callable(setrlimit) or cpu_limit is None or address_space_limit is None:
            return
        setrlimit(cpu_limit, (10, 10))
        setrlimit(address_space_limit, (maximum_memory_bytes, maximum_memory_bytes))
    except (ImportError, OSError, ValueError):
        return
