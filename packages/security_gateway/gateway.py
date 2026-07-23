from __future__ import annotations

import base64
import binascii
import io
import json
import re
import zipfile
from dataclasses import dataclass
from typing import Protocol

from defusedxml import ElementTree

from packages.common.canonical import sha256_hex
from packages.security_gateway.canonicalize import (
    INSTRUCTION_PATTERNS,
    VisibleTextHTMLParser,
    canonicalize_text,
)

ALLOWED_CONTENT_TYPES = {
    "application/atom+xml",
    "application/json",
    "application/rss+xml",
    "application/xml",
    "text/csv",
    "text/html",
    "text/plain",
}
BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")


class ContentGatewayError(RuntimeError):
    pass


class MalwareScanner(Protocol):
    def scan(self, content: bytes) -> str: ...


class NoopMalwareScanner:
    """Development hook. Production policy must replace this with an approved scanner."""

    def scan(self, content: bytes) -> str:
        del content
        return "not_configured"


@dataclass(frozen=True, slots=True)
class GatewayDecision:
    original_hash: str
    sanitized_hash: str
    sanitized_text: str
    bounded_excerpt: str
    content_risk: str
    disposition: str
    model_access: bool
    detected_patterns: tuple[str, ...]
    removed_zero_width: int
    bidi_control_count: int
    hidden_text_count: int
    active_content_count: int
    malware_scan_status: str


class ContentSecurityGateway:
    def __init__(
        self,
        *,
        maximum_bytes: int = 10_485_760,
        maximum_excerpt_characters: int = 12_000,
        malware_scanner: MalwareScanner | None = None,
    ) -> None:
        self.maximum_bytes = maximum_bytes
        self.maximum_excerpt_characters = maximum_excerpt_characters
        self.malware_scanner = malware_scanner or NoopMalwareScanner()

    def process(self, content: bytes, content_type: str) -> GatewayDecision:
        normalized_type = content_type.split(";", 1)[0].strip().lower()
        if normalized_type not in ALLOWED_CONTENT_TYPES:
            raise ContentGatewayError(f"content type {normalized_type or '<missing>'} is forbidden")
        if len(content) > self.maximum_bytes:
            raise ContentGatewayError("artifact exceeds content gateway byte limit")
        malware_status = self.malware_scanner.scan(content)
        if malware_status not in {"clean", "not_configured"}:
            raise ContentGatewayError(f"malware scanner disposition: {malware_status}")
        try:
            decoded = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ContentGatewayError("artifact is not valid UTF-8") from exc

        hidden_count = 0
        active_count = 0
        extra_patterns: list[str] = []
        if normalized_type == "text/html":
            parser = VisibleTextHTMLParser()
            parser.feed(decoded)
            decoded = "\n".join(parser.visible)
            hidden_count = parser.hidden_text_count
            active_count = parser.attribute_instruction_count + parser.comment_count
            if parser.attribute_instruction_count:
                extra_patterns.append("hidden_or_attribute_instruction")
        elif normalized_type == "application/json":
            decoded = _json_text(decoded)
        elif normalized_type in {
            "application/xml",
            "application/rss+xml",
            "application/atom+xml",
        }:
            decoded = _xml_text(content)

        canonical = canonicalize_text(decoded)
        encoded_patterns = _encoded_instruction_patterns(canonical.text)
        patterns = tuple(sorted({*canonical.detected_patterns, *extra_patterns, *encoded_patterns}))
        risk = _risk(
            patterns=patterns,
            hidden_count=hidden_count,
            bidi_count=canonical.bidi_control_count,
            zero_width_count=canonical.removed_zero_width,
        )
        disposition = {
            "low": "allow",
            "medium": "restricted",
            "high": "deterministic_only",
            "critical": "blocked",
        }[risk]
        excerpt = _safe_excerpt(canonical.text, self.maximum_excerpt_characters)
        if risk in {"high", "critical"}:
            excerpt = _remove_instruction_lines(excerpt)
        sanitized_hash = sha256_hex(canonical.text)
        return GatewayDecision(
            original_hash=sha256_hex(content),
            sanitized_hash=sanitized_hash,
            sanitized_text=canonical.text,
            bounded_excerpt=excerpt,
            content_risk=risk,
            disposition=disposition,
            model_access=risk in {"low", "medium"},
            detected_patterns=patterns,
            removed_zero_width=canonical.removed_zero_width,
            bidi_control_count=canonical.bidi_control_count,
            hidden_text_count=hidden_count,
            active_content_count=active_count,
            malware_scan_status=malware_status,
        )


def validate_zip_archive(
    content: bytes,
    *,
    maximum_depth: int = 2,
    maximum_files: int = 100,
    maximum_decompression_ratio: float = 20,
    _depth: int = 0,
) -> tuple[str, ...]:
    if _depth > maximum_depth:
        raise ContentGatewayError("archive nesting depth exceeded")
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise ContentGatewayError("invalid ZIP archive") from exc
    members = archive.infolist()
    if len(members) > maximum_files:
        raise ContentGatewayError("archive member limit exceeded")
    validated: list[str] = []
    for member in members:
        parts = member.filename.replace("\\", "/").split("/")
        if member.filename.startswith(("/", "\\")) or ".." in parts:
            raise ContentGatewayError("archive path traversal detected")
        if member.is_dir():
            continue
        compressed = max(member.compress_size, 1)
        if member.file_size / compressed > maximum_decompression_ratio:
            raise ContentGatewayError("archive decompression ratio exceeded")
        validated.append(member.filename)
        if member.filename.lower().endswith(".zip"):
            nested = archive.read(member, pwd=None)
            validate_zip_archive(
                nested,
                maximum_depth=maximum_depth,
                maximum_files=maximum_files,
                maximum_decompression_ratio=maximum_decompression_ratio,
                _depth=_depth + 1,
            )
    return tuple(validated)


def _json_text(value: str) -> str:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ContentGatewayError("invalid JSON artifact") from exc
    strings: list[str] = []

    def collect(item: object) -> None:
        if isinstance(item, str):
            strings.append(item)
        elif isinstance(item, list):
            for child in item:
                collect(child)
        elif isinstance(item, dict):
            for key in sorted(item):
                collect(item[key])

    collect(parsed)
    return "\n".join(strings)


def _xml_text(value: bytes) -> str:
    try:
        root = ElementTree.fromstring(value)
    except ElementTree.ParseError as exc:
        raise ContentGatewayError("invalid XML artifact") from exc
    return "\n".join(text.strip() for text in root.itertext() if text.strip())


def _encoded_instruction_patterns(value: str) -> tuple[str, ...]:
    found: set[str] = set()
    for candidate in BASE64_CANDIDATE.findall(value):
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if any(pattern.search(decoded) for _, pattern in INSTRUCTION_PATTERNS):
            found.add("base64_instruction")
    return tuple(sorted(found))


def _risk(
    *,
    patterns: tuple[str, ...],
    hidden_count: int,
    bidi_count: int,
    zero_width_count: int,
) -> str:
    severe = {"secret_request", "tool_call", "tool_json", "shell_payload"}
    if severe.intersection(patterns) and (
        "ignore_prior" in patterns or "role_impersonation" in patterns
    ):
        return "critical"
    if patterns or hidden_count or bidi_count:
        return "high"
    if zero_width_count:
        return "medium"
    return "low"


def _safe_excerpt(value: str, maximum: int) -> str:
    collapsed = re.sub(r"[ \t]+", " ", value)
    collapsed = re.sub(r"\n{3,}", "\n\n", collapsed).strip()
    return collapsed[:maximum]


def _remove_instruction_lines(value: str) -> str:
    safe_lines: list[str] = []
    for line in value.splitlines():
        if any(pattern.search(line) for _, pattern in INSTRUCTION_PATTERNS):
            continue
        if _encoded_instruction_patterns(line):
            continue
        safe_lines.append(line)
    return "\n".join(safe_lines)
