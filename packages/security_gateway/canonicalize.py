"""Conservative text canonicalization for the quarantine boundary.

Production parsers still run in isolated disposable workers with hard resource limits;
these primitives intentionally emit text only and never preserve executable markup.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import ClassVar
from urllib.parse import unquote

import bleach

ZERO_WIDTH = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
BIDI_CONTROLS = re.compile(r"[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]")
INSTRUCTION_PATTERNS = (
    ("ignore_prior", re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.I)),
    ("role_impersonation", re.compile(r"(system|developer)\s*(message|prompt|instruction)", re.I)),
    (
        "secret_request",
        re.compile(r"(reveal|print|send|exfiltrate)\s+.*(secret|token|api[- ]?key|password)", re.I),
    ),
    (
        "tool_call",
        re.compile(r"(call|invoke|use|execute)\s+.*(tool|function|shell|terminal|command)", re.I),
    ),
    (
        "delayed_instruction",
        re.compile(
            r"(tomorrow|next\s+run|later|on\s+\d{4}-\d{2}-\d{2}).*(execute|send|reveal|remember)",
            re.I,
        ),
    ),
    ("tool_json", re.compile(r'"(?:tool|function|command|arguments)"\s*:', re.I)),
    ("shell_payload", re.compile(r"(?:curl|wget)\s+\S+\s*\|\s*(?:sh|bash)", re.I)),
)


@dataclass(frozen=True, slots=True)
class CanonicalizedText:
    text: str
    removed_zero_width: int
    bidi_control_count: int
    injection_pattern_count: int
    detected_patterns: tuple[str, ...] = ()


def canonicalize_text(value: str) -> CanonicalizedText:
    normalized = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
    zero_width = len(ZERO_WIDTH.findall(normalized))
    bidi = len(BIDI_CONTROLS.findall(normalized))
    normalized = ZERO_WIDTH.sub("", normalized)
    normalized = BIDI_CONTROLS.sub("", normalized)
    detected = tuple(name for name, pattern in INSTRUCTION_PATTERNS if pattern.search(normalized))
    return CanonicalizedText(
        text=normalized,
        removed_zero_width=zero_width,
        bidi_control_count=bidi,
        injection_pattern_count=len(detected),
        detected_patterns=detected,
    )


def sanitize_html(value: str) -> CanonicalizedText:
    # Text-only output by design: source markup is never reused in reports.
    stripped = bleach.clean(value, tags=[], attributes={}, strip=True, strip_comments=True)
    return canonicalize_text(stripped)


def contains_instruction(value: str) -> bool:
    decoded = unquote(value)
    return any(pattern.search(decoded) for _, pattern in INSTRUCTION_PATTERNS)


class VisibleTextHTMLParser(HTMLParser):
    BLOCKED_TAGS: ClassVar[set[str]] = {
        "script",
        "style",
        "iframe",
        "object",
        "embed",
        "form",
        "input",
        "button",
        "svg",
        "template",
        "noscript",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._blocked_depth = 0
        self._hidden_depth = 0
        self._stack: list[tuple[bool, bool]] = []
        self.visible: list[str] = []
        self.hidden_text_count = 0
        self.comment_count = 0
        self.attribute_instruction_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        blocked = lowered in self.BLOCKED_TAGS
        hidden = _attributes_hide(attrs)
        self._stack.append((blocked, hidden))
        if blocked:
            self._blocked_depth += 1
        if hidden:
            self._hidden_depth += 1
        for name, value in attrs:
            if name.lower().startswith("on"):
                self.attribute_instruction_count += 1
            if value and contains_instruction(value):
                self.attribute_instruction_count += 1

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        del tag
        if not self._stack:
            return
        blocked, hidden = self._stack.pop()
        if blocked and self._blocked_depth:
            self._blocked_depth -= 1
        if hidden and self._hidden_depth:
            self._hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._blocked_depth or self._hidden_depth:
            if data.strip():
                self.hidden_text_count += 1
            return
        if data.strip():
            self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        self.comment_count += 1
        if contains_instruction(data):
            self.attribute_instruction_count += 1


def _attributes_hide(attrs: list[tuple[str, str | None]]) -> bool:
    values = {name.lower(): (value or "").lower() for name, value in attrs}
    style = re.sub(r"\s+", "", values.get("style", ""))
    return (
        "hidden" in values
        or values.get("aria-hidden") == "true"
        or "display:none" in style
        or "visibility:hidden" in style
        or "opacity:0" in style
        or "font-size:0" in style
    )
