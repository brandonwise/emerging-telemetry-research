"""Small, conservative canonicalization primitives.

This is starter code, not a complete document-security implementation.
Production parsers must run in isolated disposable workers with hard resource limits.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

import bleach

ZERO_WIDTH = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
BIDI_CONTROLS = re.compile(r"[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]")
INSTRUCTION_PATTERNS = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.I),
    re.compile(r"system\s*(message|prompt)", re.I),
    re.compile(r"(reveal|print|send)\s+.*(secret|token|api[- ]?key|password)", re.I),
    re.compile(r"(call|invoke|use)\s+.*(tool|function|shell|terminal)", re.I),
    re.compile(r"(tomorrow|next\s+run|on\s+\d{4}-\d{2}-\d{2}).*(execute|send|reveal)", re.I),
)


@dataclass(frozen=True, slots=True)
class CanonicalizedText:
    text: str
    removed_zero_width: int
    bidi_control_count: int
    injection_pattern_count: int


def canonicalize_text(value: str) -> CanonicalizedText:
    normalized = unicodedata.normalize("NFC", value).replace("\r\n", "\n").replace("\r", "\n")
    zero_width = len(ZERO_WIDTH.findall(normalized))
    bidi = len(BIDI_CONTROLS.findall(normalized))
    normalized = ZERO_WIDTH.sub("", normalized)
    normalized = BIDI_CONTROLS.sub("", normalized)
    pattern_count = sum(1 for pattern in INSTRUCTION_PATTERNS if pattern.search(normalized))
    return CanonicalizedText(
        text=normalized,
        removed_zero_width=zero_width,
        bidi_control_count=bidi,
        injection_pattern_count=pattern_count,
    )


def sanitize_html(value: str) -> CanonicalizedText:
    # Text-only output by design: source markup is never reused in reports.
    stripped = bleach.clean(value, tags=[], attributes={}, strip=True, strip_comments=True)
    return canonicalize_text(stripped)
