from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from packages.connectors.isolation import (
    IsolatedParserError,
    parse_tier0_contracts_isolated,
)
from packages.missions.isolation import (
    IsolatedSourceParserError,
    parse_feed_items_isolated,
    sanitize_artifact_isolated,
)


def test_tier0_parser_runs_in_disposable_process() -> None:
    content = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-12345",
                    "vendorProject": "Example",
                    "product": "Gateway",
                    "dateAdded": "2026-08-03",
                    "dueDate": "2026-08-24",
                }
            ]
        }
    ).encode()

    observations = parse_tier0_contracts_isolated(
        "cisa-kev",
        content,
        datetime(2026, 8, 3, 12, tzinfo=UTC),
    )

    assert observations[0]["identifiers"] == ["CVE-2026-12345"]
    assert observations[0]["known_exploited"] is True


def test_isolated_parser_returns_bounded_error() -> None:
    with pytest.raises(IsolatedParserError, match="isolated parser failed"):
        parse_tier0_contracts_isolated(
            "cisa-kev",
            b"not-json",
            datetime(2026, 8, 3, 12, tzinfo=UTC),
        )


def test_untrusted_page_and_feed_parsers_run_in_disposable_processes() -> None:
    decision = sanitize_artifact_isolated(
        b"<html><script>blocked()</script><body>Approved research text.</body></html>",
        "text/html",
    )
    assert decision.bounded_excerpt == "Approved research text."
    assert decision.hidden_text_count == 1

    feed = b"""<rss><channel><item><title>Release</title>
    <link>https://research.example.com/release</link>
    <description>New telemetry is available.</description></item></channel></rss>"""
    items = parse_feed_items_isolated(feed, "application/rss+xml", maximum_items=5)
    assert items[0].title == "Release"
    assert items[0].summary == "New telemetry is available."


def test_isolated_source_parser_returns_bounded_error() -> None:
    with pytest.raises(IsolatedSourceParserError, match="isolated source parser failed"):
        parse_feed_items_isolated(b"<rss>", "application/rss+xml")
