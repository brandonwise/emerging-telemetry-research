from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from packages.connectors.isolation import (
    IsolatedParserError,
    parse_tier0_contracts_isolated,
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
