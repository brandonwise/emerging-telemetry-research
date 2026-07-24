import json
from datetime import UTC, datetime

from packages.connectors.live import candidate_source_specs
from packages.connectors.tier0 import parse_tier0


def test_candidate_source_specs_are_fixed_https_allowlists() -> None:
    specs = candidate_source_specs("CVE-2026-12345")
    assert [item.source_id for item in specs] == [
        "cve-list-v5",
        "nvd-cve",
        "first-epss",
        "osv",
        "github-advisories",
    ]
    assert all(item.url.startswith("https://") for item in specs)
    assert "12xxx/CVE-2026-12345.json" in specs[0].url
    assert specs[3].source_id == "osv"
    assert specs[3].accepted_status_codes == (404,)


def test_epss_json_api_response_is_parsed() -> None:
    content = json.dumps(
        {"data": [{"cve": "CVE-2026-12345", "epss": "0.8123"}]}
    ).encode()
    parsed = parse_tier0("first-epss", content, datetime(2026, 7, 24, tzinfo=UTC))
    assert len(parsed) == 1
    assert parsed[0].epss_probability == 0.8123


def test_github_rest_advisory_array_is_parsed() -> None:
    content = json.dumps(
        [
            {
                "ghsa_id": "GHSA-abcd-efgh-ijkl",
                "cve_id": "CVE-2026-12345",
                "published_at": "2026-07-23T12:00:00Z",
            }
        ]
    ).encode()
    parsed = parse_tier0(
        "github-advisories",
        content,
        datetime(2026, 7, 24, tzinfo=UTC),
    )
    assert len(parsed) == 1
    assert parsed[0].identifiers == ("GHSA-ABCD-EFGH-IJKL", "CVE-2026-12345")


def test_nvd_utc_timestamp_without_offset_is_normalized() -> None:
    content = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-12345",
                        "published": "2026-07-23T12:00:00.000",
                    }
                }
            ]
        }
    ).encode()
    parsed = parse_tier0(
        "nvd-cve",
        content,
        datetime(2026, 7, 24, tzinfo=UTC),
    )
    assert parsed[0].published_at == datetime(2026, 7, 23, 12, tzinfo=UTC)
