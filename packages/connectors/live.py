from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode

from packages.safe_fetch.service import SafeFetchRequest, SafeFetchResult, SafeFetchService

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


@dataclass(frozen=True, slots=True)
class LiveSourceSpec:
    source_id: str
    url: str
    allowed_hosts: tuple[str, ...]
    allowed_content_types: tuple[str, ...]
    processing_content_type: str
    independence_group: str
    rate_limit_per_minute: int
    maximum_bytes: int = 10_485_760
    accepted_status_codes: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class LiveSourceArtifact:
    spec: LiveSourceSpec
    result: SafeFetchResult


class OfficialSourceClient:
    def __init__(self, *, fetch_service: SafeFetchService | None = None) -> None:
        self._fetch_service = fetch_service or SafeFetchService()

    async def fetch(self, spec: LiveSourceSpec) -> LiveSourceArtifact:
        result = await self._fetch_service.fetch(
            SafeFetchRequest(
                source_id=spec.source_id,
                url=spec.url,
                allowed_hosts=spec.allowed_hosts,
                allowed_content_types=spec.allowed_content_types,
                headers={
                    "Accept": (
                        "application/json,text/csv;q=0.9,text/plain;q=0.8,"
                        "application/vnd.github+json;q=0.8"
                    ),
                    "User-Agent": "OpenClaw-Threat-Radar/1.0",
                },
                max_response_bytes=spec.maximum_bytes,
                max_redirects=3,
                timeout_seconds=30,
                rate_limit_per_minute=spec.rate_limit_per_minute,
                accepted_status_codes=spec.accepted_status_codes,
            )
        )
        return LiveSourceArtifact(spec=spec, result=result)


def cisa_kev_spec() -> LiveSourceSpec:
    return LiveSourceSpec(
        source_id="cisa-kev",
        url=CISA_KEV_URL,
        allowed_hosts=("www.cisa.gov",),
        allowed_content_types=("application/json",),
        processing_content_type="application/json",
        independence_group="cisa.gov",
        rate_limit_per_minute=4,
    )


def candidate_source_specs(cve: str) -> tuple[LiveSourceSpec, ...]:
    normalized = _validate_cve(cve)
    year, sequence = normalized.split("-")[1:]
    bucket = f"{int(sequence) // 1000}xxx"
    nvd_query = urlencode({"cveId": normalized})
    epss_query = urlencode({"cve": normalized})
    github_query = urlencode({"cve_id": normalized, "per_page": "20"})
    return (
        LiveSourceSpec(
            source_id="cve-list-v5",
            url=(
                "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"
                f"cves/{year}/{bucket}/{normalized}.json"
            ),
            allowed_hosts=("raw.githubusercontent.com",),
            allowed_content_types=("application/json", "text/plain"),
            processing_content_type="application/json",
            independence_group="cve.org",
            rate_limit_per_minute=4,
        ),
        LiveSourceSpec(
            source_id="nvd-cve",
            url=f"https://services.nvd.nist.gov/rest/json/cves/2.0?{nvd_query}",
            allowed_hosts=("services.nvd.nist.gov",),
            allowed_content_types=("application/json",),
            processing_content_type="application/json",
            independence_group="nist.gov",
            rate_limit_per_minute=5,
        ),
        LiveSourceSpec(
            source_id="first-epss",
            url=f"https://api.first.org/data/v1/epss?{epss_query}",
            allowed_hosts=("api.first.org",),
            allowed_content_types=("application/json",),
            processing_content_type="application/json",
            independence_group="first.org",
            rate_limit_per_minute=4,
        ),
        LiveSourceSpec(
            source_id="osv",
            url=f"https://api.osv.dev/v1/vulns/{normalized}",
            allowed_hosts=("api.osv.dev",),
            allowed_content_types=("application/json",),
            processing_content_type="application/json",
            independence_group="osv.dev",
            rate_limit_per_minute=10,
            accepted_status_codes=(404,),
        ),
        LiveSourceSpec(
            source_id="github-advisories",
            url=f"https://api.github.com/advisories?{github_query}",
            allowed_hosts=("api.github.com",),
            allowed_content_types=(
                "application/json",
                "application/vnd.github+json",
            ),
            processing_content_type="application/json",
            independence_group="github.com",
            rate_limit_per_minute=10,
        ),
    )


def _validate_cve(value: str) -> str:
    normalized = value.upper()
    parts = normalized.split("-")
    if (
        len(parts) != 3
        or parts[0] != "CVE"
        or len(parts[1]) != 4
        or not parts[1].isdigit()
        or len(parts[2]) < 4
        or not parts[2].isdigit()
    ):
        raise ValueError("invalid CVE identifier")
    return normalized
