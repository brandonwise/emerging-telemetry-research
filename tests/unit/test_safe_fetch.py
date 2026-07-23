from collections.abc import Iterator

import httpx
import pytest

from packages.safe_fetch.service import SafeFetchError, SafeFetchRequest, SafeFetchService


class SequenceResolver:
    def __init__(self, answers: dict[str, Iterator[tuple[str, ...]]]) -> None:
        self.answers = answers

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return next(self.answers[hostname])


@pytest.mark.asyncio
async def test_safe_fetch_revalidates_dns_and_limits_headers() -> None:
    resolver = SequenceResolver(
        {"feed.example": iter([("93.184.216.34",), ("93.184.216.34",)])}
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "fixture-credential"
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "ETag": "fixture",
                "Set-Cookie": "secret=value",
            },
            content=b'{"ok":true}',
        )

    service = SafeFetchService(
        resolver=resolver,
        transport=httpx.MockTransport(handler),
    )
    result = await service.fetch(
        SafeFetchRequest(
            source_id="fixture",
            url="https://feed.example/data#ignored",
            allowed_hosts=("feed.example",),
            allowed_content_types=("application/json",),
            headers={"Authorization": "fixture-credential"},
            max_response_bytes=100,
        )
    )
    assert result.canonical_uri == "https://feed.example/data"
    assert result.content == b'{"ok":true}'
    assert "set-cookie" not in result.response_headers
    assert len(result.resolved_addresses) == 2


@pytest.mark.asyncio
async def test_redirect_to_private_address_is_rejected_before_second_request() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"Location": "https://internal.example/secret"})

    resolver = SequenceResolver(
        {
            "feed.example": iter([("93.184.216.34",)]),
            "internal.example": iter([("169.254.169.254",)]),
        }
    )
    service = SafeFetchService(resolver=resolver, transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="not globally routable"):
        await service.fetch(
            SafeFetchRequest(
                source_id="fixture",
                url="https://feed.example/data",
                allowed_hosts=("feed.example", "internal.example"),
                allowed_content_types=("application/json",),
            )
        )
    assert calls == 1


@pytest.mark.asyncio
async def test_response_size_limit_is_enforced() -> None:
    resolver = SequenceResolver({"feed.example": iter([("93.184.216.34",)])})
    service = SafeFetchService(
        resolver=resolver,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "application/json", "Content-Length": "1000"},
                content=b"{}",
                request=request,
            )
        ),
    )
    with pytest.raises(Exception, match="declared response size"):
        await service.fetch(
            SafeFetchRequest(
                source_id="fixture",
                url="https://feed.example/data",
                allowed_hosts=("feed.example",),
                allowed_content_types=("application/json",),
                max_response_bytes=10,
            )
        )


@pytest.mark.asyncio
async def test_nonpositive_rate_limit_is_rejected_before_network_access() -> None:
    service = SafeFetchService(
        resolver=SequenceResolver({"feed.example": iter([("93.184.216.34",)])}),
        transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)),
    )
    with pytest.raises(SafeFetchError, match="rate limit"):
        await service.fetch(
            SafeFetchRequest(
                source_id="fixture",
                url="https://feed.example/data",
                allowed_hosts=("feed.example",),
                allowed_content_types=("application/json",),
                rate_limit_per_minute=0,
            )
        )
