from __future__ import annotations

import asyncio
import http.client
import socket
import ssl
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urljoin, urlsplit

import httpx

from packages.common.canonical import sha256_hex
from packages.security_gateway.url_policy import (
    canonicalize_url,
    validate_allowed_host,
    validate_resolved_addresses,
)

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-subscription-token",
}


class SafeFetchError(RuntimeError):
    pass


class Resolver(Protocol):
    async def resolve(self, hostname: str) -> tuple[str, ...]: ...


class SystemResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        def lookup() -> tuple[str, ...]:
            records = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
            return tuple(str(item[4][0]) for item in records)

        return await asyncio.to_thread(lookup)


class SourceRateLimiter:
    """Conservative per-source limiter with no burst allowance."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._next_allowed: dict[str, float] = {}

    async def acquire(self, source_id: str, requests_per_minute: int) -> None:
        if requests_per_minute <= 0:
            raise SafeFetchError("rate limit must be positive")
        interval = 60 / requests_per_minute
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait_seconds = max(0.0, self._next_allowed.get(source_id, now) - now)
            if wait_seconds:
                await asyncio.sleep(wait_seconds)
                now = loop.time()
            self._next_allowed[source_id] = now + interval


@dataclass(frozen=True, slots=True)
class SafeFetchRequest:
    source_id: str
    url: str
    allowed_hosts: tuple[str, ...]
    allowed_content_types: tuple[str, ...]
    method: str = "GET"
    body: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)
    max_response_bytes: int = 10_485_760
    max_redirects: int = 3
    timeout_seconds: float = 20
    rate_limit_per_minute: int = 60
    accepted_status_codes: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class SafeFetchResult:
    source_id: str
    requested_url: str
    canonical_uri: str
    final_url: str
    status_code: int
    content_type: str
    content: bytes
    content_hash: str
    response_headers: dict[str, str]
    redirect_chain: tuple[str, ...]
    resolved_addresses: tuple[tuple[str, ...], ...]


class SafeFetchService:
    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        rate_limiter: SourceRateLimiter | None = None,
    ) -> None:
        self.resolver = resolver or SystemResolver()
        self.transport = transport
        self.rate_limiter = rate_limiter or SourceRateLimiter()

    async def fetch(self, request: SafeFetchRequest) -> SafeFetchResult:
        if request.max_response_bytes <= 0:
            raise SafeFetchError("response byte limit must be positive")
        method = request.method.upper()
        if method not in {"GET", "POST"}:
            raise SafeFetchError("only GET and POST requests are allowed")
        if method == "GET" and request.body is not None:
            raise SafeFetchError("GET requests cannot include a body")
        if request.body is not None and len(request.body) > 100_000:
            raise SafeFetchError("request body exceeds policy")
        if any(code < 400 or code > 499 for code in request.accepted_status_codes):
            raise SafeFetchError("accepted non-success statuses must be 4xx responses")
        await self.rate_limiter.acquire(request.source_id, request.rate_limit_per_minute)
        current_url = canonicalize_url(request.url)
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in {"host", "content-length"}
        }
        redirect_chain: list[str] = []
        resolutions: list[tuple[str, ...]] = []
        timeout = httpx.Timeout(request.timeout_seconds)
        for redirect_count in range(request.max_redirects + 1):
            host = validate_allowed_host(current_url, request.allowed_hosts)
            before = validate_resolved_addresses(await self.resolver.resolve(host))
            resolutions.append(before)
            selected_transport = self.transport or _PinnedAsyncTransport(
                host=host,
                addresses=before,
                timeout_seconds=request.timeout_seconds,
                maximum_response_bytes=request.max_response_bytes,
            )
            try:
                async with httpx.AsyncClient(
                    follow_redirects=False,
                    timeout=timeout,
                    transport=selected_transport,
                    trust_env=False,
                    headers={"Accept-Encoding": "identity"},
                ) as client, client.stream(
                    method,
                    current_url,
                    headers=headers,
                    content=request.body,
                ) as response:
                    if response.status_code in REDIRECT_STATUSES:
                        if method != "GET":
                            raise SafeFetchError("redirects are forbidden for POST requests")
                        location = response.headers.get("location")
                        if not location:
                            raise SafeFetchError("redirect response omitted Location")
                        if redirect_count >= request.max_redirects:
                            raise SafeFetchError("redirect limit exceeded")
                        next_url = canonicalize_url(urljoin(current_url, location))
                        next_host = validate_allowed_host(next_url, request.allowed_hosts)
                        if next_host != host:
                            headers = {
                                key: value
                                for key, value in headers.items()
                                if key.lower() not in SENSITIVE_HEADERS
                            }
                        redirect_chain.append(next_url)
                        current_url = next_url
                        continue
                    if not (
                        200 <= response.status_code < 300
                        or response.status_code in request.accepted_status_codes
                    ):
                        raise SafeFetchError(f"upstream returned HTTP {response.status_code}")
                    content_type = (
                        response.headers.get("content-type", "").split(";", 1)[0].lower()
                    )
                    if content_type not in set(request.allowed_content_types):
                        displayed_type = content_type or "<missing>"
                        raise SafeFetchError(
                            f"content type {displayed_type} is forbidden"
                        )
                    declared_length = response.headers.get("content-length")
                    if declared_length and int(declared_length) > request.max_response_bytes:
                        raise SafeFetchError("declared response size exceeds policy")
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > request.max_response_bytes:
                            raise SafeFetchError("response exceeded byte limit")
                    after = validate_resolved_addresses(await self.resolver.resolve(host))
                    resolutions.append(after)
                    return SafeFetchResult(
                        source_id=request.source_id,
                        requested_url=request.url,
                        canonical_uri=canonicalize_url(request.url),
                        final_url=current_url,
                        status_code=response.status_code,
                        content_type=content_type,
                        content=bytes(content),
                        content_hash=sha256_hex(bytes(content)),
                        response_headers=_redacted_headers(response.headers),
                        redirect_chain=tuple(redirect_chain),
                        resolved_addresses=tuple(resolutions),
                    )
            except (httpx.HTTPError, UnicodeError, ValueError) as exc:
                if isinstance(exc, SafeFetchError):
                    raise
                raise SafeFetchError(str(exc)) from exc
        raise SafeFetchError("fetch ended without a response")


class _PinnedAsyncTransport(httpx.AsyncBaseTransport):
    """Connect only to prevalidated IPs while retaining hostname TLS verification and Host."""

    def __init__(
        self,
        *,
        host: str,
        addresses: tuple[str, ...],
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> None:
        self.host = host
        self.addresses = addresses
        self.timeout_seconds = timeout_seconds
        self.maximum_response_bytes = maximum_response_bytes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        status, headers, content = await asyncio.to_thread(
            _pinned_https_request,
            request.method,
            str(request.url),
            list(request.headers.multi_items()),
            body,
            self.host,
            self.addresses,
            self.timeout_seconds,
            self.maximum_response_bytes,
        )
        return httpx.Response(status, headers=headers, content=content, request=request)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, *, timeout: float) -> None:
        context = ssl.create_default_context()
        super().__init__(
            host,
            port=port,
            timeout=timeout,
            context=context,
        )
        self._pinned_address = address
        self._radar_context = context

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
        )
        try:
            self.sock = self._radar_context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def _pinned_https_request(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes,
    host: str,
    addresses: tuple[str, ...],
    timeout_seconds: float,
    maximum_response_bytes: int,
) -> tuple[int, list[tuple[str, str]], bytes]:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != host:
        raise SafeFetchError("pinned transport URL does not match the validated HTTPS host")
    port = parts.port or 443
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    outgoing = {
        key: value
        for key, value in headers
        if key.lower() not in {"host", "content-length", "accept-encoding"}
    }
    outgoing["Accept-Encoding"] = "identity"
    last_error: Exception | None = None
    for address in addresses:
        connection = _PinnedHTTPSConnection(host, address, port, timeout=timeout_seconds)
        try:
            connection.request(method, target, body=body or None, headers=outgoing)
            response = connection.getresponse()
            response_headers = [(str(key), str(value)) for key, value in response.getheaders()]
            content_encoding = response.getheader("Content-Encoding", "identity").lower()
            if content_encoding not in {"", "identity"}:
                raise SafeFetchError("compressed responses are forbidden by pinned transport")
            declared = response.getheader("Content-Length")
            if declared and int(declared) > maximum_response_bytes:
                raise SafeFetchError("declared response size exceeds policy")
            content = response.read(maximum_response_bytes + 1)
            if len(content) > maximum_response_bytes:
                raise SafeFetchError("response exceeded byte limit")
            return response.status, response_headers, content
        except SafeFetchError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise SafeFetchError("all validated upstream addresses failed") from last_error


def _redacted_headers(headers: httpx.Headers) -> dict[str, str]:
    allowed = {
        "cache-control",
        "content-length",
        "content-type",
        "date",
        "etag",
        "last-modified",
    }
    return {
        key.lower(): value
        for key, value in headers.multi_items()
        if key.lower() in allowed
    }


def same_origin(left: str, right: str) -> bool:
    left_parts = urlsplit(left)
    right_parts = urlsplit(right)
    return (
        left_parts.scheme,
        left_parts.hostname,
        left_parts.port or 443,
    ) == (
        right_parts.scheme,
        right_parts.hostname,
        right_parts.port or 443,
    )
