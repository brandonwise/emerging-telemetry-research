"""URL and destination policy helpers for the centralized fetch service."""

from __future__ import annotations

import ipaddress
from urllib.parse import SplitResult, urlsplit, urlunsplit

BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def validate_url_shape(url: str) -> SplitResult:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("only HTTPS is allowed by the default policy")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("credential-bearing URLs are forbidden")
    if parsed.port not in {None, 443}:
        raise ValueError("non-default HTTPS ports are forbidden")
    if parsed.hostname.rstrip(".").lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("local hostnames are forbidden")
    return parsed


def validate_resolved_ip(ip_text: str) -> None:
    address = ipaddress.ip_address(ip_text)
    if not address.is_global or any(address in network for network in BLOCKED_NETWORKS):
        raise ValueError(f"destination {address} is not globally routable")


def validate_resolved_addresses(addresses: tuple[str, ...]) -> tuple[str, ...]:
    if not addresses:
        raise ValueError("hostname resolved to no addresses")
    normalized = tuple(sorted({str(ipaddress.ip_address(item)) for item in addresses}))
    for item in normalized:
        validate_resolved_ip(item)
    return normalized


def canonicalize_url(url: str) -> str:
    parsed = validate_url_shape(url)
    assert parsed.hostname is not None
    hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    path = parsed.path or "/"
    return urlunsplit(("https", hostname, path, parsed.query, ""))


def validate_allowed_host(url: str, allowed_hosts: tuple[str, ...]) -> str:
    parsed = validate_url_shape(url)
    assert parsed.hostname is not None
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    normalized_allowed = {
        item.rstrip(".").encode("idna").decode("ascii").lower() for item in allowed_hosts
    }
    if host not in normalized_allowed:
        raise ValueError(f"host {host} is not approved for this source")
    return host
