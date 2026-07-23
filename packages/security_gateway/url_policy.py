"""URL and destination policy helpers for the centralized fetch service."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def validate_url_shape(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("only HTTPS is allowed by the default policy")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("credential-bearing URLs are forbidden")


def validate_resolved_ip(ip_text: str) -> None:
    address = ipaddress.ip_address(ip_text)
    if any(address in network for network in BLOCKED_NETWORKS):
        raise ValueError(f"destination {address} is in a blocked network")
