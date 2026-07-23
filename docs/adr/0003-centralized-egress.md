# ADR 0003: All source traffic crosses a centralized egress boundary

Status: accepted

## Decision

Collectors submit allowlisted fetch plans to a safe-fetch service. They do not receive a general
browser or direct HTTP tool. The service validates scheme, credentials, DNS answers, redirect
targets, MIME type, response size, and source budget on every hop.

## Why

Application checks alone cannot close DNS time-of-check/time-of-use races. Production also needs a
network policy with no route to internal, metadata, or control-plane networks.

## Consequences

- A new source adds a narrow destination rule, never global egress.
- Browser discovery requires a separately reviewed, isolated egress profile.
- Direct `web_fetch` and broad browser tools are denied to production collectors.
