# ADR 0002: S3-compatible storage holds immutable raw artifacts

Status: accepted

## Decision

Store raw bytes in a versioned S3-compatible bucket. Object keys are SHA-256 content addresses.
Production buckets must enable versioning, retention metadata, encryption, and deny overwrite.

## Why

Raw evidence must survive database repair and support byte-for-byte replay without refetching a
source.

## Consequences

- Database rows reference content hashes and object versions.
- Retention changes never rewrite historical report lineage.
- The local filesystem adapter is test-only and uses exclusive creation.
