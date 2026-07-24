from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]
import psycopg
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from packages.storage.object_store import S3ImmutableObjectStore
from packages.storage.repository import PostgresRepository


@dataclass(frozen=True, slots=True)
class ProductionStoreSettings:
    database_url: str
    s3_endpoint_url: str
    s3_access_key_id: str
    s3_secret_access_key: str
    s3_bucket: str
    s3_region: str = "us-east-1"
    server_side_encryption: str | None = "AES256"
    object_retention_days: int = 30


@dataclass(frozen=True, slots=True)
class ProductionStores:
    repository: PostgresRepository
    object_store: S3ImmutableObjectStore


def initialize_production_stores(
    settings: ProductionStoreSettings,
    *,
    migrations_root: Path,
) -> ProductionStores:
    _apply_migrations(settings.database_url, migrations_root)
    client = boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=settings.s3_secret_access_key,
        region_name=settings.s3_region,
        config=Config(
            signature_version="s3v4",
            connect_timeout=5,
            read_timeout=20,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )
    _ensure_bucket(
        client,
        settings.s3_bucket,
        retention_days=settings.object_retention_days,
    )
    return ProductionStores(
        repository=PostgresRepository(settings.database_url),
        object_store=S3ImmutableObjectStore(
            client,
            settings.s3_bucket,
            server_side_encryption=settings.server_side_encryption,
        ),
    )


def _apply_migrations(database_url: str, migrations_root: Path) -> None:
    if not database_url:
        raise ValueError("database URL is required")
    migration_paths = sorted(migrations_root.glob("*.sql"))
    if not migration_paths:
        raise ValueError("no database migrations were found")
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS radar_schema_migrations (
              migration_name text PRIMARY KEY,
              content_hash text NOT NULL,
              applied_at timestamptz NOT NULL DEFAULT now()
            )
            """
        )
        for path in migration_paths:
            content = path.read_text(encoding="utf-8")
            digest = __import__("hashlib").sha256(content.encode("utf-8")).hexdigest()
            existing = connection.execute(
                """
                SELECT content_hash
                FROM radar_schema_migrations
                WHERE migration_name = %s
                """,
                (path.name,),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != digest:
                    raise RuntimeError(f"applied migration changed: {path.name}")
                continue
            connection.execute(content)
            connection.execute(
                """
                INSERT INTO radar_schema_migrations (migration_name, content_hash)
                VALUES (%s, %s)
                """,
                (path.name, digest),
            )


def _ensure_bucket(client: Any, bucket: str, *, retention_days: int) -> None:
    if not bucket:
        raise ValueError("S3 bucket is required")
    if retention_days <= 0:
        raise ValueError("object retention must be positive")
    try:
        client.head_bucket(Bucket=bucket)
    except ClientError as exc:
        status = int(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if status not in {404} and code not in {"404", "NoSuchBucket", "NotFound"}:
            raise
        client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    client.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    client.put_object_lock_configuration(
        Bucket=bucket,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {
                "DefaultRetention": {
                    "Mode": "GOVERNANCE",
                    "Days": retention_days,
                }
            },
        },
    )
