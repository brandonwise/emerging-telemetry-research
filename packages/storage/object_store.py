from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from packages.common.canonical import canonical_json_bytes, sha256_hex


class ImmutableObjectError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StoredObject:
    key: str
    content_hash: str
    size: int
    version_id: str | None


class ImmutableObjectStore(Protocol):
    def put(self, content: bytes, metadata: dict[str, str]) -> StoredObject: ...

    def get(self, key: str) -> bytes: ...


class LocalImmutableObjectStore:
    """Filesystem adapter for tests and frozen replay; never use for production raw evidence."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, content: bytes, metadata: dict[str, str]) -> StoredObject:
        content_hash = sha256_hex(content)
        key = f"sha256/{content_hash[:2]}/{content_hash}"
        path = self._path(key)
        metadata_path = path.with_suffix(".metadata.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != content:
                raise ImmutableObjectError(f"content-address collision for {key}")
        else:
            with path.open("xb") as handle:
                handle.write(content)
        normalized_metadata = {
            **metadata,
            "content_hash": content_hash,
            "size": str(len(content)),
        }
        encoded_metadata = canonical_json_bytes(normalized_metadata)
        if metadata_path.exists():
            if metadata_path.read_bytes() != encoded_metadata:
                raise ImmutableObjectError(f"metadata mutation denied for {key}")
        else:
            with metadata_path.open("xb") as handle:
                handle.write(encoded_metadata)
        return StoredObject(key=key, content_hash=content_hash, size=len(content), version_id=None)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def metadata(self, key: str) -> dict[str, str]:
        value = json.loads(self._path(key).with_suffix(".metadata.json").read_text("utf-8"))
        if not isinstance(value, dict) or not all(
            isinstance(item_key, str) and isinstance(item_value, str)
            for item_key, item_value in value.items()
        ):
            raise ImmutableObjectError(f"invalid metadata for {key}")
        return value

    def _path(self, key: str) -> Path:
        candidate = (self.root / key).resolve()
        if not candidate.is_relative_to(self.root):
            raise ImmutableObjectError("object key escaped storage root")
        return candidate


class S3ImmutableObjectStore:
    def __init__(
        self,
        client: Any,
        bucket: str,
        prefix: str = "raw",
        server_side_encryption: str | None = "AES256",
    ) -> None:
        if server_side_encryption not in {None, "AES256"}:
            raise ValueError("unsupported S3 server-side encryption mode")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.server_side_encryption = server_side_encryption

    def put(self, content: bytes, metadata: dict[str, str]) -> StoredObject:
        content_hash = sha256_hex(content)
        key = f"{self.prefix}/sha256/{content_hash[:2]}/{content_hash}"
        try:
            response = self.client.head_object(Bucket=self.bucket, Key=key)
        except self.client.exceptions.ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code not in {"404", "NoSuchKey", "NotFound"}:
                raise
        else:
            existing_hash = response.get("Metadata", {}).get("content_hash")
            if existing_hash != content_hash:
                raise ImmutableObjectError(f"existing object hash mismatch for {key}")
            return StoredObject(
                key=key,
                content_hash=content_hash,
                size=int(response["ContentLength"]),
                version_id=response.get("VersionId"),
            )
        put_options: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": content,
            "ContentType": "application/octet-stream",
            "Metadata": {**metadata, "content_hash": content_hash},
        }
        if self.server_side_encryption is not None:
            put_options["ServerSideEncryption"] = self.server_side_encryption
        response = self.client.put_object(
            **put_options,
        )
        return StoredObject(
            key=key,
            content_hash=content_hash,
            size=len(content),
            version_id=response.get("VersionId"),
        )

    def get(self, key: str) -> bytes:
        response = self.client.get_object(Bucket=self.bucket, Key=key)
        return bytes(response["Body"].read())


def stored_object_dict(value: StoredObject) -> dict[str, Any]:
    return asdict(value)
