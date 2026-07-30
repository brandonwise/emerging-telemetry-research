from pathlib import Path
from typing import Any

import pytest

from packages.storage.object_store import (
    ImmutableObjectError,
    LocalImmutableObjectStore,
    S3ImmutableObjectStore,
)


def test_local_store_is_content_addressed_and_immutable(tmp_path: Path) -> None:
    store = LocalImmutableObjectStore(tmp_path)
    first = store.put(b"evidence", {"source_id": "one"})
    second = store.put(b"evidence", {"source_id": "one"})
    third = store.put(b"evidence", {"source_id": "two"})
    assert first == second
    assert first == third
    assert store.get(first.key) == b"evidence"
    assert store.metadata(first.key)["source_id"] == "one"


def test_object_key_cannot_escape_root(tmp_path: Path) -> None:
    store = LocalImmutableObjectStore(tmp_path)
    with pytest.raises(ImmutableObjectError, match="escaped"):
        store.get("../outside")


class _MissingObjectError(Exception):
    def __init__(self) -> None:
        self.response = {"Error": {"Code": "404"}}


class _FakeS3Client:
    class exceptions:
        ClientError = _MissingObjectError

    def __init__(self) -> None:
        self.put_options: dict[str, Any] = {}

    def head_object(self, **_: Any) -> None:
        raise _MissingObjectError

    def put_object(self, **kwargs: Any) -> dict[str, str]:
        self.put_options = kwargs
        return {"VersionId": "version-1"}


def test_s3_store_can_rely_on_encrypted_host_storage_for_local_minio() -> None:
    client = _FakeS3Client()
    store = S3ImmutableObjectStore(
        client,
        "evidence",
        server_side_encryption=None,
    )
    stored = store.put(b"evidence", {"source_id": "cisa-kev"})
    assert stored.version_id == "version-1"
    assert "ServerSideEncryption" not in client.put_options
