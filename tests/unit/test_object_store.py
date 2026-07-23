from pathlib import Path

import pytest

from packages.storage.object_store import ImmutableObjectError, LocalImmutableObjectStore


def test_local_store_is_content_addressed_and_immutable(tmp_path: Path) -> None:
    store = LocalImmutableObjectStore(tmp_path)
    first = store.put(b"evidence", {"source_id": "one"})
    second = store.put(b"evidence", {"source_id": "one"})
    assert first == second
    assert store.get(first.key) == b"evidence"
    with pytest.raises(ImmutableObjectError, match="metadata mutation"):
        store.put(b"evidence", {"source_id": "two"})


def test_object_key_cannot_escape_root(tmp_path: Path) -> None:
    store = LocalImmutableObjectStore(tmp_path)
    with pytest.raises(ImmutableObjectError, match="escaped"):
        store.get("../outside")
