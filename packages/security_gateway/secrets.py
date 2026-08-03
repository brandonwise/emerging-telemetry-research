from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

SECRET_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
KEYRING_SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SecretResolutionError(ValueError):
    """Raised when a secret reference is missing, ambiguous, or unsupported."""


class KeyringBackend(Protocol):
    def get_password(self, service_name: str, username: str) -> str | None: ...

    def set_password(self, service_name: str, username: str, password: str) -> None: ...


@dataclass(frozen=True, slots=True)
class SecretStatus:
    name: str
    configured: bool
    source: str
    error: str | None = None


def resolve_secret(
    name: str,
    *,
    required: bool = True,
    environ: Mapping[str, str] | None = None,
    keyring_backend: KeyringBackend | None = None,
) -> str | None:
    """Resolve a secret without logging or returning its reference metadata."""
    _validate_name(name)
    values = environ if environ is not None else os.environ
    direct = values.get(name, "").strip()
    reference = values.get(f"{name}_REF", "").strip()
    if direct and reference:
        raise SecretResolutionError(f"{name} and {name}_REF cannot both be configured")
    if direct:
        return direct
    if reference:
        value = _resolve_reference(
            name,
            reference,
            values,
            keyring_backend=keyring_backend,
        )
        if value:
            return value
        raise SecretResolutionError(f"secret reference for {name} returned no value")
    if required:
        raise SecretResolutionError(f"{name} or {name}_REF is required")
    return None


def inspect_secret(
    name: str,
    *,
    environ: Mapping[str, str] | None = None,
    keyring_backend: KeyringBackend | None = None,
) -> SecretStatus:
    values = environ if environ is not None else os.environ
    direct = bool(values.get(name, "").strip())
    reference = values.get(f"{name}_REF", "").strip()
    source = "direct-environment" if direct else "reference" if reference else "missing"
    try:
        configured = resolve_secret(
            name,
            required=False,
            environ=values,
            keyring_backend=keyring_backend,
        ) is not None
    except SecretResolutionError as exc:
        return SecretStatus(name, False, source, str(exc))
    return SecretStatus(name, configured, source)


def store_keyring_secret(
    name: str,
    value: str,
    *,
    service: str = "emerging-telemetry-research",
    keyring_backend: KeyringBackend | None = None,
) -> None:
    _validate_name(name)
    if not KEYRING_SERVICE.fullmatch(service):
        raise SecretResolutionError("keyring service name is invalid")
    if not value or "\x00" in value or len(value) > 65_536:
        raise SecretResolutionError("secret value is empty or too large")
    backend = keyring_backend or _system_keyring()
    try:
        backend.set_password(service, name, value)
    except Exception as exc:
        raise SecretResolutionError(
            "OS credential store rejected the secret; configure a supported keyring backend "
            "or use an env:// reference"
        ) from exc


def keyring_reference(name: str, *, service: str = "emerging-telemetry-research") -> str:
    """Build a credential locator exclusively from validated non-sensitive metadata."""
    _validate_name(name)
    if not KEYRING_SERVICE.fullmatch(service):
        raise SecretResolutionError("keyring service name is invalid")
    return f"keyring://{service}/{name}"


def _resolve_reference(
    name: str,
    reference: str,
    environ: Mapping[str, str],
    *,
    keyring_backend: KeyringBackend | None,
) -> str | None:
    parsed = urlsplit(reference)
    if parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port:
        raise SecretResolutionError(f"{name}_REF contains unsupported URL components")
    if parsed.scheme == "env":
        target = f"{parsed.netloc}{parsed.path}".lstrip("/")
        _validate_name(target)
        if target in {name, f"{name}_REF"}:
            raise SecretResolutionError(f"{name}_REF cannot reference itself")
        value = environ.get(target, "").strip()
        if not value:
            raise SecretResolutionError(f"environment secret {target} is not configured")
        return value
    if parsed.scheme == "keyring":
        service = unquote(parsed.netloc)
        account = unquote(parsed.path.lstrip("/"))
        if not KEYRING_SERVICE.fullmatch(service) or not SECRET_NAME.fullmatch(account):
            raise SecretResolutionError(f"{name}_REF keyring service or account is invalid")
        backend = keyring_backend or _system_keyring()
        try:
            return backend.get_password(service, account)
        except Exception as exc:
            raise SecretResolutionError(
                f"OS credential store could not resolve {name}"
            ) from exc
    if parsed.scheme == "file":
        if parsed.netloc not in {"", "localhost"}:
            raise SecretResolutionError(f"{name}_REF file host must be empty or localhost")
        path = Path(url2pathname(unquote(parsed.path)))
        return _read_secret_file(name, path)
    raise SecretResolutionError(f"{name}_REF must use env://, keyring://, or file://")


def _read_secret_file(name: str, path: Path) -> str:
    if not path.is_absolute():
        raise SecretResolutionError(f"{name}_REF secret file path must be absolute")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SecretResolutionError(f"secret file for {name} could not be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SecretResolutionError(f"secret file for {name} must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > 65_536:
            raise SecretResolutionError(f"secret file for {name} is empty or too large")
        if os.name != "nt":
            if metadata.st_mode & 0o077:
                raise SecretResolutionError(f"secret file for {name} must be owner-only")
            getuid = getattr(os, "getuid", None)
            if getuid is None or metadata.st_uid != getuid():
                raise SecretResolutionError(f"secret file for {name} has an unexpected owner")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(65_537)
    finally:
        os.close(descriptor)
    if len(raw) > 65_536 or b"\x00" in raw:
        raise SecretResolutionError(f"secret file for {name} is invalid")
    try:
        value = raw.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise SecretResolutionError(f"secret file for {name} must contain UTF-8 text") from exc
    if not value:
        raise SecretResolutionError(f"secret file for {name} returned no value")
    return value


def _system_keyring() -> KeyringBackend:
    try:
        import keyring
    except ImportError as exc:
        raise SecretResolutionError("keyring support is not installed") from exc
    return keyring


def _validate_name(name: str) -> None:
    if not SECRET_NAME.fullmatch(name):
        raise SecretResolutionError("secret name must be an uppercase environment variable")
