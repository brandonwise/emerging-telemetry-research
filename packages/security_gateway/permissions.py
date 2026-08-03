from __future__ import annotations

import os
import subprocess
from pathlib import Path


def harden_private_path(path: Path) -> None:
    """Restrict a file or directory to the current user on POSIX and Windows."""
    if not path.exists():
        raise FileNotFoundError(path)
    if os.name != "nt":
        path.chmod(0o700 if path.is_dir() else 0o600)
        return
    system_root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    whoami = system_root / "System32/whoami.exe"
    icacls = system_root / "System32/icacls.exe"
    if not whoami.is_file() or not icacls.is_file():
        raise PermissionError("Windows ACL utilities are unavailable")
    identity = subprocess.run(  # noqa: S603 - trusted Windows system binary.
        [str(whoami)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if not identity:
        raise PermissionError("could not determine the Windows account for ACL hardening")
    result = subprocess.run(  # noqa: S603 - trusted Windows system binary.
        [
            str(icacls),
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{identity}:(F)",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise PermissionError("Windows ACL hardening failed")
