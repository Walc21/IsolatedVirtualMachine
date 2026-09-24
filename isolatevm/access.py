"""Select the local Incus socket using the client's documented preference."""
from __future__ import annotations

import os
from pathlib import Path


def local_socket() -> tuple[Path | None, str]:
    # Incus prefers /run/incus when its admin socket exists, then /var/lib/incus.
    directory = Path("/run/incus") if os.path.lexists("/run/incus/unix.socket") else Path("/var/lib/incus")
    admin = directory / "unix.socket"
    user = directory / "unix.socket.user"
    if admin.is_socket() and os.access(admin, os.W_OK):
        return admin, "admin"
    if user.is_socket() and os.access(user, os.W_OK):
        return user, "confined"
    return None, "unavailable"
