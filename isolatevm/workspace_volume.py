"""Names and device settings for IsolateVM-managed persistent workspaces."""
from __future__ import annotations

import hashlib

from .model import _name


WORKSPACE_DEVICE = "isovm-workspace"
WORKSPACE_GUEST_PATH = "/workspace"
WORKSPACE_GUEST_UID = 1000
WORKSPACE_GUEST_GID = 1000
WORKSPACE_GUEST_MODE = "0750"


def volume_name(vm_name: str) -> str:
    _name(vm_name, "VM")
    digest = hashlib.sha256(vm_name.encode("utf-8")).hexdigest()[:24]
    return f"isolatevm-ws-{digest}"
