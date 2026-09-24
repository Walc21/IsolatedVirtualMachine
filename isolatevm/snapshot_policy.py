"""Names and action allowlist for opt-in protection snapshots."""
from __future__ import annotations

from datetime import datetime, timezone
import secrets


PROTECTED_ACTIONS = frozenset({
    "mount-add", "mount-remove", "usb-add", "usb-remove", "gpu-add", "gpu-remove",
    "network-block", "network-restore", "resources", "snapshot-restore",
})


def protection_name(action: str) -> str:
    if action not in PROTECTED_ACTIONS:
        raise ValueError("Ação sem snapshot de proteção")
    moment = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"pre-{action}-{moment}-{secrets.token_hex(3)}"
