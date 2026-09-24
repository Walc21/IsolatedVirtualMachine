#!/usr/bin/env python3
"""Live Incus check for create-time initial snapshot and close-time restore."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import tempfile

from isolatevm.incus import LocalIncus
from isolatevm.model import INITIAL_SNAPSHOT, Manifest
from isolatevm.storage import remove_instance_manifest, save_instance_manifest
from isolatevm.ui import IsolateWindow


class SynchronousWindow:
    def __init__(self, service: LocalIncus) -> None:
        self.service = service

    _verify_close_target = IsolateWindow._verify_close_target


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="isolatevm-lifecycle-smoke-", dir=Path.home()) as temporary:
        os.environ["XDG_DATA_HOME"] = str(Path(temporary) / "xdg")
        name = f"isovm-life-{os.getpid()}"
        manifest = Manifest.parse({
            "schemaVersion": 1, "name": name,
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 12, "pool": "isolatevm"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "maximum-isolation"},
            "lifecycle": {"disposition": "restore-initial-on-close"},
        })
        service = LocalIncus()
        service.approve_confined_connection()
        images = service._json("image", "list", "--format", "json")
        matches = [image for image in images if isinstance(image, dict) and
                   image.get("type") == "virtual-machine" and
                   image.get("architecture") == platform.machine() and
                   image.get("properties", {}).get("variant") == "cloud" and
                   image.get("update_source", {}).get("alias") == "ubuntu/24.04/cloud" and
                   isinstance(image.get("fingerprint"), str)]
        if len(matches) != 1:
            raise RuntimeError("Expected one cached Ubuntu 24.04 cloud VM image")
        fingerprint = matches[0]["fingerprint"]
        # Use the verified local cache for this check, avoiding the remote image catalog.
        service.image_info = lambda _release: {"fingerprint": fingerprint,
                                                "alias": "images:ubuntu/24.04/cloud"}
        run = service._run
        def run_cached(*args: str, **kwargs: object) -> str:
            if len(args) > 1 and args[0] == "create" and args[1] == "images:ubuntu/24.04/cloud":
                args = (args[0], fingerprint, *args[2:])
            return run(*args, **kwargs)
        service._run = run_cached
        created = False
        saved_manifest = False
        try:
            service.create(manifest, print)
            created = True
            save_instance_manifest(manifest)
            saved_manifest = True
            assert service.snapshots(name) == [INITIAL_SNAPSHOT]
            service.set_resources(name, 1, 2048)
            result = IsolateWindow._apply_close_lifecycle(
                SynchronousWindow(service), [(name, "Stopped", "restore-initial-on-close")])
            if result != ([name], []):
                raise RuntimeError(f"close lifecycle returned {result!r}")
            vm = next(item for item in service.list_vms() if item.name == name)
            assert vm.cpu == "2" and vm.status == "Stopped"
            assert INITIAL_SNAPSHOT in service.snapshots(name)
            print("LIVE_LIFECYCLE_OK: initial snapshot restored and VM retained stopped")
        finally:
            if created:
                service.delete(name)
            if saved_manifest:
                remove_instance_manifest(name)


if __name__ == "__main__":
    main()
