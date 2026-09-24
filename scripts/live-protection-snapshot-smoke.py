#!/usr/bin/env python3
"""Disposable live check that the opt-in UI policy snapshots before mutation."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import tempfile

from isolatevm.incus import LocalIncus
from isolatevm import change_diff
from isolatevm.model import Manifest
from isolatevm.storage import history, save_auto_snapshot
from isolatevm.ui import IsolateWindow


class SynchronousWindow:
    def __init__(self, service: LocalIncus) -> None:
        self.service = service

    def _work(self, operation, done) -> None:
        operation()

    def _toast(self, _message: str) -> None:
        pass

    def show_dashboard(self) -> None:
        pass


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="isolatevm-snapshot-smoke-", dir=Path.home()) as temporary:
        os.environ["XDG_DATA_HOME"] = str(Path(temporary) / "xdg")
        name = f"isovm-snap-{os.getpid()}"
        manifest = Manifest.parse({
            "schemaVersion": 1, "name": name,
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 12, "pool": "isolatevm"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "maximum-isolation"},
        })
        service = LocalIncus()
        service.approve_confined_connection()
        created = False
        try:
            # The smoke uses a locally cached, verified Ubuntu cloud image so
            # the preview check does not depend on the remote image catalog.
            images = service._json("image", "list", "--format", "json")
            matches = [image for image in images if isinstance(image, dict) and
                       image.get("type") == "virtual-machine" and
                       image.get("architecture") == platform.machine() and
                       image.get("properties", {}).get("variant") == "cloud" and
                       image.get("update_source", {}).get("alias") == "ubuntu/24.04/cloud" and
                       isinstance(image.get("fingerprint"), str)]
            if len(matches) != 1:
                raise RuntimeError("Expected one cached Ubuntu 24.04 cloud VM image")
            service._run("create", matches[0]["fingerprint"], manifest.name, "--vm", "--no-profiles",
                         "-d", "root,type=disk", "-d", "root,path=/",
                         "-d", f"root,pool={manifest.pool}", "-d", f"root,size={manifest.diskGiB}GiB",
                         "-c", f"limits.cpu={manifest.cpu}", "-c", f"limits.memory={manifest.memoryMiB}MiB",
                         "-c", "user.isolatevm.managed=true",
                         "-c", f"user.isolatevm.security-profile={manifest.securityProfile}", timeout=1200)
            created = True
            preview = change_diff.resources(service.effective(name), 1, 2048)
            assert "- CPU: 2; RAM: 2048MiB" in preview.text()
            assert "+ CPU: 1; RAM: 2048MiB" in preview.text()
            save_auto_snapshot(True)
            IsolateWindow._audited(SynchronousWindow(service), "resources", name,
                                   lambda: service.set_resources(name, 1, 2048))
            snapshots = service.snapshots(name)
            assert len(snapshots) == 1 and snapshots[0].startswith("pre-resources-")
            current = next(vm for vm in service.list_vms() if vm.name == name)
            assert current.cpu == "1"
            records = history()
            assert records[0]["action"] == "resources" and records[0]["result"] == "ok"
            assert records[1]["action"] == "snapshot" and records[1]["source"] == "auto"
            print("LIVE_PROTECTION_OK: snapshot precedes resource change and is audited")
        finally:
            if created:
                service.delete(name)


if __name__ == "__main__":
    main()
