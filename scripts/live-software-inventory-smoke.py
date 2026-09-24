#!/usr/bin/env python3
"""Verify APT inventory against a disposable offline Incus VM."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import tempfile
import time

from isolatevm.incus import IncusError, LocalIncus
from isolatevm.model import Manifest
from isolatevm.storage import remove_instance_manifest, save_instance_manifest


def cached_ubuntu_fingerprint(service: LocalIncus) -> str:
    images = service._json("image", "list", "--format", "json")
    matches = [image for image in images if isinstance(image, dict) and
               image.get("type") == "virtual-machine" and
               image.get("architecture") == platform.machine() and
               image.get("properties", {}).get("variant") == "cloud" and
               image.get("update_source", {}).get("alias") == "ubuntu/24.04/cloud" and
               isinstance(image.get("fingerprint"), str)]
    if len(matches) != 1:
        raise RuntimeError("Expected one cached Ubuntu 24.04 cloud VM image")
    return matches[0]["fingerprint"]


def wait_for_agent(service: LocalIncus, name: str) -> None:
    deadline = time.monotonic() + 180
    while True:
        try:
            service._run("exec", name, "--", "/usr/bin/true", timeout=15)
            return
        except IncusError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Incus guest agent did not become ready") from None
            time.sleep(3)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="isolatevm-inventory-smoke-", dir=Path.home()) as temporary:
        os.environ["XDG_DATA_HOME"] = str(Path(temporary) / "xdg")
        name = f"isovm-inventory-{os.getpid()}"
        creation_manifest = Manifest.parse({
            "schemaVersion": 1, "name": name,
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 12, "pool": "isolatevm"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "maximum-isolation"},
        })
        service = LocalIncus()
        service.approve_confined_connection()
        fingerprint = cached_ubuntu_fingerprint(service)
        service.image_info = lambda _release: {"fingerprint": fingerprint,
                                               "alias": "images:ubuntu/24.04/cloud"}
        original_run = service._run

        def use_cached_image(*args: str, **kwargs: object) -> str:
            if len(args) > 1 and args[0] == "create" and args[1] == "images:ubuntu/24.04/cloud":
                args = (args[0], fingerprint, *args[2:])
            return original_run(*args, **kwargs)

        service._run = use_cached_image
        created = False
        manifest_saved = False
        try:
            service.create(creation_manifest, print)
            created = True
            service.change_state(name, "start")
            wait_for_agent(service, name)

            # The VM itself remains offline and unchanged. This temporary local
            # selection asks the inventory to report one base package and one
            # deliberately absent name without running any installer.
            inventory_manifest = Manifest.parse({
                **creation_manifest.to_dict(),
                "software": {"apt": ["python3", "zz-isolatevm-inventory-absent"]},
            })
            save_instance_manifest(inventory_manifest)
            manifest_saved = True
            entries = {entry.package: entry for entry in service.software_inventory(name)}
            assert entries["python3"].status == "installed"
            assert entries["python3"].version
            assert entries["zz-isolatevm-inventory-absent"].status == "missing"
            print("LIVE_INVENTORY_OK: guest APT version observed; absent package distinguished; no install performed")
        finally:
            if created:
                service.delete(name)
            if manifest_saved:
                remove_instance_manifest(name)


if __name__ == "__main__":
    main()
