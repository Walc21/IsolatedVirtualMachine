#!/usr/bin/env python3
"""Disposable, synthetic live check of one-time copy in a confined Incus project."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile

from isolatevm.incus import LocalIncus
from isolatevm.model import Manifest
from isolatevm.storage import save_instance_manifest


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="isolatevm-copy-smoke-", dir=Path.home()) as temporary:
        workspace = Path(temporary)
        os.environ["XDG_DATA_HOME"] = str(workspace / "xdg")
        source = workspace / "source"
        source.mkdir()
        data = b"IsolateVM synthetic one-time copy\n"
        (source / "sample.txt").write_bytes(data)
        (source / "empty").mkdir()
        name = f"isovm-copy-{os.getpid()}"
        raw = {"schemaVersion": 1, "name": name,
               "os": {"distribution": "ubuntu", "release": "24.04"},
               "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 12, "pool": "isolatevm"},
               "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
               "security": {"profile": "normal-development"},
               "copies": [{"host": str(source), "guest": "/home/ubuntu/imports/sample",
                           "kind": "directory", "includeHidden": False}]}
        manifest = Manifest.parse(raw)
        service = LocalIncus()
        service.approve_confined_connection()
        created = False
        try:
            service.create(manifest, print)
            created = True
            save_instance_manifest(manifest)
            service.change_state(name, "start")
            receipt = service.apply_copies(name, print)
            guest_file = "/home/ubuntu/imports/sample/sample.txt"
            digest = service._run("exec", name, "--", "/usr/bin/sha256sum", guest_file).split()[0]
            assert digest == hashlib.sha256(data).hexdigest()
            assert receipt == service.apply_copies(name)
            assert next(vm for vm in service.list_vms() if vm.name == name).copy_state == "done"
            (source / "sample.txt").write_bytes(b"host changed afterward\n")
            unchanged = service._run("exec", name, "--", "/usr/bin/sha256sum", guest_file).split()[0]
            assert unchanged == digest
            print("LIVE_COPY_OK: guest digest, idempotent receipt, done state, host independence")
        finally:
            if created:
                service.delete(name)


if __name__ == "__main__":
    main()
