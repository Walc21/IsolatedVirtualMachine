#!/usr/bin/env python3
"""Live Incus check for persistent /workspace and disposable VM root state."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import tempfile
import time

from isolatevm.incus import IncusError, LocalIncus
from isolatevm.model import INITIAL_SNAPSHOT, Manifest
from isolatevm.storage import remove_instance_manifest, save_instance_manifest
from isolatevm.ui import IsolateWindow
from isolatevm.workspace_volume import volume_name as workspace_volume_name


class SynchronousWindow:
    def __init__(self, service: LocalIncus) -> None:
        self.service = service

    _verify_close_target = IsolateWindow._verify_close_target


def _cached_ubuntu_fingerprint(service: LocalIncus) -> str:
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


def _wait_for_agent(service: LocalIncus, name: str) -> None:
    deadline = time.monotonic() + 180
    while True:
        try:
            service._run("exec", name, "--", "/usr/bin/true", timeout=15)
            break
        except IncusError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Incus guest agent did not become ready") from None
            time.sleep(3)
    while time.monotonic() < deadline:
        status = service.provisioning_status(name)
        if status.status in {"done", "disabled"}:
            return
        if status.status in {"error", "degraded done"}:
            raise RuntimeError(f"cloud-init did not finish cleanly: {status.status}, errors={status.error_count}")
        time.sleep(2)
    raise RuntimeError("cloud-init did not finish within three minutes")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="isolatevm-workspace-smoke-", dir=Path.home()) as temporary:
        os.environ["XDG_DATA_HOME"] = str(Path(temporary) / "xdg")
        name = f"isovm-ws-{os.getpid()}"
        clone_name = f"{name}-copy"
        workspace_contents = f"persistent-workspace-{os.getpid()}"
        clone_contents = f"clone-only-{os.getpid()}"
        manifest = Manifest.parse({
            "schemaVersion": 1, "name": name,
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 12, "pool": "isolatevm"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "maximum-isolation"},
            "lifecycle": {"disposition": "persist-workspace", "workspaceSizeGiB": 4},
        })
        service = LocalIncus()
        service.approve_confined_connection()
        fingerprint = _cached_ubuntu_fingerprint(service)
        service.image_info = lambda _release: {"fingerprint": fingerprint,
                                                "alias": "images:ubuntu/24.04/cloud"}
        original_run = service._run

        def use_cached_image(*args: str, **kwargs: object) -> str:
            if len(args) > 1 and args[0] == "create" and args[1] == "images:ubuntu/24.04/cloud":
                args = (args[0], fingerprint, *args[2:])
            return original_run(*args, **kwargs)

        service._run = use_cached_image
        created = False
        clone_created = False
        saved_manifest = False
        clone_manifest_saved = False
        try:
            try:
                service.create(manifest, print)
            except IncusError as exc:
                print(f"CREATE_TECHNICAL: {exc.technical or exc}")
                raise
            created = True
            save_instance_manifest(manifest)
            saved_manifest = True
            assert service.snapshots(name) == [INITIAL_SNAPSHOT]
            volume = workspace_volume_name(name)
            effective = service.effective(name)
            if effective["mounts"] or len(effective["volumes"]) != 1:
                raise RuntimeError("workspace volume was not separated from host mounts")
            if any("Máximo isolamento diverge" in warning for warning in effective["warnings"]):
                raise RuntimeError("managed /workspace volume was misclassified as external access")

            try:
                service.change_state(name, "start")
            except IncusError as exc:
                print(f"START_TECHNICAL: {exc.technical or exc}")
                raise
            _wait_for_agent(service, name)
            owner = service._run("exec", name, "--", "stat", "-c", "%u:%g:%a", "/workspace").strip()
            print(f"WORKSPACE_OWNER: {owner}")
            service._run("exec", name, "--user", "1000", "--", "sh", "-c",
                          f"printf '%s' '{workspace_contents}' > /workspace/persistent.txt")
            service._run("exec", name, "--", "sh", "-c",
                          "printf 'discard-me' > /root/isolatevm-root-marker")
            service.change_state(name, "stop")
            service.set_resources(name, 1, 2048)
            result = IsolateWindow._apply_close_lifecycle(
                SynchronousWindow(service), [(name, "Stopped", "persist-workspace")])
            if result != ([name], []):
                raise RuntimeError(f"close lifecycle returned {result!r}")
            restored = next(vm for vm in service.list_vms() if vm.name == name)
            if restored.cpu != "2" or restored.status != "Stopped":
                raise RuntimeError(f"VM root state was not restored: CPU={restored.cpu}, state={restored.status}")

            service.change_state(name, "start")
            _wait_for_agent(service, name)
            retained = service._run("exec", name, "--user", "1000", "--", "cat",
                                    "/workspace/persistent.txt").strip()
            if retained != workspace_contents:
                raise RuntimeError("/workspace content did not survive restoring the VM snapshot")
            root_marker = service._run("exec", name, "--", "sh", "-c",
                                       "test ! -e /root/isolatevm-root-marker && echo reset").strip()
            if root_marker != "reset":
                raise RuntimeError("VM root disk did not return to its initial snapshot")
            service.change_state(name, "stop")
            print("LIVE_WORKSPACE_PERSISTED: guest uid 1000 can write and data survives initial VM restore")

            service.clone(name, clone_name)
            clone_created = True
            clone_manifest_data = manifest.to_dict()
            clone_manifest_data["name"] = clone_name
            clone_manifest = Manifest.parse(clone_manifest_data, check_copy_sources=False)
            save_instance_manifest(clone_manifest)
            clone_manifest_saved = True
            if not service.verify_managed_lifecycle(clone_name, "persist-workspace", "isolatevm", 4):
                raise RuntimeError("workspace clone ownership or device markers did not verify")
            assert service.snapshots(clone_name) == [INITIAL_SNAPSHOT]
            service.change_state(clone_name, "start")
            _wait_for_agent(service, clone_name)
            clone_retained = service._run("exec", clone_name, "--user", "1000", "--", "cat",
                                          "/workspace/persistent.txt").strip()
            if clone_retained != workspace_contents:
                raise RuntimeError("workspace clone does not contain the source data")
            service._run("exec", clone_name, "--user", "1000", "--", "sh", "-c",
                          f"printf '%s' '{clone_contents}' > /workspace/clone-only.txt")
            service.change_state(clone_name, "stop")
            service.set_resources(clone_name, 1, 2048)
            clone_restore = IsolateWindow._apply_close_lifecycle(
                SynchronousWindow(service), [(clone_name, "Stopped", "persist-workspace")])
            if clone_restore != ([clone_name], []):
                raise RuntimeError(f"clone close lifecycle returned {clone_restore!r}")
            clone_vm = next(vm for vm in service.list_vms() if vm.name == clone_name)
            if clone_vm.cpu != "2" or clone_vm.status != "Stopped":
                raise RuntimeError("clone VM root state did not return to its own initial snapshot")
            if not service.verify_managed_lifecycle(clone_name, "persist-workspace", "isolatevm", 4):
                raise RuntimeError("clone initial snapshot restore changed its /workspace volume ownership")
            service.change_state(clone_name, "start")
            _wait_for_agent(service, clone_name)
            clone_retained = service._run("exec", clone_name, "--user", "1000", "--", "cat",
                                          "/workspace/clone-only.txt").strip()
            if clone_retained != clone_contents:
                raise RuntimeError("clone's workspace data did not survive restoring its own snapshot")
            service.change_state(clone_name, "stop")
            service.change_state(name, "start")
            _wait_for_agent(service, name)
            source_isolated = service._run("exec", name, "--user", "1000", "--", "sh", "-c",
                                           "test ! -e /workspace/clone-only.txt && echo isolated").strip()
            if source_isolated != "isolated":
                raise RuntimeError("workspace clone writes changed the source volume")
            service.change_state(name, "stop")
            clone_volume = workspace_volume_name(clone_name)
            service.delete(clone_name)
            clone_created = False
            remove_instance_manifest(clone_name)
            clone_manifest_saved = False
            if service._workspace_volume_exists("isolatevm", clone_volume):
                raise RuntimeError("deleting the workspace clone left its custom volume behind")
            print("LIVE_WORKSPACE_CLONE_OK: clone data is independent and deletion removes its volume")

            export_path = Path(temporary) / "workspace-export.tar.gz"
            service.export_workspace(name, export_path)
            if not export_path.is_file() or export_path.stat().st_mode & 0o777 != 0o600 or export_path.stat().st_size == 0:
                raise RuntimeError("workspace export is missing, empty, or not mode 0600")
            print("LIVE_WORKSPACE_EXPORT_OK: separate custom volume exported mode 0600")

            service.delete(name)
            created = False
            if service._workspace_volume_exists("isolatevm", volume):
                raise RuntimeError("explicit VM deletion left its managed /workspace volume behind")
            print("LIVE_WORKSPACE_DELETE_OK: VM and separately managed /workspace volume removed")
        finally:
            if clone_created:
                service.delete(clone_name)
            if clone_manifest_saved:
                remove_instance_manifest(clone_name)
            if created:
                service.delete(name)
            if saved_manifest:
                remove_instance_manifest(name)


if __name__ == "__main__":
    main()
