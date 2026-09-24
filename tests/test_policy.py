from pathlib import Path

from isolatevm.model import Manifest
from isolatevm.policy import assess


def test_policy_explains_network_and_host_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    folder = tmp_path / "Documents"; folder.mkdir()
    manifest = Manifest.parse({"schemaVersion": 1, "name": "policy-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
        "network": {"mode": "normal", "bridge": "incusbr0"},
        "mounts": [{"host": str(folder), "guest": "/workspace", "mode": "rw"}],
        "software": {"apt": []}})
    codes = {finding.code for finding in assess(manifest)}
    assert codes == {"NETWORK_UNRESTRICTED", "HOST_WRITE", "BROAD_PERSONAL_FOLDER"}


def test_desktop_without_network_warns_about_install_and_login():
    manifest = Manifest.parse({"schemaVersion": 1, "name": "desktop-vm",
        "os": {"distribution": "ubuntu", "release": "24.04", "desktop": "xfce"},
        "resources": {"cpu": 2, "memoryMiB": 4096, "diskGiB": 30, "pool": "default"},
        "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []}})
    assert {finding.code for finding in assess(manifest)} == {"OFFLINE_PROVISION", "DESKTOP_LOGIN"}


def test_guest_container_engine_has_explicit_warning():
    manifest = Manifest.parse({"schemaVersion": 1, "name": "docker-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 4096, "diskGiB": 30, "pool": "default"},
        "network": {"mode": "offline"}, "mounts": [], "software": {"apt": ["docker.io"]}})
    assert {finding.code for finding in assess(manifest)} == {"OFFLINE_PROVISION", "GUEST_CONTAINER_ENGINE"}
