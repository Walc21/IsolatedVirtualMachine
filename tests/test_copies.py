from __future__ import annotations

import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import os
from pathlib import Path
import stat

import pytest

from isolatevm.copy_source import CopySourceError, open_source_file, scan_source
from isolatevm.model import Manifest, Mount, ValidationError
from isolatevm.mock import MockIncus
from isolatevm.storage import load_instance_manifest, save_instance_manifest, save_template


def raw(source: Path, *, kind: str = "directory", destination: str = "/home/ubuntu/imports/sample",
        include_hidden: bool = False) -> dict:
    return {"schemaVersion": 1, "name": "copy-vm",
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "normal-development"},
            "copies": [{"host": str(source), "guest": destination, "kind": kind,
                        "includeHidden": include_hidden}]}


def helper():
    path = Path(__file__).resolve().parents[1] / "packaging/guest/isolatevm-copy-files.py"
    loader = SourceFileLoader("guest_copy_helper", str(path))
    spec = importlib.util.spec_from_loader("guest_copy_helper", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def guest_root(tmp_path: Path) -> Path:
    (tmp_path / "home/ubuntu").mkdir(parents=True)
    return tmp_path


def test_copy_manifest_round_trip_and_saved_source_can_disappear(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    source = tmp_path / "project"
    source.mkdir()
    (source / "note.txt").write_text("synthetic", encoding="utf-8")
    manifest = Manifest.parse(raw(source))
    assert Manifest.from_yaml(manifest.to_yaml()) == manifest
    save_instance_manifest(manifest)
    template = save_template("copy-safe", manifest)
    assert str(source) not in template.read_text()
    (source / "note.txt").unlink()
    source.rmdir()
    assert load_instance_manifest("copy-vm").copies == manifest.copies
    with pytest.raises(ValidationError):
        Manifest.from_yaml(manifest.to_yaml())


def test_copy_source_rejects_hidden_sensitive_symlink_and_overlap(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    source = tmp_path / "project"
    source.mkdir()
    (source / "public.txt").write_text("data")
    (source / ".hidden").write_text("private")
    with pytest.raises(ValidationError, match="ocultos"):
        Manifest.parse(raw(source))
    assert len(Manifest.parse(raw(source, include_hidden=True)).copies) == 1
    sensitive = source / ".ssh"
    sensitive.mkdir()
    with pytest.raises(ValidationError, match="sensível"):
        Manifest.parse(raw(source, include_hidden=True))
    sensitive.rmdir()
    (source / "link").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ValidationError, match="symlink"):
        Manifest.parse(raw(source, include_hidden=True))
    (source / "link").unlink()
    copied = raw(source, include_hidden=True)
    copied["mounts"] = [{"host": str(tmp_path / "elsewhere"),
                         "guest": "/home/ubuntu/imports", "mode": "ro"}]
    (tmp_path / "elsewhere").mkdir()
    with pytest.raises(ValidationError, match="sobrepõe"):
        Manifest.parse(copied)


def test_descriptor_open_rejects_swapped_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    source = tmp_path / "project"
    source.mkdir()
    file = source / "data.txt"
    file.write_text("safe")
    assert scan_source(str(source), "directory", False)[1].path == file
    file.unlink()
    file.symlink_to(tmp_path / "outside")
    with pytest.raises(CopySourceError):
        open_source_file(file)


def test_guest_copy_is_create_only_and_idempotent(tmp_path):
    module = helper()
    root = guest_root(tmp_path)
    uid, gid = os.getuid(), os.getgid()
    data = b"synthetic contents\n"
    digest = hashlib.sha256(data).hexdigest()
    destination = "/home/ubuntu/imports/sample/note.txt"
    module.apply_directory("/home/ubuntu/imports/sample", root=root, uid=uid, gid=gid)
    for _ in range(2):
        module.apply_file(destination, io.BytesIO(data), len(data), digest, 0o600,
                          root=root, uid=uid, gid=gid)
    target = root / destination.lstrip("/")
    assert target.read_bytes() == data
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="different content"):
        module.apply_file(destination, io.BytesIO(b"other"), 5,
                          hashlib.sha256(b"other").hexdigest(), 0o600,
                          root=root, uid=uid, gid=gid)
    assert target.read_bytes() == data
    target.unlink()
    target.symlink_to(root / "outside")
    with pytest.raises(OSError):
        module.apply_file(destination, io.BytesIO(data), len(data), digest, 0o600,
                          root=root, uid=uid, gid=gid)


def test_mock_copy_state_and_mount_overlap(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    source = tmp_path / "project"
    source.mkdir()
    manifest = Manifest.parse(raw(source))
    mock = MockIncus()
    mock.create(manifest)
    assert mock.list_vms()[0].copy_state == "pending"
    with pytest.raises(ValidationError, match="sobrepõe"):
        mock.add_mount("copy-vm", Mount.parse({"host": str(source),
                        "guest": "/home/ubuntu/imports", "mode": "ro"}))
    mock.change_state("copy-vm", "start")
    assert mock.apply_copies("copy-vm") == "simulado"
    assert mock.list_vms()[0].copy_state == "done"
