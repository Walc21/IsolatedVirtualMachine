from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import stat

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_helper(name: str, module_name: str):
    path = ROOT / "packaging" / "guest" / name
    loader = SourceFileLoader(module_name, str(path))
    spec = importlib.util.spec_from_loader(module_name, loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_guest_injector_uses_private_volatile_files_and_clears_stale_names(tmp_path):
    helper = load_helper("isolatevm-inject-secrets.py", "guest_secret_injector")
    parent = tmp_path / "run"
    parent.mkdir()
    directory = parent / "isolatevm-secrets"
    user, group = os.getuid(), os.getgid()
    stored, removed = helper.apply_payload({"OPENAI_API_KEY": "synthetic-secret"}, directory,
                                            owner_uid=user, guest_gid=group)
    assert stored == ["OPENAI_API_KEY"] and removed == []
    secret_file = directory / "OPENAI_API_KEY"
    assert secret_file.read_text(encoding="utf-8") == "synthetic-secret"
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o640
    assert secret_file.stat().st_uid == user and secret_file.stat().st_gid == group
    assert stat.S_IMODE(directory.stat().st_mode) == 0o750
    assert json.loads((directory / ".isolatevm-index").read_text()) == ["OPENAI_API_KEY"]

    stored, removed = helper.apply_payload({"GITHUB_TOKEN": "other-synthetic"}, directory,
                                            owner_uid=user, guest_gid=group)
    assert stored == ["GITHUB_TOKEN"] and removed == ["OPENAI_API_KEY"]
    assert not secret_file.exists()
    helper.apply_payload({}, directory, owner_uid=user, guest_gid=group)
    assert not (directory / "GITHUB_TOKEN").exists()


@pytest.mark.parametrize("payload", [
    {"LD_PRELOAD": "value"}, {"PATH": "value"}, {"OPENAI_API_KEY": "has\x00nul"},
    {"lowercase": "value"}, {"OPENAI_API_KEY": ""},
])
def test_guest_injector_rejects_unsafe_values_without_creating_directory(tmp_path, payload):
    helper = load_helper("isolatevm-inject-secrets.py", "guest_secret_injector")
    parent = tmp_path / "run"
    parent.mkdir()
    directory = parent / "isolatevm-secrets"
    with pytest.raises(ValueError):
        helper.apply_payload(payload, directory, owner_uid=os.getuid(), guest_gid=os.getgid())
    assert not directory.exists()


def test_guest_injector_refuses_symlink_runtime_directory(tmp_path):
    helper = load_helper("isolatevm-inject-secrets.py", "guest_secret_injector")
    parent = tmp_path / "run"
    parent.mkdir()
    target = tmp_path / "other"
    target.mkdir()
    directory = parent / "isolatevm-secrets"
    directory.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe runtime directory"):
        helper.apply_payload({"TOKEN": "synthetic"}, directory,
                             owner_uid=os.getuid(), guest_gid=os.getgid())
    assert list(target.iterdir()) == []


def test_guest_runner_reads_only_root_owned_group_readable_regular_files(tmp_path):
    helper = load_helper("isolatevm-run", "guest_secret_runner")
    directory = tmp_path / "isolatevm-secrets"
    directory.mkdir(mode=0o750)
    directory.chmod(0o750)
    secret = directory / "OPENAI_API_KEY"
    secret.write_text("synthetic-secret", encoding="utf-8")
    secret.chmod(0o640)
    assert helper._load_secret(directory, "OPENAI_API_KEY", os.getgid(), os.getuid()) == "synthetic-secret"

    secret.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe secret file"):
        helper._load_secret(directory, "OPENAI_API_KEY", os.getgid(), os.getuid())
    secret.unlink()
    secret.symlink_to(tmp_path / "target")
    with pytest.raises(OSError):
        helper._load_secret(directory, "OPENAI_API_KEY", os.getgid(), os.getuid())


def test_guest_runner_requires_explicit_secret_names_and_command(capsys):
    helper = load_helper("isolatevm-run", "guest_secret_runner")
    assert helper.main([]) == 2
    assert "Uso:" in capsys.readouterr().err
