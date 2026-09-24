from __future__ import annotations

import pytest

from isolatevm.snapshot_policy import PROTECTED_ACTIONS, protection_name
from isolatevm.storage import (history, load_auto_snapshot, load_theme,
                               save_auto_snapshot, save_theme)
from isolatevm.ui import IsolateWindow


class RecordingService:
    def __init__(self, *, fail_snapshot: bool = False) -> None:
        self.events: list[str] = []
        self.fail_snapshot = fail_snapshot

    def snapshot(self, vm: str, name: str) -> None:
        assert vm == "protected-vm"
        assert name.startswith("pre-resources-")
        self.events.append("snapshot")
        if self.fail_snapshot:
            raise RuntimeError("snapshot unavailable")


class WindowHarness:
    def __init__(self, service: RecordingService) -> None:
        self.service = service

    def _work(self, fn, done) -> None:
        fn()

    def show_dashboard(self) -> None:
        pass

    def _toast(self, _message: str) -> None:
        pass


def test_settings_preserve_theme_and_snapshot_preference(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert load_auto_snapshot() is False
    save_theme("dark")
    save_auto_snapshot(True)
    assert load_theme() == "dark" and load_auto_snapshot() is True
    save_theme("light")
    assert load_theme() == "light" and load_auto_snapshot() is True
    save_auto_snapshot(False)
    assert load_auto_snapshot() is False
    assert (tmp_path / "isolatevm/settings.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        protection_name("delete")
    assert "snapshot-restore" in PROTECTED_ACTIONS


def test_protection_snapshot_precedes_change_and_is_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    save_auto_snapshot(True)
    service = RecordingService()
    harness = WindowHarness(service)
    IsolateWindow._audited(harness, "resources", "protected-vm",
                           lambda: service.events.append("change"))
    assert service.events == ["snapshot", "change"]
    records = history()
    assert records[0]["action"] == "resources" and records[0]["result"] == "ok"
    assert records[1]["action"] == "snapshot" and records[1]["source"] == "auto"


def test_snapshot_failure_prevents_change(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    save_auto_snapshot(True)
    service = RecordingService(fail_snapshot=True)
    with pytest.raises(RuntimeError, match="snapshot unavailable"):
        IsolateWindow._audited(WindowHarness(service), "resources", "protected-vm",
                               lambda: service.events.append("change"))
    assert service.events == ["snapshot"]
    records = history()
    assert [(x["action"], x["result"]) for x in records] == [
        ("resources", "erro"), ("snapshot", "erro")]


def test_stale_preview_precheck_prevents_snapshot_and_change(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    save_auto_snapshot(True)
    service = RecordingService()
    def stale() -> None:
        raise ValueError("Configuration changed since preview")
    with pytest.raises(ValueError, match="changed since preview"):
        IsolateWindow._audited(WindowHarness(service), "resources", "protected-vm",
                               lambda: service.events.append("change"), precheck=stale)
    assert service.events == []
    assert [(x["action"], x["result"]) for x in history()] == [("resources", "erro")]
