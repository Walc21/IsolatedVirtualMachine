"""Opt-in GTK flow test; requires an active graphical session."""
import os
import subprocess
import sys

import pytest


def _has_vte_391() -> bool:
    try:
        import gi
        gi.require_version("Vte", "3.91")
        from gi.repository import Vte
    except (ImportError, ValueError):
        return False
    return Vte is not None


@pytest.mark.skipif(os.environ.get("ISOLATEVM_UI_TEST") != "1" or
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="ative ISOLATEVM_UI_TEST=1 em sessão gráfica")
def test_existing_vm_change_preview_can_be_cancelled(tmp_path):
    script = '''
import os
import traceback
from gi.repository import GLib, Gtk
from isolatevm import change_diff as diff
from isolatevm.model import Manifest
from isolatevm.storage import history, load_instance_manifest, save_instance_manifest
from isolatevm.workspace_volume import volume_name as workspace_volume_name
from isolatevm.ui import IsolateApp

app = IsolateApp()
def poll_until(predicate, callback, description, timeout_ms=5000):
    deadline = GLib.get_monotonic_time() + timeout_ms * 1000
    def poll():
        try:
            result = predicate()
            if result is not None:
                callback(result)
                return False
            if GLib.get_monotonic_time() >= deadline:
                raise AssertionError(f"Timed out waiting for {description}")
        except BaseException:
            traceback.print_exc(); os._exit(2)
        return True
    GLib.timeout_add(25, poll)

def review_dialog():
    dialogs = [item for item in Gtk.Window.list_toplevels()
               if isinstance(item, Gtk.Dialog) and item.get_title().startswith("Revisar alteração")]
    assert len(dialogs) <= 1
    return dialogs[0] if dialogs else None

def begin():
    if app.get_active_window() is None:
        return True
    try:
        window = app.get_active_window()
        manifest = Manifest.parse({"schemaVersion": 1, "name": "preview-vm",
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "maximum-isolation"}})
        window.service.create(manifest)
        window._review_change("preview-vm", "resources",
                              lambda current: diff.resources(current, 4, 4096),
                              lambda: window.service.set_resources("preview-vm", 4, 4096))
        poll_until(review_dialog, inspect, "initial review dialog")
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False

def inspect(dialog):
    try:
        window = app.get_active_window()
        assert dialog.get_widget_for_response(Gtk.ResponseType.OK).get_label() == "Aplicar alterações"
        labels = []
        def collect(widget):
            if isinstance(widget, Gtk.TextView):
                buffer = widget.get_buffer()
                labels.append(buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False))
            child = widget.get_first_child()
            while child is not None:
                collect(child); child = child.get_next_sibling()
        collect(dialog)
        assert "- CPU: 2; RAM: 2048MiB" in " ".join(labels)
        assert "+ CPU: 4; RAM: 4096MiB" in " ".join(labels)
        dialog.response(Gtk.ResponseType.CANCEL)
        assert window.service.list_vms()[0].cpu == "2"
        window._review_change("preview-vm", "resources",
                              lambda current: diff.resources(current, 4, 4096),
                              lambda: window.service.set_resources("preview-vm", 4, 4096))
        poll_until(review_dialog, inspect_stale, "second review dialog")
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False

def inspect_stale(dialog):
    try:
        window = app.get_active_window()
        window.service.set_resources("preview-vm", 3, 2048)
        dialog.response(Gtk.ResponseType.OK)
        poll_until(stale_error_dialog, finish, "stale-preview error dialog")
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False

def stale_error_dialog():
    dialogs = [item for item in Gtk.Window.list_toplevels()
               if isinstance(item, Gtk.MessageDialog) and
               "mudou desde a prévia" in str(item.get_property("text"))]
    assert len(dialogs) <= 1
    return dialogs[0] if dialogs else None

def finish(dialog):
    try:
        window = app.get_active_window()
        assert window.service.list_vms()[0].cpu == "3"
        dialog.response(Gtk.ResponseType.OK)
        window.close(); app.quit()
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False

GLib.timeout_add(25, begin)
app.run([])
'''
    env = {**os.environ, "ISOLATEVM_MOCK": "1", "XDG_DATA_HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-c", script], check=True, timeout=20, env=env)


@pytest.mark.skipif(os.environ.get("ISOLATEVM_UI_TEST") != "1" or
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="ative ISOLATEVM_UI_TEST=1 em sessão gráfica")
def test_disposable_close_requires_confirmation_and_deletes_only_after_apply(tmp_path):
    script = '''
import os
import traceback
from gi.repository import GLib, Gtk
from isolatevm.incus import LocalIncus
from isolatevm.model import Manifest
from isolatevm.storage import history, load_instance_manifest, save_instance_manifest
from isolatevm.workspace_volume import volume_name as workspace_volume_name
from isolatevm.ui import IsolateApp

app = IsolateApp()
def begin():
    try:
        window = app.get_active_window()
        manifest = Manifest.parse({"schemaVersion": 1, "name": "disposable-vm",
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "maximum-isolation"},
            "lifecycle": {"disposition": "delete-on-close"}})
        restore_manifest = Manifest.parse({"schemaVersion": 1, "name": "restore-vm",
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "maximum-isolation"},
            "lifecycle": {"disposition": "restore-initial-on-close"}})
        workspace_manifest = Manifest.parse({"schemaVersion": 1, "name": "workspace-vm",
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": []},
            "security": {"profile": "maximum-isolation"},
            "lifecycle": {"disposition": "persist-workspace", "workspaceSizeGiB": 8}})
        window.service.create(manifest)
        window.service.create(restore_manifest)
        window.service.create(workspace_manifest)
        save_instance_manifest(manifest)
        save_instance_manifest(restore_manifest)
        save_instance_manifest(workspace_manifest)
        mock = window.service
        mock.workspace_volumes[workspace_volume_name("workspace-vm")]["files"]["kept.txt"] = "persistent-data"
        service = LocalIncus.__new__(LocalIncus)
        service.access_mode = "admin"
        service._confined_approved = True
        service.list_vms = mock.list_vms
        service.effective = mock.effective
        service.verify_managed_lifecycle = mock.verify_managed_lifecycle
        service.delete = mock.delete
        service.snapshots = mock.snapshots
        service.restore_snapshot = mock.restore_snapshot
        service.change_state = mock.change_state
        window.service = service
        window.mock = False
        assert window._close_requested() is True
        GLib.timeout_add(350, cancel_first)
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False

def close_dialog():
    dialogs = [item for item in Gtk.Window.list_toplevels()
               if isinstance(item, Gtk.MessageDialog) and
               "ação de ciclo de vida" in item.get_property("text")]
    assert len(dialogs) == 1
    return dialogs[0]

def cancel_first():
    try:
        window = app.get_active_window()
        dialog = close_dialog()
        assert dialog.get_widget_for_response(Gtk.ResponseType.APPLY).get_label() == "Aplicar e fechar"
        dialog.response(Gtk.ResponseType.CANCEL)
        assert len(window.service.list_vms()) == 3
        assert window._close_requested() is True
        GLib.timeout_add(350, confirm_delete)
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False

def confirm_delete():
    try:
        dialog = close_dialog()
        dialog.response(Gtk.ResponseType.APPLY)
        GLib.timeout_add(350, finish)
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False

def finish():
    try:
        window = app.get_active_window()
        remaining = window.service.list_vms()
        assert [vm.name for vm in remaining] == ["restore-vm", "workspace-vm"]
        assert "isolatevm-initial" in window.service.snapshots("restore-vm")
        assert "isolatevm-initial" in window.service.snapshots("workspace-vm")
        assert window.service.verify_managed_lifecycle("workspace-vm", "persist-workspace", "default", 8)
        assert workspace_volume_name("workspace-vm") in mock.workspace_volumes
        assert mock.workspace_volumes[workspace_volume_name("workspace-vm")]["files"]["kept.txt"] == "persistent-data"
        try:
            load_instance_manifest("disposable-vm")
            raise AssertionError("local disposable manifest was not removed")
        except ValueError:
            pass
        assert load_instance_manifest("restore-vm").lifecycleDisposition == "restore-initial-on-close"
        assert load_instance_manifest("workspace-vm").lifecycleDisposition == "persist-workspace"
        assert any(event["source"] == "auto-close" and event["vm"] == "disposable-vm"
                   for event in history())
        assert any(event["action"] == "snapshot-restore" and event["vm"] == "restore-vm"
                   for event in history())
        window.close(); app.quit()
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False

GLib.timeout_add(300, begin)
app.run([])
'''
    env = {**os.environ, "ISOLATEVM_MOCK": "1", "XDG_DATA_HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-c", script], check=True, timeout=12, env=env)


@pytest.mark.skipif(os.environ.get("ISOLATEVM_UI_TEST") != "1" or
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="ative ISOLATEVM_UI_TEST=1 em sessão gráfica")
def test_wizard_dashboard_and_permissions(tmp_path):
    script = '''
import os
import traceback
from gi.repository import GLib, Gtk
from isolatevm.metrics import MetricsSnapshot
from isolatevm.storage import save_instance_manifest
from isolatevm.ui import IsolateApp
app = IsolateApp()
def flow():
    window = app.get_active_window()
    window.stack.set_visible_child_name("wizard")
    window.catalog_checks["curl"].set_active(True)
    for package in ("@openai/codex@0.154.0", "@anthropic-ai/claude-code@2.1.276",
                    "aider-chat==0.86.2", "opencode-ai@1.18.31"):
        window.ai_coding_checks[package].set_active(True)
    for _ in range(11): window._next()
    assert window.current_manifest is not None
    assert window.current_manifest.securityProfile == "maximum-isolation"
    assert window.current_manifest.desktop is None
    assert "curl" in window.current_manifest.apt
    assert set(window.current_manifest.npm) == {
        "@openai/codex@0.154.0", "@anthropic-ai/claude-code@2.1.276", "opencode-ai@1.18.31"}
    assert window.current_manifest.pipx == ("aider-chat==0.86.2",)
    window._next()
    assert window.wizard_step == 12
    assert window.next_btn.get_label() == "Criar ambiente"
    window.service.create(window.current_manifest)
    save_instance_manifest(window.current_manifest)
    window.service.change_state(window.current_manifest.name, "start")
    card_box = Gtk.Box()
    window._vm_card(window.service.list_vms()[0], card_box,
                    (MetricsSnapshot(0, 1024**3, 4*1024**3, 2*1024**3,
                                     30*1024**3, 0, 0, 3660), 25.0), True)
    card_text = []
    def collect_card(widget):
        if isinstance(widget, Gtk.Label): card_text.append(widget.get_text())
        child = widget.get_first_child()
        while child is not None:
            collect_card(child)
            child = child.get_next_sibling()
    collect_card(card_box)
    assert any("Perfil: maximum-isolation" in text for text in card_text)
    assert any("Sem NIC Incus" in text for text in card_text)
    assert any("CPU 25.0%" in text and "uptime 1 h 1 min" in text for text in card_text)
    window.show_dashboard()
    window.show_effective(window.current_manifest.name)
    GLib.timeout_add(600, finish)
    return False
def finish():
    try:
        window = app.get_active_window()
        assert window.service.list_vms()[0].name == "novo-ambiente"
        labels = []
        def collect(widget):
            if isinstance(widget, Gtk.Label): labels.append(widget.get_text())
            child = widget.get_first_child()
            while child is not None:
                collect(child)
                child = child.get_next_sibling()
        collect(window.details)
        assert "Acessos ao Host · pastas" in labels
        assert "Rede" in labels
        assert "Perfis Incus" in labels
        assert "Inventário observado no guest" in labels
        assert window.terminal_page is not None
        window._open_integrated_terminal("novo-ambiente")
        assert window.stack.get_visible_child_name() == "terminal"
        assert window.terminal_status.get_text() == "Terminal real indisponível no modo mock."
        assert window.terminal_widget is None
        window.close()
        app.quit()
    except BaseException:
        traceback.print_exc()
        os._exit(2)
    return False
GLib.timeout_add(400, flow)
app.run([])
'''
    env = {**os.environ, "ISOLATEVM_MOCK": "1", "XDG_DATA_HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-c", script], check=True, timeout=12, env=env)


@pytest.mark.skipif(os.environ.get("ISOLATEVM_UI_TEST") != "1" or
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) or
                    not _has_vte_391(),
                    reason="ative ISOLATEVM_UI_TEST=1 em sessão gráfica com VTE 3.91")
def test_vte_terminal_spawns_fixed_argv_in_a_pty():
    script = '''
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Vte", "3.91")
from gi.repository import GLib, Gtk, Vte
app = Gtk.Application(application_id="org.isolatevm.VteSmoke", flags=0)
state = {"error": None, "ok": False}
def activate(app):
    window = Gtk.ApplicationWindow(application=app)
    terminal = Vte.Terminal()
    window.set_child(terminal)
    def exited(widget, status):
        output = widget.get_text_format(Vte.Format.TEXT) or ""
        state["ok"] = status == 0 and "PTY_TERMINAL_OK" in output
        app.quit()
    def spawned(widget, pid, error, _data):
        if error is not None:
            state["error"] = str(error)
            app.quit()
        else:
            widget.watch_child(pid)
    terminal.connect("child-exited", exited)
    terminal.spawn_async(Vte.PtyFlags.DEFAULT, None,
                         ["/usr/bin/printf", "PTY_TERMINAL_OK"],
                         ["PATH=/usr/bin:/bin", "LANG=C.UTF-8"],
                         GLib.SpawnFlags.DEFAULT, None, None, -1, None, spawned, None)
    window.present()
    GLib.timeout_add(5000, lambda: (state.update(error="VTE PTY timeout"), app.quit(), False)[-1])
app.connect("activate", activate)
app.run([])
if state["error"] or not state["ok"]:
    raise SystemExit(state["error"] or "VTE PTY did not deliver child output")
'''
    subprocess.run([sys.executable, "-c", script], check=True, timeout=8,
                   env=os.environ.copy())


@pytest.mark.skipif(os.environ.get("ISOLATEVM_UI_TEST") != "1" or
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="ative ISOLATEVM_UI_TEST=1 em sessão gráfica")
def test_wizard_exports_and_imports_real_manifest_file(tmp_path):
    script = '''
import os
import traceback
from pathlib import Path
from gi.repository import GLib
from isolatevm.model import Manifest
from isolatevm.ui import IsolateApp
app = IsolateApp()
def flow():
    try:
        window = app.get_active_window()
        manifest = Manifest.parse({"schemaVersion": 1, "name": "roundtrip-vm",
            "os": {"distribution": "ubuntu", "release": "24.04"},
            "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
            "network": {"mode": "offline"}, "mounts": [], "software": {"apt": ["curl"]},
            "security": {"profile": "maximum-isolation"}})
        target = Path(os.environ["EXPORT_TARGET"])
        window._fill_form(manifest)
        window._export_to(manifest, str(target))
        assert target.is_file()
        window.name_input.set_text("changed-vm")
        window.show_templates()
        window._import_from(str(target))
        assert window.stack.get_visible_child_name() == "wizard"
        assert window._form_manifest() == manifest
        window.close(); app.quit()
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False
GLib.timeout_add(400, flow)
app.run([])
'''
    env = {**os.environ, "ISOLATEVM_MOCK": "1", "XDG_DATA_HOME": str(tmp_path / "data"),
           "EXPORT_TARGET": str(tmp_path / "exported.yaml")}
    subprocess.run([sys.executable, "-c", script], check=True, timeout=12, env=env)


@pytest.mark.skipif(os.environ.get("ISOLATEVM_UI_TEST") != "1" or
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="ative ISOLATEVM_UI_TEST=1 em sessão gráfica")
def test_import_round_trips_multiple_host_mounts(tmp_path):
    script = '''
import os
import traceback
from pathlib import Path
from unittest.mock import patch
from gi.repository import GLib
from isolatevm.model import Manifest
from isolatevm.ui import IsolateApp
app = IsolateApp()
def flow():
    try:
        test_home = Path(os.environ["TEST_HOME"])
        first = test_home / "first"; second = test_home / "second"
        first.mkdir(); second.mkdir()
        raw = {"schemaVersion": 1, "name": "multi-mount",
               "os": {"distribution": "ubuntu", "release": "24.04", "desktop": "xfce"},
               "resources": {"cpu": 2, "memoryMiB": 4096, "diskGiB": 30, "pool": "default"},
               "network": {"mode": "offline"},
               "security": {"profile": "normal-development"},
               "lifecycle": {"disposition": "restore-initial-on-close"},
               "mounts": [{"host": str(first), "guest": "/workspace", "mode": "rw"},
                          {"host": str(second), "guest": "/datasets", "mode": "ro"}],
               "software": {"apt": ["git", "postgresql-client", "golang-go", "pipx", "docker.io", "python3", "python3-pip", "dotnet-sdk-10.0"],
                            "pipx": ["uv==0.12.18", "poetry==2.5.1", "aider-chat==0.86.2"],
                            "npm": ["bun@1.4.2", "@pnpm/exe@12.5.1", "@openai/codex@0.154.0",
                                    "@anthropic-ai/claude-code@2.1.276", "opencode-ai@1.18.31"],
                            "external": ["helm@community", "terraform@hashicorp", "kubectl@1.37"],
                            "cargo": ["ripgrep@14.1.1"], "go": ["golang.org/x/tools/gopls@v0.20.0"]},
               "environment": {"NODE_ENV": "development"}}
        with patch.object(Path, "home", return_value=test_home):
            manifest = Manifest.parse(raw)
            window = app.get_active_window()
            window._fill_form(manifest)
            assert len(window.mount_rows) == 2
            assert window.desktop_check.get_active()
            assert window.catalog_checks["git"].get_active()
            assert window.catalog_checks["docker.io"].get_active()
            assert window.catalog_checks["pipx:uv==0.12.18"].get_active()
            assert window.catalog_checks["npm:bun@1.4.2"].get_active()
            assert window.catalog_checks["npm:@pnpm/exe@12.5.1"].get_active()
            assert window.catalog_checks["external:helm@community"].get_active()
            assert window.catalog_checks["external:terraform@hashicorp"].get_active()
            assert window.catalog_checks["external:kubectl@1.37"].get_active()
            assert window.ai_coding_checks["@openai/codex@0.154.0"].get_active()
            assert window.ai_coding_checks["@anthropic-ai/claude-code@2.1.276"].get_active()
            assert window.ai_coding_checks["aider-chat==0.86.2"].get_active()
            assert window.ai_coding_checks["opencode-ai@1.18.31"].get_active()
            assert window.dotnet10_check.get_active()
            assert window.python_check.get_active()
            assert window.cargo_input.get_text() == "ripgrep@14.1.1"
            assert window.go_input.get_text() == "golang.org/x/tools/gopls@v0.20.0"
            assert window.lifecycle_input.get_active() == 3
            rebuilt = window._form_manifest()
            assert rebuilt == manifest, f"rebuilt={rebuilt.to_dict()!r}; original={manifest.to_dict()!r}"
            window.catalog_checks["docker.io"].set_active(False)
            assert "docker.io" not in window._form_manifest().apt
            window.catalog_checks["docker.io"].set_active(True)
            assert window._form_manifest() == manifest
            window.security_profile_input.set_active(0)
            window.wizard_step = 9; window._render_step()
            assert window.next_btn.get_sensitive()
            window._next()
            assert window.wizard_step == 10
            window.security_profile_input.set_active(1)
            window._next()
            assert window.current_manifest == manifest
        window.close(); app.quit()
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False
GLib.timeout_add(400, flow)
app.run([])
'''
    env = {**os.environ, "ISOLATEVM_MOCK": "1", "XDG_DATA_HOME": str(tmp_path / "data"),
           "TEST_HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-c", script], check=True, timeout=12, env=env)


@pytest.mark.skipif(os.environ.get("ISOLATEVM_UI_TEST") != "1" or
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="ative ISOLATEVM_UI_TEST=1 em sessão gráfica")
def test_dry_run_dialog_is_read_only_and_detailed(tmp_path):
    script = '''
import os
import traceback
from gi.repository import GLib, Gtk
from isolatevm.ui import IsolateApp
app = IsolateApp()
def flow():
    try:
        window = app.get_active_window()
        for _ in range(11): window._next()
        window._dry_run()
        GLib.timeout_add(700, verify)
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False
def verify():
    try:
        window = app.get_active_window()
        assert not window.service.items
        dialogs = [w for w in Gtk.Window.list_toplevels()
                   if isinstance(w, Gtk.Dialog) and w.get_title() == "Simulação de criação · somente leitura"]
        assert len(dialogs) == 1
        def walk(widget):
            if isinstance(widget, Gtk.TextView):
                buffer = widget.get_buffer()
                text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
                if "IMAGEM E DOWNLOADS" in text:
                    assert "REDE E ACESSO AO HOST" in text
                    assert "PROVISIONAMENTO NO PRIMEIRO BOOT" in text
                    return True
            child = widget.get_first_child()
            while child is not None:
                if walk(child): return True
                child = child.get_next_sibling()
            return False
        assert walk(dialogs[0])
        dialogs[0].destroy(); window.close(); app.quit()
    except BaseException:
        traceback.print_exc(); os._exit(2)
    return False
GLib.timeout_add(400, flow)
app.run([])
'''
    env = {**os.environ, "ISOLATEVM_MOCK": "1", "XDG_DATA_HOME": str(tmp_path)}
    subprocess.run([sys.executable, "-c", script], check=True, timeout=12, env=env)
