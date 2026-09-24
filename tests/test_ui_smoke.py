"""Opt-in GTK flow test; requires an active graphical session."""
import os
import subprocess
import sys

import pytest


@pytest.mark.skipif(os.environ.get("ISOLATEVM_UI_TEST") != "1" or
                    not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
                    reason="ative ISOLATEVM_UI_TEST=1 em sessão gráfica")
def test_wizard_dashboard_and_permissions(tmp_path):
    script = '''
import os
import traceback
from gi.repository import GLib, Gtk
from isolatevm.metrics import MetricsSnapshot
from isolatevm.ui import IsolateApp
app = IsolateApp()
def flow():
    window = app.get_active_window()
    window.stack.set_visible_child_name("wizard")
    window.catalog_checks["curl"].set_active(True)
    for _ in range(11): window._next()
    assert window.current_manifest is not None
    assert window.current_manifest.securityProfile == "maximum-isolation"
    assert window.current_manifest.desktop is None
    assert "curl" in window.current_manifest.apt
    window._next()
    assert window.wizard_step == 12
    assert window.next_btn.get_label() == "Criar ambiente"
    window.service.create(window.current_manifest)
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
               "mounts": [{"host": str(first), "guest": "/workspace", "mode": "rw"},
                          {"host": str(second), "guest": "/datasets", "mode": "ro"}],
               "software": {"apt": ["git", "postgresql-client", "golang-go", "pipx", "docker.io", "python3", "python3-pip"],
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
            assert window.python_check.get_active()
            assert window.cargo_input.get_text() == "ripgrep@14.1.1"
            assert window.go_input.get_text() == "golang.org/x/tools/gopls@v0.20.0"
            assert window._form_manifest() == manifest
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
