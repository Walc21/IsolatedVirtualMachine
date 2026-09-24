from pathlib import Path
from types import SimpleNamespace

import pytest

from isolatevm.access import local_socket
from isolatevm.incus import IncusError, LocalIncus
from isolatevm.model import Mount


def test_socket_selection_prefers_admin_and_tracks_confined_fallback(monkeypatch):
    monkeypatch.setattr("isolatevm.access.os.path.lexists", lambda path: path == "/run/incus/unix.socket")
    monkeypatch.setattr(Path, "is_socket", lambda path: str(path).startswith("/run/incus/unix.socket"))
    writable = {"/run/incus/unix.socket", "/run/incus/unix.socket.user"}
    monkeypatch.setattr("isolatevm.access.os.access", lambda path, mode: str(path) in writable)
    assert local_socket() == (Path("/run/incus/unix.socket"), "admin")
    writable.remove("/run/incus/unix.socket")
    assert local_socket() == (Path("/run/incus/unix.socket.user"), "confined")
    writable.clear()
    assert local_socket() == (None, "unavailable")


def test_cli_ignores_inherited_socket_overrides(monkeypatch, tmp_path):
    service = LocalIncus.__new__(LocalIncus)
    service.binary = "/usr/bin/incus"
    service.client_config_dir = tmp_path
    monkeypatch.setenv("INCUS_SOCKET", "/some/other/socket")
    monkeypatch.setenv("INCUS_DIR", "/some/other/directory")
    monkeypatch.setenv("INCUS_REMOTE", "remote")
    monkeypatch.setenv("INCUS_PROJECT", "unexpected-project")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs["env"]))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("isolatevm.incus.subprocess.run", run)
    assert service._run("info") == "ok"
    argv, env = calls[0]
    assert argv == ["/usr/bin/incus", "--force-local", "info"]
    assert not {"INCUS_SOCKET", "INCUS_DIR", "INCUS_REMOTE", "INCUS_PROJECT"} & env.keys()


def test_cli_can_read_cloud_init_error_status_without_accepting_empty_cli_failures(monkeypatch, tmp_path):
    service = LocalIncus.__new__(LocalIncus)
    service.binary = "/usr/bin/incus"
    service.client_config_dir = tmp_path
    monkeypatch.setattr("isolatevm.incus.subprocess.run", lambda *_, **__: SimpleNamespace(
        returncode=2, stdout='{"status":"error"}', stderr=""))
    assert service._run("exec", "dev-vm", "--", "cloud-init", "status", "--format=json",
                        ok_returncodes=(0, 1, 2)) == '{"status":"error"}'
    monkeypatch.setattr("isolatevm.incus.subprocess.run", lambda *_, **__: SimpleNamespace(
        returncode=2, stdout="", stderr="VM agent isn't currently running"))
    with pytest.raises(IncusError):
        service._run("exec", "dev-vm", "--", "cloud-init", "status", "--format=json",
                     ok_returncodes=(0, 1, 2))


def test_confined_socket_uses_cli_reads_for_its_project(monkeypatch, tmp_path):
    seen = []

    class Api:
        def __init__(self, path):
            seen.append(path)

        def get(self, endpoint):
            assert endpoint == "/1.0"
            return {}

    monkeypatch.setattr("isolatevm.incus.shutil.which", lambda _: "/usr/bin/incus")
    monkeypatch.setattr("isolatevm.incus.local_socket", lambda: (Path("/var/lib/incus/unix.socket.user"), "confined"))
    monkeypatch.setattr("isolatevm.incus.data_dir", lambda: tmp_path)
    monkeypatch.setattr("isolatevm.incus.IncusUnixApi", Api)
    service = LocalIncus()
    assert service.access_mode == "confined"
    assert service.api is None
    assert seen == []
    assert service.confined_connection_pending
    with pytest.raises(IncusError, match="Confirme a conexão"):
        service._run("info")
    service.approve_confined_connection()
    assert not service.confined_connection_pending


def test_admin_socket_keeps_api_reader(monkeypatch, tmp_path):
    class Api:
        def __init__(self, path):
            self.socket_path = path

        def get(self, endpoint):
            return {}

    monkeypatch.setattr("isolatevm.incus.shutil.which", lambda _: "/usr/bin/incus")
    monkeypatch.setattr("isolatevm.incus.local_socket", lambda: (Path("/var/lib/incus/unix.socket"), "admin"))
    monkeypatch.setattr("isolatevm.incus.data_dir", lambda: tmp_path)
    monkeypatch.setattr("isolatevm.incus.IncusUnixApi", Api)
    service = LocalIncus()
    assert service.api.socket_path == Path("/var/lib/incus/unix.socket")


def test_confined_project_blocks_host_mount_before_mutation(tmp_path):
    service = LocalIncus.__new__(LocalIncus)
    service.access_mode = "confined"
    service._run = lambda *args: "config:\n  restricted: 'true'\n"
    mount = Mount(str(tmp_path / "workspace"), "/workspace", "ro")
    with pytest.raises(IncusError, match="não permite compartilhar"):
        service._check_host_mount_policy((mount,))


def test_confined_project_honors_allowed_host_paths(tmp_path):
    service = LocalIncus.__new__(LocalIncus)
    service.access_mode = "confined"
    allowed = tmp_path / "allowed"
    service._run = lambda *args: ("config:\n  restricted: 'true'\n"
                                  "  restricted.devices.disk: allow\n"
                                  f"  restricted.devices.disk.paths: {allowed}\n")
    service._check_host_mount_policy((Mount(str(allowed / "project"), "/workspace"),))
    with pytest.raises(IncusError, match="lista de mounts"):
        service._check_host_mount_policy((Mount(str(tmp_path / "other"), "/workspace"),))


def test_raw_instance_queries_use_the_confined_user_project(monkeypatch):
    service = LocalIncus.__new__(LocalIncus)
    service.access_mode = "confined"
    monkeypatch.setattr("isolatevm.incus.os.geteuid", lambda: 1234)
    calls = []
    def query(*args):
        calls.append(args)
        return {"metadata": []}
    service._json = query
    assert service.snapshots("dev-vm") == []
    assert calls == [("query", "/1.0/instances/dev-vm/snapshots?project=user-1234")]
    service._json = lambda *args: {"metadata": [
        "/1.0/instances/dev-vm/snapshots/baseline?project=user-1234"]}
    assert service.snapshots("dev-vm") == ["baseline"]
