import pytest
from pathlib import Path

from isolatevm.incus import IncusError, LocalIncus, _friendly_error, _redact_config
from isolatevm.mock import MockIncus
from isolatevm.model import Manifest, Mount, ValidationError
from isolatevm.usb import UsbDevice
from isolatevm.gpu import GpuDevice


def sample():
    return Manifest.parse({"schemaVersion": 1, "name": "dev-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 4096, "diskGiB": 30, "pool": "default"},
        "network": {"mode": "offline"}, "mounts": [], "software": {"apt": ["git"]}})


def test_mock_lifecycle():
    service = MockIncus(); manifest = sample()
    service.create(manifest)
    assert service.list_vms()[0].status == "Stopped"
    service.change_state("dev-vm", "start")
    service.change_state("dev-vm", "force-stop")
    assert service.list_vms()[0].status == "Stopped"
    service.snapshot("dev-vm", "initial")
    assert service.list_vms()[0].snapshots == 1
    service.rename_snapshot("dev-vm", "initial", "baseline")
    assert service.snapshots("dev-vm") == ["baseline"]
    service.clone("dev-vm", "dev-copy")
    assert len(service.list_vms()) == 2
    service.delete("dev-vm")
    assert [x.name for x in service.list_vms()] == ["dev-copy"]


def test_force_stop_uses_explicit_incus_operation():
    service = LocalIncus.__new__(LocalIncus)
    calls = []
    service._run = lambda *args, **kwargs: calls.append((args, kwargs))
    service.change_state("dev-vm", "force-stop")
    assert calls == [(("stop", "dev-vm", "--force"), {"timeout": 120})]
    with pytest.raises(ValidationError):
        service.change_state("dev-vm", "force;stop")


def test_provisioning_status_reads_guest_without_leaking_error_details():
    service = LocalIncus.__new__(LocalIncus)
    calls = []
    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return '{"extended_status":"degraded done","stage":null,"errors":["secret value"],"recoverable_errors":{"WARNING":["details"]}}'
    service._run = run
    result = service.provisioning_status("dev-vm")
    assert (result.status, result.stage, result.error_count) == ("degraded done", None, 2)
    assert calls == [(("exec", "dev-vm", "--", "cloud-init", "status", "--format=json"),
                      {"timeout": 30, "ok_returncodes": (0, 1, 2)})]
    with pytest.raises(ValidationError): service.provisioning_status("bad;name")


def test_snapshot_rename_uses_fixed_cli_operation():
    service = LocalIncus.__new__(LocalIncus)
    calls = []
    service._run = lambda *args, **kwargs: calls.append(args)
    service.rename_snapshot("dev-vm", "before", "after")
    assert calls == [("snapshot", "rename", "dev-vm", "before", "after")]
    with pytest.raises(ValidationError):
        service.rename_snapshot("dev-vm", "before", "bad;name")
    with pytest.raises(ValidationError):
        service.rename_snapshot("dev-vm", "before", "before")


def test_list_cards_separate_host_mounts_from_volumes_and_show_effective_policy():
    service = LocalIncus.__new__(LocalIncus)
    service._read = lambda *args: [{"name": "dev-vm", "type": "virtual-machine", "status": "Running",
        "expanded_config": {"limits.cpu": "4", "limits.memory": "8192MiB",
                            "image.os": "Ubuntu", "image.release": "24.04",
                            "user.isolatevm.security-profile": "normal-development"},
        "expanded_devices": {"root": {"type": "disk", "path": "/", "size": "50GiB"},
                             "share": {"type": "disk", "source": "/home/user/project", "path": "/workspace"},
                             "volume": {"type": "disk", "source": "data", "path": "/data"},
                             "eth0": {"type": "nic", "network": "incusbr0"}},
        "state": {"network": {"eth0": {"addresses": [{"family": "inet", "scope": "global", "address": "10.0.0.2"}]}}},
        "snapshots": [{"name": "baseline"}]}]
    vm = service.list_vms()[0]
    assert vm.mounts == 1
    assert vm.snapshots == 1
    assert vm.os == "Ubuntu 24.04"
    assert vm.ip == "10.0.0.2"
    assert vm.security_profile == "normal-development"
    assert "saída não verificada" in vm.network_policy


def test_create_has_no_profile_or_nic_when_offline():
    service = LocalIncus.__new__(LocalIncus)
    calls = []
    service.preflight = lambda manifest: None
    service._run = lambda *args, **kwargs: calls.append(args)
    events = []
    service.create(sample(), events.append)
    args = calls[0]
    assert "--no-profiles" in args
    assert not any("nic" in part for part in args)
    assert "root,type=disk" in args
    assert "root,path=/" in args
    assert "root,pool=default" in args
    assert "root,size=30GiB" in args
    assert "user.isolatevm.managed=true" in args
    assert "user.isolatevm.security-profile=custom" in args
    assert any("cloud-init.user-data=#cloud-config" in part for part in args)
    assert events[-1] == "VM criada e parada"


def test_create_network_uses_separate_device_properties():
    raw = sample().to_dict(); raw["network"] = {"mode": "normal", "bridge": "incusbr0"}
    service = LocalIncus.__new__(LocalIncus)
    service.preflight = lambda manifest: None
    calls = []
    service._run = lambda *args, **kwargs: calls.append(args)
    service.create(Manifest.parse(raw))
    assert "--no-profiles" in calls[0]
    assert not any("eth0" in part for part in calls[0])
    assert calls[1] == ("config", "device", "add", "dev-vm", "eth0", "nic",
                        "network=incusbr0", "name=eth0")


def test_create_restricted_network_applies_proxy_before_filtered_nic(monkeypatch):
    raw = sample().to_dict()
    raw["network"] = {"mode": "restricted", "bridge": "incusbr0", "egress": [
        {"kind": "domain", "value": "github.com", "port": 443, "protocol": "tcp"}]}
    raw["security"] = {"profile": "restricted-development"}
    service = LocalIncus.__new__(LocalIncus)
    service.preflight = lambda manifest: None
    calls = []
    service._run = lambda *args, **kwargs: calls.append(args)
    class Runtime:
        address = "198.51.100.200"
        proxy_url = "http://198.51.100.1:20200"
        mac = "02:00:00:00:00:01"
    monkeypatch.setattr("isolatevm.incus.apply_egress", lambda manifest: Runtime())
    service.create(Manifest.parse(raw))
    assert calls[1] == ("config", "device", "add", "dev-vm", "eth0", "nic",
                        "network=incusbr0", "name=eth0", "ipv4.address=198.51.100.200", "hwaddr=02:00:00:00:00:01",
                        "ipv6.address=none", "security.ipv4_filtering=true", "security.ipv6_filtering=true",
                        "security.port_isolation=true")
    assert 'cloud-init.user-data=#cloud-config' in calls[0][-1]
    assert 'Acquire::https::Proxy' in calls[0][-1]


def test_create_passes_non_secret_environment_as_separate_config_item():
    raw = sample().to_dict(); raw["environment"] = {"NODE_ENV": "development"}
    service = LocalIncus.__new__(LocalIncus)
    service.preflight = lambda manifest: None
    calls = []
    service._run = lambda *args, **kwargs: calls.append(args)
    service.create(Manifest.parse(raw))
    assert "environment.NODE_ENV=development" in calls[0]


def test_pool_space_uses_typed_read_only_resources():
    service = LocalIncus.__new__(LocalIncus)
    class Api:
        def get(self, endpoint):
            assert endpoint == "/1.0/storage-pools/default/resources"
            return {"space": {"total": 1000, "used": 250}}
    service.api = Api()
    assert service.pool_space("default") == (750, 1000)
    with pytest.raises(ValidationError): service.pool_space("../other")
    service.api = None
    service._run = lambda *args: "space:\n  total: 1000\n  used: 250\n"
    assert service.pool_space("default") == (750, 1000)
    service._run = lambda *args: "space:\n  total: invalid\n  used: 250\n"
    assert service.pool_space("default") is None


def test_confined_project_discovers_its_named_pool_when_listing_is_denied():
    service = LocalIncus.__new__(LocalIncus)
    service.access_mode = "confined"
    def denied(*args):
        raise IncusError("A operação Incus falhou", "Certificate is restricted")
    service._read = denied
    calls = []
    def run(*args):
        calls.append(args)
        if args == ("profile", "show", "default"):
            return "devices:\n  root:\n    type: disk\n    path: /\n    pool: isolatevm\n"
        if args == ("storage", "show", "isolatevm"):
            return "name: isolatevm\n"
        raise AssertionError(args)
    service._run = run
    assert service.pools() == ["isolatevm"]
    assert calls == [("profile", "show", "default"), ("storage", "show", "isolatevm")]


def test_image_preview_selects_vm_alias_for_host_architecture(monkeypatch):
    service = LocalIncus.__new__(LocalIncus)
    monkeypatch.setattr("isolatevm.incus.platform.machine", lambda: "x86_64")
    rows = [
        {"type": "container", "architecture": "x86_64", "fingerprint": "container",
         "aliases": [{"name": "ubuntu/24.04/cloud"}]},
        {"type": "virtual-machine", "architecture": "aarch64", "fingerprint": "arm",
         "aliases": [{"name": "ubuntu/24.04/cloud"}]},
        {"type": "virtual-machine", "architecture": "x86_64", "fingerprint": "vm",
         "aliases": [{"name": "ubuntu/24.04/cloud"}], "size": 1048576,
         "uploaded_at": "2026-09-23T00:00:00Z"},
    ]
    service._json = lambda *args: rows
    info = service.image_info("24.04")
    assert info["fingerprint"] == "vm"
    assert info["size"] == "1048576 bytes (1.0 MiB)"
    assert info["architecture"] == "x86_64"
    rows.pop()
    with pytest.raises(IncusError, match="indisponível"):
        service.image_info("24.04")


def test_rollback_after_mount_failure(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    project = tmp_path / "project"; project.mkdir()
    raw = sample().to_dict()
    raw["mounts"] = [{"host": str(project), "guest": "/workspace", "mode": "ro"}]
    manifest = Manifest.parse(raw)
    service = LocalIncus.__new__(LocalIncus)
    service.preflight = lambda manifest: None
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("config", "device", "add"): raise IncusError("mount failed")
    service._run = run
    with pytest.raises(IncusError): service.create(manifest)
    assert calls[-1] == ("delete", "dev-vm", "--force")


def test_failed_create_reports_uncertain_state():
    service = LocalIncus.__new__(LocalIncus)
    service.preflight = lambda manifest: None
    service._run = lambda *args, **kwargs: (_ for _ in ()).throw(IncusError("timeout"))
    with pytest.raises(IncusError, match="não foi confirmada"):
        service.create(sample())


def test_sensitive_values_hidden():
    config = {"cloud-init.user-data": "password: abc", "limits.cpu": "2",
              "environment.OPENAI_API_KEY": "sk-test", "user.note": "possibly private",
              "nested": {"api_token": "secret"}}
    clean = _redact_config(config)
    assert clean["cloud-init.user-data"] == "[OCULTO]"
    assert clean["limits.cpu"] == "2"
    assert clean["nested"]["api_token"] == "[OCULTO]"
    assert clean["environment.OPENAI_API_KEY"] == "[OCULTO]"
    assert clean["user.note"] == "[OCULTO]"


def test_network_controls_require_incus_managed_marker():
    service = LocalIncus.__new__(LocalIncus)
    service._run = lambda *args, **kwargs: "config: {}\nprofiles: []\ndevices: {}\n"
    with pytest.raises(IncusError, match="criadas pelo IsolateVM"):
        service._local_devices("other-vm")


def test_common_incus_errors_are_actionable():
    assert "Espaço insuficiente" in _friendly_error("No space left on device")
    assert "Sem autorização" in _friendly_error("Permission denied")


def test_managed_mount_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    folder = tmp_path / "project"; folder.mkdir()
    service = MockIncus(); service.create(sample())
    service.add_mount("dev-vm", Mount(str(folder), "/workspace", "ro"))
    assert service.effective("dev-vm")["mounts"][0]["mode"] == "RO"
    assert service.list_vms()[0].mounts == 1
    with pytest.raises(ValidationError):
        service.add_mount("dev-vm", Mount(str(folder), "/workspace", "rw"))
    service.remove_mount("dev-vm", "isovm0")
    assert service.effective("dev-vm")["mounts"] == []
    with pytest.raises(ValidationError): service.remove_mount("dev-vm", "root")


def test_maximum_isolation_blocks_later_mounts_and_nic(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    folder = tmp_path / "project"; folder.mkdir()
    raw = sample().to_dict()
    raw["security"] = {"profile": "maximum-isolation"}
    service = MockIncus(); service.create(Manifest.parse(raw))
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        service.add_mount("dev-vm", Mount(str(folder), "/workspace", "ro"))
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        service.restore_network("dev-vm", "incusbr0")
    assert service.effective("dev-vm")["security_profile"] == "maximum-isolation"


def test_mock_usb_is_explicit_managed_and_rejected_by_maximum_isolation():
    usb = UsbDevice("1-7", "2b7e", "0134", "Camera")
    service = MockIncus(); service.create(sample())
    service.add_usb_device("dev-vm", usb)
    effective = service.effective("dev-vm")
    assert effective["other_devices"] == [{"device": "isousb0", "type": "usb", "managed": True}]
    service.remove_usb_device("dev-vm", "isousb0")
    assert not service.effective("dev-vm")["other_devices"]
    raw = sample().to_dict(); raw["security"] = {"profile": "maximum-isolation"}
    service = MockIncus(); service.create(Manifest.parse(raw))
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        service.add_usb_device("dev-vm", usb)


def test_local_usb_uses_only_ids_and_managed_slot(monkeypatch):
    service = LocalIncus.__new__(LocalIncus)
    service._security_profile = lambda name: "custom"
    service._check_usb_policy = lambda: None
    service._local_devices = lambda name: {"root": {"type": "disk"}}
    calls = []
    service._run = lambda *args, **kwargs: calls.append(args)
    service.add_usb_device("dev-vm", UsbDevice("1-7", "2b7e", "0134", "Camera"))
    assert calls == [("config", "device", "add", "dev-vm", "isousb0", "usb", "vendorid=2b7e", "productid=0134", "required=false")]
    with pytest.raises(ValidationError):
        service.remove_usb_device("dev-vm", "usb0")


def test_local_gpu_uses_only_pci_and_managed_slot():
    service = LocalIncus.__new__(LocalIncus)
    service._security_profile = lambda name: "custom"
    service._local_devices = lambda name: {}
    calls = []; service._run = lambda *args, **kwargs: calls.append(args)
    service.add_gpu_device("dev-vm", GpuDevice("0000:01:00.0", "10de", "1f91", "GPU"))
    assert calls == [("config", "device", "add", "dev-vm", "isogpu0", "gpu", "gputype=physical", "pci=0000:01:00.0", "vendorid=10de", "productid=1f91")]
    service._security_profile = lambda name: "maximum-isolation"
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        service.add_gpu_device("dev-vm", GpuDevice("0000:01:00.0", "10de", "1f91", "GPU"))


def test_local_maximum_isolation_rejects_mount_before_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    folder = tmp_path / "project"; folder.mkdir()
    service = LocalIncus.__new__(LocalIncus)
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        return "config:\n  user.isolatevm.security-profile: maximum-isolation\n"
    service._run = run
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        service.add_mount("dev-vm", Mount(str(folder), "/workspace", "ro"))
    assert calls == [("config", "show", "dev-vm")]


def test_network_block_and_restore_only_original_bridge():
    raw = sample().to_dict()
    raw["network"] = {"mode": "normal", "bridge": "incusbr0"}
    service = MockIncus(); service.create(Manifest.parse(raw))
    service.block_network("dev-vm")
    assert "Sem NIC" in service.effective("dev-vm")["network"]
    with pytest.raises(IncusError): service.restore_network("dev-vm", "otherbr0")
    service.restore_network("dev-vm", "incusbr0")
    assert "Conectada" in service.effective("dev-vm")["network"]


@pytest.mark.parametrize("kind", ["proxy", "pci", "mystery"])
def test_block_network_rejects_other_possible_paths_even_with_one_nic(monkeypatch, kind):
    service = LocalIncus.__new__(LocalIncus)
    calls = []
    service._local_devices = lambda name: {
        "eth0": {"type": "nic", "network": "incusbr0"},
        "forward": {"type": kind, "listen": "tcp:127.0.0.1:8080"}}
    service._run = lambda *args, **kwargs: calls.append(args)
    monkeypatch.setattr("isolatevm.incus.saved_network_bridge", lambda name: "incusbr0")
    with pytest.raises(IncusError, match="bloqueio total"):
        service.block_network("dev-vm")
    assert calls == []


def test_resource_edit_is_typed_and_atomic():
    service = LocalIncus.__new__(LocalIncus)
    calls = []
    service._run = lambda *args, **kwargs: calls.append(args)
    service.set_resources("dev-vm", 4, 8192)
    assert calls == [("config", "set", "dev-vm", "limits.cpu=4", "limits.memory=8192MiB")]
    with pytest.raises(ValidationError): service.set_resources("dev-vm", True, 8192)
    assert len(calls) == 1


def test_console_requires_spice_client(monkeypatch):
    service = LocalIncus.__new__(LocalIncus)
    service.binary = "/usr/bin/incus"
    monkeypatch.setattr("isolatevm.incus.shutil.which", lambda name: None)
    with pytest.raises(IncusError, match="SPICE"):
        service.console_argv("dev-vm")
    monkeypatch.setattr("isolatevm.incus.shutil.which", lambda name: "/usr/bin/remote-viewer" if name == "remote-viewer" else None)
    assert service.console_argv("dev-vm") == ["/usr/bin/incus", "--force-local", "console", "dev-vm", "--type", "vga"]


def test_guest_login_prompts_interactively_without_password_argument():
    service = LocalIncus.__new__(LocalIncus)
    service.binary = "/usr/bin/incus"
    assert service.guest_login_argv("dev-vm") == ["/usr/bin/incus", "--force-local", "exec", "dev-vm",
                                                  "--mode", "interactive", "--", "/usr/bin/passwd", "ubuntu"]
    with pytest.raises(ValidationError):
        service.guest_login_argv("other;vm")


def test_full_backup_is_create_only_and_cleans_staging(tmp_path):
    service = LocalIncus.__new__(LocalIncus)
    calls = []
    def export(*args, **kwargs):
        calls.append(args)
        Path(args[2]).write_bytes(b"incus backup")
        Path(args[2]).chmod(0o666)
    service._run = export
    target = tmp_path / "dev-vm.tar.gz"
    service.export_full("dev-vm", target)
    assert target.read_bytes() == b"incus backup"
    assert target.stat().st_mode & 0o777 == 0o600
    assert calls[0][:2] == ("export", "dev-vm")
    assert list(tmp_path.iterdir()) == [target]
    with pytest.raises(ValidationError, match="já existe"):
        service.export_full("dev-vm", target)
    assert len(calls) == 1


def test_failed_full_backup_leaves_no_destination(tmp_path):
    service = LocalIncus.__new__(LocalIncus)
    def fail(*args, **kwargs):
        Path(args[2]).write_bytes(b"partial")
        raise IncusError("export failed")
    service._run = fail
    with pytest.raises(IncusError, match="export failed"):
        service.export_full("dev-vm", tmp_path / "failed.tar.gz")
    assert list(tmp_path.iterdir()) == []
