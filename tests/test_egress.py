import os

import pytest

from isolatevm.egress import EgressError, _runtime, request_for
from isolatevm.model import Manifest, ValidationError


def restricted():
    return Manifest.parse({"schemaVersion": 1, "name": "locked-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
        "network": {"mode": "restricted", "bridge": f"incusbr-{os.getuid()}", "egress": [
            {"kind": "domain", "value": "github.com", "port": 443, "protocol": "tcp"}]},
        "security": {"profile": "restricted-development"}, "mounts": [], "software": {"apt": []}})


def test_helper_request_has_only_typed_fields():
    assert request_for(restricted()) == {"version": 1, "name": "locked-vm", "bridge": f"incusbr-{os.getuid()}",
                                         "network_mode": "restricted",
                                         "rules": [{"kind": "domain", "value": "github.com", "port": 443}]}


def test_proxy_request_rejects_bridge_that_privileged_helper_cannot_accept():
    raw = restricted().to_dict()
    raw["network"]["bridge"] = "incusbr0"
    with pytest.raises(ValidationError, match="bridge Incus de usuário"):
        request_for(Manifest.parse(raw))


def test_runtime_response_is_closed():
    assert _runtime({"address": "198.51.100.200", "gateway": "198.51.100.1", "port": 20200,
                     "mac": "02:00:00:00:00:01"}).proxy_url.endswith(":20200")
    with pytest.raises(EgressError): _runtime({"address": "10.0.0.2", "gateway": "10.0.0.1", "port": 1,
                                                "mac": "broken"})
    with pytest.raises(EgressError): _runtime({"address": "not-an-ip", "gateway": "10.0.0.1", "port": 20200,
                                                "mac": "02:00:00:00:00:01"})
    with pytest.raises(ValidationError): request_for(Manifest.parse({**restricted().to_dict(), "network": {"mode": "offline"}}))


def lan_only(network):
    return Manifest.parse({"schemaVersion": 1, "name": "locked-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
        "network": {"mode": "lan-only", "bridge": f"incusbr-{os.getuid()}", "egress": network},
        "security": {"profile": "restricted-development"}, "mounts": [],
        "software": {"apt": []}})


def test_lan_only_manifest_uses_private_ipv4_cidrs_and_proxy():
    manifest = lan_only([{"kind": "cidr", "value": "192.168.1.0/24", "port": 5432}])
    assert request_for(manifest)["network_mode"] == "lan-only"
    assert request_for(manifest)["rules"] == [{"kind": "cidr", "value": "192.168.1.0/24", "port": 5432}]
    with pytest.raises(ValidationError, match="CIDRs dentro"):
        lan_only([{"kind": "cidr", "value": "8.8.8.0/24", "port": 5432}])
    with pytest.raises(ValidationError, match="CIDRs IPv4 privados"):
        lan_only([{"kind": "domain", "value": "printer.local", "port": 443}])


def test_privileged_helper_revalidates_lan_only_cidr_restriction():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).parents[1] / "packaging" / "isolatevm-egress-helper.py"
    spec = importlib.util.spec_from_file_location("isolatevm_egress_helper_test", path)
    assert spec and spec.loader
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    private = [{"kind": "cidr", "value": "10.20.0.0/16", "port": 443}]
    assert helper.rules(private, "lan-only") == private
    with pytest.raises(helper.Error, match="RFC1918"):
        helper.rules([{"kind": "cidr", "value": "0.0.0.0/0", "port": 443}], "lan-only")
    with pytest.raises(helper.Error, match="RFC1918"):
        helper.rules([{"kind": "domain", "value": "example.com", "port": 443}], "lan-only")
    with pytest.raises(helper.Error, match="IP ou CIDR inválido"):
        helper.rules([{"kind": "cidr", "value": "10.20.3.4/16", "port": 443}], "lan-only")


def _helper_module():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).parents[1] / "packaging" / "isolatevm-egress-helper.py"
    spec = importlib.util.spec_from_file_location("isolatevm_egress_helper_security_test", path)
    assert spec and spec.loader
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def test_firewall_replacement_uses_one_transaction_and_rejects_nft_injection(monkeypatch):
    from types import SimpleNamespace

    helper = _helper_module()
    calls = []

    def run(*args, input_text=None, check=True):
        calls.append((args, input_text, check))
        if args[:3] == ("/usr/sbin/nft", "list", "table"):
            return SimpleNamespace(returncode=0, stdout="table exists", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(helper, "run", run)
    helper.apply_nft({"u1000-vm": {"mac": "02:00:00:00:00:01", "address": "10.0.0.200",
                                   "gateway": "10.0.0.1", "port": 20200}})
    assert len(calls) == 3
    assert calls[1][0] == ("/usr/sbin/nft", "--check", "--file", "-")
    assert calls[2][0] == ("/usr/sbin/nft", "--file", "-")
    assert calls[1][1].startswith("delete table bridge isolatevm_egress\n")
    assert calls[1][1] == calls[2][1]
    assert not any(call[0][1:3] == ("delete", "table") for call in calls)
    forward = calls[1][1].split("chain input", 1)[0]
    assert "ether saddr 02:00:00:00:00:01 drop" in forward
    assert "arp accept" not in forward and "udp dport 67 accept" not in forward
    bad = {"vm": {"mac": "02:00:00:00:00:01; flush ruleset", "address": "10.0.0.200",
                   "gateway": "10.0.0.1", "port": 20200}}
    with pytest.raises(helper.Error, match="estado de firewall inválido"):
        helper.render_nft(bad)


def test_egress_removal_cannot_stop_another_users_policy(monkeypatch):
    helper = _helper_module()
    other = {"bridge": "incusbr-2000", "owner_uid": 2000, "name": "locked-vm",
             "service_name": "u2000-locked-vm"}
    monkeypatch.setattr(helper, "state", lambda: {"u2000-locked-vm": other})
    stopped = []
    monkeypatch.setattr(helper, "unit", lambda *args: stopped.append(args))
    helper.remove({"version": 1, "name": "locked-vm"}, 1000)
    assert stopped == []


def test_helper_bounds_request_json_and_rejects_duplicate_keys(monkeypatch):
    import io
    helper = _helper_module()
    monkeypatch.setattr(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(
        b'{"version":1,"version":1}'), encoding="utf-8"))
    with pytest.raises(helper.Error, match="duplicados"):
        helper.load_json()
    monkeypatch.setattr(helper.sys, "stdin", io.TextIOWrapper(io.BytesIO(
        b" " * (helper.MAX_REQUEST_BYTES + 1)), encoding="utf-8"))
    with pytest.raises(helper.Error, match="limite"):
        helper.load_json()


def test_policy_update_stops_the_old_proxy_before_replacing_its_acl(monkeypatch):
    helper = _helper_module()
    existing = {"bridge": "incusbr-1000", "network_mode": "restricted",
                "address": "10.0.0.200", "gateway": "10.0.0.1", "port": 20200,
                "mac": "02:00:00:00:00:01", "rules": [{"kind": "domain", "value": "github.com", "port": 443}],
                "owner_uid": 1000, "name": "locked-vm", "service_name": "u1000-locked-vm"}
    monkeypatch.setattr(helper, "bridge_info", lambda *_args: ("10.0.0.1", helper.ipaddress.ip_network("10.0.0.0/24")))
    monkeypatch.setattr(helper, "state", lambda: {"u1000-locked-vm": existing})
    monkeypatch.setattr(helper, "lease_addresses", lambda _bridge, _uid: set())
    monkeypatch.setattr(helper, "ensure_bridge_netfilter", lambda: None)
    monkeypatch.setattr(helper, "ensure_firewall_guard", lambda: None)
    events = []
    monkeypatch.setattr(helper, "unit", lambda _name, action: events.append(("unit", action)))
    monkeypatch.setattr(helper, "prepare_logs", lambda _name: events.append(("logs", None)))
    monkeypatch.setattr(helper, "write_config", lambda *_args: events.append(("config", None)))
    monkeypatch.setattr(helper, "save_state", lambda _data: events.append(("state", None)))
    monkeypatch.setattr(helper, "apply_nft", lambda _data: events.append(("firewall", None)))
    helper.apply({"version": 1, "name": "locked-vm", "bridge": "incusbr-1000",
                  "network_mode": "restricted",
                  "rules": [{"kind": "domain", "value": "api.github.com", "port": 443}]}, 1000)
    assert events.index(("unit", "stop")) < events.index(("config", None))
    assert events.index(("config", None)) < events.index(("firewall", None))
    assert events.index(("firewall", None)) < events.index(("unit", "restart"))


def test_lease_lookup_is_local_and_covers_user_and_default_projects(monkeypatch):
    from types import SimpleNamespace
    helper = _helper_module()
    calls = []

    def run_limited(args, *, output_limit_bytes):
        calls.append(tuple(args))
        output = '[{"address":"10.0.0.20"}]' if "user-1000" in args else '[]'
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(helper, "run_limited", run_limited)
    assert helper.lease_addresses("incusbr-1000", 1000) == {"10.0.0.20"}
    assert len(calls) == 2
    assert all(args[:5] == ("/usr/bin/incus", "--force-local", "--project",
                            "user-1000" if index == 0 else "default", "network")
               for index, args in enumerate(calls))


def test_root_helper_bounds_subprocess_capture():
    helper = _helper_module()
    with pytest.raises(helper.Error, match="excedeu o limite"):
        helper.run_limited([helper.sys.executable, "-c", "print('x' * 10000)"],
                           output_limit_bytes=128)


def test_proxy_log_setup_rejects_symlink_before_chown(monkeypatch, tmp_path):
    from pathlib import Path
    from types import SimpleNamespace
    helper = _helper_module()
    logdir = tmp_path / "logs"
    logdir.mkdir()
    target = tmp_path / "sensitive"
    target.write_text("preserve")
    (logdir / "vm.cache.log").symlink_to(target)
    monkeypatch.setattr(helper, "LOG", logdir)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: type("Account", (), {"pw_uid": 1, "pw_gid": 1})())
    monkeypatch.setattr(helper.os, "chown", lambda *_args: None)
    monkeypatch.setattr(helper.os, "chmod", lambda *_args: None)
    original_lstat = Path.lstat
    def root_owned_logdir(path):
        result = original_lstat(path)
        if path == logdir:
            return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
        return result
    monkeypatch.setattr(Path, "lstat", root_owned_logdir)
    with pytest.raises(helper.Error, match="log do proxy inseguro"):
        helper.prepare_logs("vm")
    assert target.read_text() == "preserve"
