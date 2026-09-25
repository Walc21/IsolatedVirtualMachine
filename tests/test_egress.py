import os
import shutil
import socket
import subprocess
import tempfile
import time

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
        if args[:5] == ("/usr/sbin/nft", "list", "table", "bridge", "isolatevm_egress"):
            return SimpleNamespace(returncode=0, stdout="table exists", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(helper, "run", run)
    helper.apply_nft({"u1000-vm": {"mac": "02:00:00:00:00:01", "address": "10.0.0.200",
                                   "gateway": "10.0.0.1", "port": 20200}})
    assert len(calls) == 4
    assert calls[2][0] == ("/usr/sbin/nft", "--check", "--file", "-")
    assert calls[3][0] == ("/usr/sbin/nft", "--file", "-")
    assert calls[2][1].startswith("delete table bridge isolatevm_egress\n")
    assert calls[2][1] == calls[3][1]
    assert not any(call[0][1:3] == ("delete", "table") for call in calls)
    forward = calls[2][1].split("chain input", 1)[0]
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


def test_privileged_state_rejects_duplicate_json_fields(monkeypatch, tmp_path):
    from pathlib import Path
    from types import SimpleNamespace
    import stat

    helper = _helper_module()
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    state_path = root / "state.json"
    state_path.write_text('{"u1000-vm":{"owner_uid":1000,"owner_uid":2000}}')
    monkeypatch.setattr(helper, "ROOT", root)
    monkeypatch.setattr(helper, "STATE", state_path)
    original_lstat = Path.lstat
    def root_as_system_directory(path):
        result = original_lstat(path)
        if path == root:
            return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
        return result
    monkeypatch.setattr(Path, "lstat", root_as_system_directory)
    original_fstat = helper.os.fstat
    def root_owned_state(fd):
        result = original_fstat(fd)
        if fd == state_fd[0]:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                                   st_nlink=1, st_size=result.st_size)
        return result
    state_fd = []
    original_open = helper.os.open
    def record_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        if args[0] == state_path:
            state_fd.append(fd)
        return fd
    monkeypatch.setattr(helper.os, "open", record_open)
    monkeypatch.setattr(helper.os, "fstat", root_owned_state)
    with pytest.raises(helper.Error, match="campos duplicados"):
        helper.state()


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
    monkeypatch.setattr(helper, "wait_for_proxy", lambda *_args: events.append(("listener", None)))
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


def test_root_helper_bounds_all_commands_and_can_send_nft_batch_stdin(monkeypatch):
    helper = _helper_module()
    monkeypatch.setattr(helper, "MAX_COMMAND_OUTPUT_BYTES", 128)
    with pytest.raises(helper.Error, match="excedeu o limite"):
        helper.run(helper.sys.executable, "-c", "print('x' * 10000)")
    result = helper.run(helper.sys.executable, "-c",
                        "import sys; print(sys.stdin.read())", input_text="nft batch")
    assert result.returncode == 0 and result.stdout == "nft batch\n"
    monkeypatch.setattr(helper, "MAX_COMMAND_INPUT_BYTES", 8)
    with pytest.raises(helper.Error, match="entrada do comando excedeu"):
        helper.run(helper.sys.executable, "-c", "pass", input_text="x" * 9)


def test_proxy_log_setup_rejects_symlink_before_chown(monkeypatch, tmp_path):
    helper = _helper_module()
    logdir = tmp_path / "logs"
    logdir.mkdir(mode=0o750)
    target = tmp_path / "sensitive"
    target.write_text("preserve")
    (logdir / "vm.cache.log").symlink_to(target)
    monkeypatch.setattr(helper, "LOG", logdir)
    account = type("Account", (), {"pw_uid": os.getuid(), "pw_gid": os.getgid()})()
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: account)
    monkeypatch.setattr(helper.os, "fchown", lambda *_args: None)
    with pytest.raises(helper.Error, match="log do proxy inseguro"):
        helper.prepare_logs("vm")
    assert target.read_text() == "preserve"


def test_proxy_log_setup_adopts_legacy_proxy_owned_directory_safely(monkeypatch, tmp_path):
    helper = _helper_module()
    logdir = tmp_path / "logs"
    logdir.mkdir(mode=0o750)
    logdir.chmod(0o750)
    previous = logdir / "u1000-old.cache.log"
    previous.write_text("preserve prior log contents\n")
    previous.chmod(0o640)
    monkeypatch.setattr(helper, "LOG", logdir)
    account = type("Account", (), {"pw_uid": os.getuid(), "pw_gid": os.getgid()})()
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: account)
    fchown_calls = []

    def capture_fchown(fd, uid, gid):
        fchown_calls.append((helper.stat.S_ISDIR(helper.os.fstat(fd).st_mode), uid, gid))

    monkeypatch.setattr(helper.os, "fchown", capture_fchown)
    helper.prepare_logs("new-vm")
    assert fchown_calls[0] == (True, 0, account.pw_gid)
    assert previous.read_text() == "preserve prior log contents\n"
    assert (logdir.stat().st_mode & 0o777) == 0o750
    assert (logdir / "new-vm.cache.log").stat().st_mode & 0o777 == 0o640
    assert (logdir / "new-vm.access.log").stat().st_mode & 0o777 == 0o640


def test_proxy_log_setup_rejects_directory_owned_by_unknown_user(monkeypatch, tmp_path):
    helper = _helper_module()
    logdir = tmp_path / "logs"
    logdir.mkdir(mode=0o750)
    monkeypatch.setattr(helper, "LOG", logdir)
    account = type("Account", (), {"pw_uid": os.getuid() + 1, "pw_gid": os.getgid()})()
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: account)
    monkeypatch.setattr(helper.os, "fchown", lambda *_args: pytest.fail("unknown owner must fail before chown"))
    with pytest.raises(helper.Error, match="diretório de logs do proxy inseguro"):
        helper.prepare_logs("vm")


def test_domain_proxy_rules_require_live_resolution_and_reject_any_non_global_answer():
    helper = _helper_module()
    config = helper.squid_config("u1000-locked-vm", "10.0.0.200", "10.0.0.1", 20200,
                                 [{"kind": "domain", "value": "github.com", "port": 443}])
    assert "acl destination_has_ipv4_address dst 0.0.0.0/0" in config
    assert "acl destination_has_ipv6_address dst ::/0" in config
    assert "acl non_global_destination dst " in config
    assert "acl destination_0 dstdomain -n github.com" in config
    assert f"tcp_outgoing_mark {helper.DOMAIN_EGRESS_MARK} vm_source destination_0" in config
    assert ("http_access allow vm_source destination_0 destination_port_0 "
            "destination_has_ipv4_address !destination_has_ipv6_address "
            "!non_global_destination") in config
    for address in ("127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                    "224.0.0.0/4", "240.0.0.0/4"):
        assert address in helper.NON_GLOBAL_DESTINATIONS


def test_squid_instances_get_distinct_alphanumeric_service_names():
    helper = _helper_module()
    first = helper.squid_service_name("u1000-locked-vm")
    second = helper.squid_service_name("u1000-other-vm")
    assert first.startswith("ivm") and first.isalnum()
    assert second.startswith("ivm") and second.isalnum()
    assert first != second
    assert helper.squid_service_name("u1000-locked-vm") == first
    with pytest.raises(helper.Error, match="identificador de serviço"):
        helper.squid_service_name("../../squid")


def test_proxy_readiness_requires_the_expected_default_deny_response(monkeypatch):
    from types import SimpleNamespace
    import io

    helper = _helper_module()
    requests = []

    class FakeConnection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def settimeout(self, _timeout): pass
        def sendall(self, payload): requests.append(payload)
        def makefile(self, *_args): return io.BytesIO(b"HTTP/1.1 403 Forbidden\r\n")

    monkeypatch.setattr(helper, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout="active"))
    monkeypatch.setattr(helper.socket, "create_connection", lambda *_args, **_kwargs: FakeConnection())
    helper.wait_for_proxy("u1000-locked-vm", "10.0.0.1", 20200)
    assert requests == [b"CONNECT isolatevm-healthcheck.invalid:443 HTTP/1.1\r\n"
                        b"Host: isolatevm-healthcheck.invalid:443\r\n"
                        b"Connection: close\r\n\r\n"]

    class WrongProxy(FakeConnection):
        def makefile(self, *_args): return io.BytesIO(b"HTTP/1.1 200 OK\r\n")

    monkeypatch.setattr(helper.socket, "create_connection", lambda *_args, **_kwargs: WrongProxy())
    with pytest.raises(helper.Error, match="negação padrão"):
        helper.wait_for_proxy("u1000-locked-vm", "10.0.0.1", 20200)


def test_squid_domain_acl_checks_public_private_mixed_and_rebound_answers(request):
    from pathlib import Path

    helper = _helper_module()
    squid = Path("/usr/sbin/squid")
    assert squid.is_file(), "install squid to run the restricted-domain ACL integration test"
    root = Path(tempfile.mkdtemp(prefix="isolatevm-squid-acl-", dir="/tmp"))
    request.addfinalizer(lambda: shutil.rmtree(root, ignore_errors=True))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        proxy_port = reservation.getsockname()[1]

    root.chmod(0o755)
    hosts = root / "hosts"
    hosts.write_text("8.8.8.8 target.example\n", encoding="ascii")
    hosts.chmod(0o644)
    config = root / "squid.conf"
    lines = helper.squid_config(
        "u1000-test", "10.0.0.200", "10.0.0.1", 20200,
        [{"kind": "domain", "value": "target.example", "port": 80}],
    ).splitlines()
    rewritten = []
    for line in lines:
        if line.startswith("http_port "):
            line = f"http_port 127.0.0.1:{proxy_port}"
        elif line.startswith("acl vm_source src "):
            line = "acl vm_source src 127.0.0.1"
        elif line.startswith("cache_log "):
            line = f"cache_log {root / 'squid.cache.log'}"
        elif line.startswith("access_log "):
            line = "access_log stdio:/dev/null"
        elif line == "pid_filename none":
            line = f"pid_filename {root / 'squid.pid'}"
        rewritten.append(line)
    config.write_text(
        f"hosts_file {hosts}\nconnect_timeout 1 seconds\n"
        "debug_options ALL,1 33,2 28,9\n" + "\n".join(rewritten) + "\n",
        encoding="utf-8",
    )
    config.chmod(0o644)
    service_name = helper.squid_service_name("u1000-test")
    parsed = subprocess.run([str(squid), "-n", service_name, "-k", "parse", "-f", str(config)],
                            capture_output=True, text=True, timeout=10, check=False)
    assert parsed.returncode == 0, parsed.stderr[-1000:]

    stderr_path = root / "squid.stderr"
    stderr_log = stderr_path.open("wb")
    process = subprocess.Popen([str(squid), "-n", service_name, "--foreground", "-N", "-f", str(config)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=stderr_log, close_fds=True)

    def startup_failure(phase: str) -> str:
        stderr_log.flush()
        stderr_detail = stderr_path.read_text(encoding="utf-8", errors="replace")[-1000:]
        cache_log_path = root / "squid.cache.log"
        cache_detail = (cache_log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                        if cache_log_path.exists() else "")
        detail = "\n".join(part for part in (stderr_detail, cache_detail) if part)
        suffix = f"\nSquid logs:\n{detail}" if detail else " (no log output)"
        return f"Squid exited during {phase} with status {process.returncode}{suffix}"

    def status_code() -> int:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
            client.settimeout(4)
            client.sendall(b"GET http://target.example/ HTTP/1.1\r\n"
                           b"Host: target.example\r\nConnection: close\r\n\r\n")
            first_line = client.recv(1024).split(b"\r\n", 1)[0]
        return int(first_line.split()[1])

    def rebind(answer: str) -> None:
        hosts.write_text(answer, encoding="ascii")
        result = subprocess.run([str(squid), "-n", service_name, "-k", "reconfigure", "-f", str(config)],
                                capture_output=True, text=True, timeout=5, check=False)
        assert result.returncode == 0, result.stderr[-1000:]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail(startup_failure("reconfigure"))
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        pytest.fail("Squid did not reopen the test listener after reconfigure")

    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail(startup_failure("startup"))
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("Squid did not start the test listener")

        # A public address passes the ACL; the network may still reject the
        # actual connection, so a Squid 503 is an allowed-policy result.
        code = status_code()
        cache_log = (root / "squid.cache.log").read_text(encoding="utf-8", errors="replace")
        assert code != 403, f"public destination denied with HTTP {code}; Squid cache log:\n{cache_log[-6000:]}"
        for answer in (
            "127.0.0.1 target.example\n",
            "10.2.3.4 target.example\n",
            "169.254.169.254 target.example\n",
            "8.8.8.8 target.example\n127.0.0.1 target.example\n",
        ):
            rebind(answer)
            assert status_code() == 403

        # The same running proxy must deny a request after its answer changes
        # from a public IP to loopback.
        rebind("8.8.8.8 target.example\n")
        assert status_code() != 403
        rebind("127.0.0.1 target.example\n")
        assert status_code() == 403
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        stderr_log.close()


def test_explicit_ip_and_cidr_proxy_rules_keep_their_explicit_destination_semantics():
    helper = _helper_module()
    config = helper.squid_config("u1000-locked-vm", "10.0.0.200", "10.0.0.1", 20200,
                                 [{"kind": "ip", "value": "127.0.0.1", "port": 8080},
                                  {"kind": "cidr", "value": "10.20.0.0/16", "port": 5432}])
    assert "acl non_global_destination" not in config
    assert "destination_has_ipv4_address" not in config
    assert "tcp_outgoing_mark" not in config
    assert "http_access allow vm_source destination_0 destination_port_0\n" in config
    assert "http_access allow vm_source destination_1 destination_port_1\n" in config


def test_domain_policy_adds_actual_destination_firewall_without_changing_explicit_ip_rules():
    helper = _helper_module()
    domain_config = helper.squid_config("u1000-vm", "10.0.0.200", "10.0.0.1", 20200,
                                        [{"kind": "domain", "value": "example.com", "port": 443}])
    assert f"tcp_outgoing_mark {helper.DOMAIN_EGRESS_MARK} vm_source destination_0" in domain_config
    domain_table = helper.render_nft({"u1000-vm": {
        "address": "10.0.0.200", "gateway": "10.0.0.1", "port": 20200,
        "mac": "02:00:00:00:00:01",
        "rules": [{"kind": "domain", "value": "example.com", "port": 443}],
    }})
    assert "table inet isolatevm_domain_egress" in domain_table
    assert f"meta mark {helper.DOMAIN_EGRESS_MARK} ip daddr 127.0.0.0/8 drop" in domain_table
    assert f"meta mark {helper.DOMAIN_EGRESS_MARK} ip daddr 100.64.0.0/10 drop" in domain_table
    assert f"meta mark {helper.DOMAIN_EGRESS_MARK} ip6 daddr ::/0 drop" in domain_table

    explicit_table = helper.render_nft({"u1000-vm": {
        "address": "10.0.0.200", "gateway": "10.0.0.1", "port": 20200,
        "mac": "02:00:00:00:00:01",
        "rules": [{"kind": "ip", "value": "127.0.0.1", "port": 8080}],
    }})
    assert "table inet isolatevm_domain_egress" not in explicit_table


def test_domain_firewall_tables_are_replaced_in_one_nft_transaction(monkeypatch):
    from types import SimpleNamespace

    helper = _helper_module()
    calls = []

    def run(*args, input_text=None, check=True):
        calls.append((args, input_text, check))
        return SimpleNamespace(returncode=0, stdout="table exists", stderr="")

    monkeypatch.setattr(helper, "run", run)
    helper.apply_nft({"u1000-vm": {
        "mac": "02:00:00:00:00:01", "address": "10.0.0.200", "gateway": "10.0.0.1",
        "port": 20200, "rules": [{"kind": "domain", "value": "example.com", "port": 443}],
    }})
    assert [call[0][1:5] for call in calls[:2]] == [
        ("list", "table", "bridge", "isolatevm_egress"),
        ("list", "table", "inet", "isolatevm_domain_egress"),
    ]
    payload = calls[2][1]
    assert payload.startswith("delete table bridge isolatevm_egress\ndelete table inet isolatevm_domain_egress\n")
    assert "table bridge isolatevm_egress" in payload
    assert "table inet isolatevm_domain_egress" in payload
    assert calls[2][0] == ("/usr/sbin/nft", "--check", "--file", "-")
    assert calls[3][0] == ("/usr/sbin/nft", "--file", "-")
    assert calls[3][1] == payload


def test_removing_last_domain_policy_deletes_both_firewall_tables_in_one_transaction(monkeypatch):
    from types import SimpleNamespace

    helper = _helper_module()
    calls = []

    def run(*args, input_text=None, check=True):
        calls.append((args, input_text, check))
        return SimpleNamespace(returncode=0, stdout="table exists", stderr="")

    monkeypatch.setattr(helper, "run", run)
    helper.apply_nft({})
    assert calls[2][1] == "delete table bridge isolatevm_egress\ndelete table inet isolatevm_domain_egress\n"
    assert calls[2][0] == ("/usr/sbin/nft", "--check", "--file", "-")
    assert calls[3][0] == ("/usr/sbin/nft", "--file", "-")
    assert calls[3][1] == calls[2][1]


@pytest.mark.parametrize("failed_stage", [
    "ensure_bridge_netfilter", "ensure_firewall_guard",
    "unit:stop", "unit:disable", "prepare_logs", "write_config", "save_state",
    "apply_nft", "unit:enable", "unit:restart", "wait_for_proxy",
])
def test_failed_policy_apply_leaves_proxy_stopped_and_disabled_for_retry(monkeypatch, failed_stage):
    helper = _helper_module()
    existing = {"bridge": "incusbr-1000", "network_mode": "restricted",
                "address": "10.0.0.200", "gateway": "10.0.0.1", "port": 20200,
                "mac": "02:00:00:00:00:01", "rules": [{"kind": "domain", "value": "github.com", "port": 443}],
                "owner_uid": 1000, "name": "locked-vm", "service_name": "u1000-locked-vm"}
    monkeypatch.setattr(helper, "bridge_info", lambda *_args: ("10.0.0.1", helper.ipaddress.ip_network("10.0.0.0/24")))
    monkeypatch.setattr(helper, "state", lambda: {"u1000-locked-vm": existing.copy()})
    monkeypatch.setattr(helper, "lease_addresses", lambda _bridge, _uid: set())
    monkeypatch.setattr(helper, "ensure_bridge_netfilter", lambda: None)
    monkeypatch.setattr(helper, "ensure_firewall_guard", lambda: None)
    events = []

    def stage(name):
        def run(*_args, **_kwargs):
            events.append(name)
            if name == failed_stage:
                raise helper.Error("injected failure")
        return run

    for name in ("ensure_bridge_netfilter", "ensure_firewall_guard", "prepare_logs",
                 "write_config", "save_state", "apply_nft", "wait_for_proxy"):
        monkeypatch.setattr(helper, name, stage(name))

    def unit(_service, action):
        name = f"unit:{action}"
        events.append(name)
        if name == failed_stage:
            raise helper.Error("injected failure")

    monkeypatch.setattr(helper, "unit", unit)
    with pytest.raises(helper.Error):
        helper.apply({"version": 1, "name": "locked-vm", "bridge": "incusbr-1000",
                      "network_mode": "restricted",
                      "rules": [{"kind": "domain", "value": "api.github.com", "port": 443}]}, 1000)
    assert events[-2:] == ["unit:stop", "unit:disable"]


def test_failed_first_policy_apply_removes_new_empty_boot_guard(monkeypatch):
    helper = _helper_module()
    monkeypatch.setattr(helper, "bridge_info", lambda *_args: ("10.0.0.1", helper.ipaddress.ip_network("10.0.0.0/24")))
    monkeypatch.setattr(helper, "state", lambda: {})
    monkeypatch.setattr(helper, "lease_addresses", lambda _bridge, _uid: set())
    monkeypatch.setattr(helper, "firewall_guard_preexisting", lambda: False)
    events = []
    monkeypatch.setattr(helper, "ensure_bridge_netfilter", lambda: events.append("br_netfilter"))
    monkeypatch.setattr(helper, "ensure_firewall_guard", lambda: events.append("install_guard"))
    monkeypatch.setattr(helper, "prepare_logs", lambda _name: (_ for _ in ()).throw(helper.Error("injected failure")))
    monkeypatch.setattr(helper, "unit", lambda _service, action: events.append(f"proxy:{action}"))
    monkeypatch.setattr(helper, "remove_firewall_guard", lambda: events.append("remove_guard"))
    with pytest.raises(helper.Error, match="injected failure"):
        helper.apply({"version": 1, "name": "locked-vm", "bridge": "incusbr-1000",
                      "network_mode": "restricted",
                      "rules": [{"kind": "domain", "value": "github.com", "port": 443}]}, 1000)
    assert events.count("remove_guard") == 1
    assert events.index("install_guard") < events.index("remove_guard")


def test_failed_policy_apply_keeps_boot_guard_when_persisted_state_remains(monkeypatch):
    helper = _helper_module()
    record = {"bridge": "incusbr-1000", "network_mode": "restricted",
              "address": "10.0.0.200", "gateway": "10.0.0.1", "port": 20200,
              "mac": "02:00:00:00:00:01", "rules": [{"kind": "domain", "value": "github.com", "port": 443}],
              "owner_uid": 1000, "name": "locked-vm", "service_name": "u1000-locked-vm"}
    current = {"u1000-locked-vm": record.copy()}
    monkeypatch.setattr(helper, "bridge_info", lambda *_args: ("10.0.0.1", helper.ipaddress.ip_network("10.0.0.0/24")))
    monkeypatch.setattr(helper, "state", lambda: dict(current))
    monkeypatch.setattr(helper, "lease_addresses", lambda _bridge, _uid: set())
    monkeypatch.setattr(helper, "firewall_guard_preexisting", lambda: False)
    monkeypatch.setattr(helper, "ensure_bridge_netfilter", lambda: None)
    monkeypatch.setattr(helper, "ensure_firewall_guard", lambda: None)
    monkeypatch.setattr(helper, "stop_disable_proxy", lambda _name: None)
    monkeypatch.setattr(helper, "prepare_logs", lambda _name: None)
    monkeypatch.setattr(helper, "write_config", lambda *_args: None)
    monkeypatch.setattr(helper, "save_state", lambda value: current.update(value))
    monkeypatch.setattr(helper, "apply_nft", lambda _data: (_ for _ in ()).throw(helper.Error("nft failure")))
    monkeypatch.setattr(helper, "unit", lambda *_args: None)
    monkeypatch.setattr(helper, "best_effort_stop_disable_proxy", lambda _name: None)
    removed = []
    monkeypatch.setattr(helper, "remove_firewall_guard", lambda: removed.append(True))
    with pytest.raises(helper.Error, match="nft failure"):
        helper.apply({"version": 1, "name": "locked-vm", "bridge": "incusbr-1000",
                      "network_mode": "restricted",
                      "rules": [{"kind": "domain", "value": "github.com", "port": 443}]}, 1000)
    assert current["u1000-locked-vm"]["name"] == record["name"]
    assert current["u1000-locked-vm"]["service_name"] == record["service_name"]
    assert removed == []


def test_failed_first_policy_apply_cleans_partial_state_when_vm_is_absent(monkeypatch, tmp_path):
    helper = _helper_module()
    current = {}
    removed_guard = []
    monkeypatch.setattr(helper, "bridge_info", lambda *_args: ("10.0.0.1", helper.ipaddress.ip_network("10.0.0.0/24")))
    monkeypatch.setattr(helper, "state", lambda: dict(current))
    monkeypatch.setattr(helper, "lease_addresses", lambda _bridge, _uid: set())
    monkeypatch.setattr(helper, "firewall_guard_preexisting", lambda: False)
    monkeypatch.setattr(helper, "instance_exists", lambda _name, _uid: False)
    monkeypatch.setattr(helper, "ensure_bridge_netfilter", lambda: None)
    monkeypatch.setattr(helper, "ensure_firewall_guard", lambda: None)
    monkeypatch.setattr(helper, "stop_disable_proxy", lambda _name: None)
    monkeypatch.setattr(helper, "prepare_logs", lambda _name: None)
    monkeypatch.setattr(helper, "write_config", lambda *_args: None)
    monkeypatch.setattr(helper, "save_state", lambda value: (current.clear(), current.update(value)))
    monkeypatch.setattr(helper, "apply_nft", lambda _data: None)
    monkeypatch.setattr(helper, "CONFIG", tmp_path / "config")
    monkeypatch.setattr(helper, "LOG", tmp_path / "logs")
    monkeypatch.setattr(helper, "unit", lambda _service, action: (_ for _ in ()).throw(helper.Error("restart failure"))
                        if action == "restart" else None)
    monkeypatch.setattr(helper, "best_effort_stop_disable_proxy", lambda _name: None)
    monkeypatch.setattr(helper, "remove_firewall_guard", lambda: removed_guard.append(True))
    with pytest.raises(helper.Error, match="restart failure"):
        helper.apply({"version": 1, "name": "locked-vm", "bridge": "incusbr-1000",
                      "network_mode": "restricted",
                      "rules": [{"kind": "domain", "value": "github.com", "port": 443}]}, 1000,
                     guard_preexisting_override=False)
    assert current == {}
    assert removed_guard == [True]


def test_egress_remove_preserves_policy_while_scoped_vm_still_exists(monkeypatch):
    helper = _helper_module()
    record = {"bridge": "incusbr-1000", "network_mode": "restricted",
              "address": "10.0.0.200", "gateway": "10.0.0.1", "port": 20200,
              "mac": "02:00:00:00:00:01", "rules": [{"kind": "domain", "value": "github.com", "port": 443}],
              "owner_uid": 1000, "name": "locked-vm", "service_name": "u1000-locked-vm"}
    monkeypatch.setattr(helper, "state", lambda: {"u1000-locked-vm": record})
    monkeypatch.setattr(helper, "instance_exists", lambda _name, _uid: True)
    stopped = []
    monkeypatch.setattr(helper, "stop_disable_proxy", lambda name: stopped.append(name))
    with pytest.raises(helper.Error, match="VM ainda existe"):
        helper.remove({"version": 1, "name": "locked-vm"}, 1000)
    assert stopped == []


def test_successful_policy_apply_disables_old_listener_until_firewall_is_replaced(monkeypatch):
    helper = _helper_module()
    existing = {"bridge": "incusbr-1000", "network_mode": "restricted",
                "address": "10.0.0.200", "gateway": "10.0.0.1", "port": 20200,
                "mac": "02:00:00:00:00:01", "rules": [{"kind": "domain", "value": "github.com", "port": 443}],
                "owner_uid": 1000, "name": "locked-vm", "service_name": "u1000-locked-vm"}
    monkeypatch.setattr(helper, "bridge_info", lambda *_args: ("10.0.0.1", helper.ipaddress.ip_network("10.0.0.0/24")))
    monkeypatch.setattr(helper, "state", lambda: {"u1000-locked-vm": existing.copy()})
    monkeypatch.setattr(helper, "lease_addresses", lambda _bridge, _uid: set())
    monkeypatch.setattr(helper, "ensure_bridge_netfilter", lambda: None)
    monkeypatch.setattr(helper, "ensure_firewall_guard", lambda: None)
    events = []
    monkeypatch.setattr(helper, "unit", lambda _service, action: events.append(f"unit:{action}"))
    monkeypatch.setattr(helper, "prepare_logs", lambda _service: events.append("logs"))
    monkeypatch.setattr(helper, "write_config", lambda *_args: events.append("config"))
    monkeypatch.setattr(helper, "save_state", lambda _data: events.append("state"))
    monkeypatch.setattr(helper, "apply_nft", lambda _data: events.append("firewall"))
    monkeypatch.setattr(helper, "wait_for_proxy", lambda *_args: events.append("listener"))
    helper.apply({"version": 1, "name": "locked-vm", "bridge": "incusbr-1000",
                  "network_mode": "restricted",
                  "rules": [{"kind": "domain", "value": "api.github.com", "port": 443}]}, 1000)
    assert events.index("unit:stop") < events.index("unit:disable") < events.index("logs")
    assert events.index("config") < events.index("state") < events.index("firewall")
    assert events.index("firewall") < events.index("unit:enable") < events.index("unit:restart")
