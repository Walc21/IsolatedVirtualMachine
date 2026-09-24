#!/usr/bin/python3
"""Root-only, Polkit-launched configurator for IsolateVM restricted egress.

It intentionally accepts only JSON on stdin and has no generic command or path
parameter.  Each VM gets one Squid listener and one source IP.  An nftables
bridge table then permits that source to reach only its listener and DHCP.
"""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time


NAME = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
ROOT = Path("/var/lib/isolatevm/egress")
CONFIG = Path("/etc/isolatevm/egress")
LOG = Path("/var/log/isolatevm/egress")
STATE = ROOT / "state.json"
LOCK = ROOT / ".lock"
FIREWALL_SERVICE = "isolatevm-egress-firewall.service"
INCUS_SERVICE_UNITS = ("incus.service", "snap.incus.daemon.service")
FIREWALL_DROPIN = "[Unit]\nRequires=isolatevm-egress-firewall.service\nAfter=isolatevm-egress-firewall.service\n"
MAX_REQUEST_BYTES = 64 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024


class Error(ValueError):
    pass


def run(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=input_text, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=45, check=False)
    if check and result.returncode:
        raise Error(result.stderr.strip().splitlines()[-1] if result.stderr.strip() else f"falhou: {args[0]}")
    return result


def run_limited(args: list[str], *, output_limit_bytes: int,
                timeout: int = 45) -> subprocess.CompletedProcess[str]:
    """Capture bounded output from local inventory commands such as Incus leases."""
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=False, bufsize=0)
    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout

    def stop_process() -> None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()

    try:
        for stream, target in ((process.stdout, stdout), (process.stderr, stderr)):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, target)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_process()
                raise Error("consulta local excedeu o tempo permitido")
            events = selector.select(remaining)
            if not events:
                stop_process()
                raise Error("consulta local excedeu o tempo permitido")
            for key, _ in events:
                remaining_output = output_limit_bytes + 1 - len(stdout) - len(stderr)
                chunk = os.read(key.fileobj.fileno(), min(65536, remaining_output))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                if len(stdout) + len(stderr) > output_limit_bytes:
                    stop_process()
                    raise Error("saída da consulta local excedeu o limite permitido")
        returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        stop_process()
        raise Error("consulta local excedeu o tempo permitido") from exc
    except OSError as exc:
        stop_process()
        raise Error("não foi possível executar a consulta local") from exc
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    return subprocess.CompletedProcess(args, returncode, stdout.decode("utf-8", "replace"),
                                        stderr.decode("utf-8", "replace"))


def require_root_and_uid() -> int:
    if os.geteuid() != 0:
        raise Error("helper exige root via Polkit")
    raw = os.environ.get("PKEXEC_UID", "")
    if not re.fullmatch(r"[0-9]{4,10}", raw) or not 1000 <= int(raw) <= 4_294_967_294:
        raise Error("origem Polkit inválida")
    return int(raw)


def require_systemd_root() -> None:
    if os.geteuid() != 0 or os.environ.get("PKEXEC_UID"):
        raise Error("restauração do firewall só pode ser chamada pelo systemd")


def scoped_name(uid: int, vm_name: str) -> str:
    if type(uid) is not int or not 1000 <= uid <= 4_294_967_294:
        raise Error("UID de usuário inválido")
    return f"u{uid}-{vm_name}"


def _legacy_owner(record: object) -> int | None:
    if not isinstance(record, dict):
        return None
    bridge = record.get("bridge")
    match = re.fullmatch(r"incusbr-([0-9]{4,10})", bridge) if isinstance(bridge, str) else None
    if not match:
        return None
    uid = int(match.group(1))
    return uid if 1000 <= uid <= 4_294_967_294 else None


def ensure_state_directory() -> None:
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o750)
    info = ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Error("diretório de estado inseguro; intervenção administrativa necessária")
    os.chmod(ROOT, 0o750)


def load_json() -> dict[str, object]:
    try:
        raw_bytes = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw_bytes) > MAX_REQUEST_BYTES:
            raise Error("pedido JSON excede o limite permitido")

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise Error("pedido JSON contém campos duplicados")
                result[key] = value
            return result

        raw = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError, RecursionError) as exc:
        raise Error("pedido JSON inválido") from exc
    if not isinstance(raw, dict) or type(raw.get("version")) is not int or raw.get("version") != 1:
        raise Error("versão de pedido inválida")
    return raw


def name(raw: object) -> str:
    if not isinstance(raw, str) or not NAME.fullmatch(raw):
        raise Error("nome de VM inválido")
    return raw


def rules(raw: object, network_mode: object) -> list[dict[str, object]]:
    if not isinstance(network_mode, str) or network_mode not in {"restricted", "lan-only"}:
        raise Error("modo de rede proxied inválido")
    if not isinstance(raw, list) or not raw or len(raw) > 32:
        raise Error("lista de regras inválida")
    output: list[dict[str, object]] = []
    seen: set[tuple[str, str, int]] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"kind", "value", "port"}:
            raise Error("regra de saída inválida")
        kind, value, port = item["kind"], item["value"], item["port"]
        if (not isinstance(kind, str) or kind not in {"domain", "ip", "cidr"} or
                not isinstance(value, str) or type(port) is not int or not 1 <= port <= 65535):
            raise Error("regra de saída inválida")
        if network_mode == "lan-only" and kind != "cidr":
            raise Error("LAN somente aceita CIDRs IPv4 RFC1918")
        if kind == "domain":
            value = value.lower().rstrip(".")
            if not DOMAIN.fullmatch(value): raise Error("domínio inválido")
        else:
            try:
                parsed = ipaddress.ip_network(value, strict=True) if kind == "cidr" else ipaddress.ip_address(value)
            except ValueError as exc:
                raise Error("IP ou CIDR inválido") from exc
            if parsed.version != 4: raise Error("somente IPv4 é suportado")
            if network_mode == "lan-only":
                private = tuple(ipaddress.ip_network(value) for value in
                                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
                if kind != "cidr" or not any(parsed.subnet_of(network) for network in private):
                    raise Error("LAN somente aceita CIDRs IPv4 RFC1918")
            value = str(parsed)
        key = (kind, value, port)
        if key in seen: raise Error("regra de saída duplicada")
        seen.add(key); output.append({"kind": kind, "value": value, "port": port})
    return output


def state() -> dict[str, dict[str, object]]:
    try:
        root_info = ROOT.lstat()
    except FileNotFoundError:
        return {}
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or
            root_info.st_mode & 0o022):
        raise Error("diretório de estado inseguro; intervenção administrativa necessária")
    fd = -1
    try:
        fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_STATE_BYTES):
            raise Error("arquivo de estado inseguro; intervenção administrativa necessária")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_STATE_BYTES + 1)
        if len(raw) > MAX_STATE_BYTES:
            raise Error("estado de rede excede o limite; intervenção administrativa necessária")
        data = json.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Error("estado de rede inválido; intervenção administrativa necessária") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(data, dict) or any(not isinstance(k, str) or not isinstance(v, dict) for k, v in data.items()):
        raise Error("estado de rede inválido; intervenção administrativa necessária")
    return data


def save_state(data: dict[str, dict[str, object]]) -> None:
    ensure_state_directory()
    fd, temporary = tempfile.mkstemp(prefix="state.", dir=ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, STATE)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def _write_root_file(target: Path, content: str, mode: int = 0o644) -> None:
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    parent_info = parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0 or
            parent_info.st_mode & 0o022):
        raise Error("diretório de configuração systemd inseguro")
    try:
        info = target.lstat()
    except FileNotFoundError:
        info = None
    if info is not None:
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o022):
            raise Error("arquivo de configuração systemd inseguro")
        if target.read_text(encoding="utf-8") != content:
            raise Error("arquivo de configuração systemd já existe com conteúdo diferente")
        return
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def ensure_firewall_guard() -> None:
    loaded: list[str] = []
    for service in INCUS_SERVICE_UNITS:
        result = run("/usr/bin/systemctl", "show", "--property=LoadState", "--value",
                     service, check=False)
        if result.returncode == 0 and result.stdout.strip() == "loaded":
            loaded.append(service)
    if not loaded:
        raise Error("serviço Incus não encontrado; firewall de boot não pode ser vinculado")
    for service in loaded:
        dropin = Path("/etc/systemd/system") / f"{service}.d" / "10-isolatevm-egress.conf"
        _write_root_file(dropin, FIREWALL_DROPIN)
    run("/usr/bin/systemctl", "daemon-reload")
    run("/usr/bin/systemctl", "enable", FIREWALL_SERVICE)


def remove_firewall_guard() -> None:
    run("/usr/bin/systemctl", "disable", "--now", FIREWALL_SERVICE, check=False)
    for service in INCUS_SERVICE_UNITS:
        dropin = Path("/etc/systemd/system") / f"{service}.d" / "10-isolatevm-egress.conf"
        try:
            info = dropin.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Error("drop-in do firewall de boot foi alterado; revisão administrativa necessária")
        if dropin.read_text(encoding="utf-8") != FIREWALL_DROPIN:
            raise Error("drop-in do firewall de boot foi alterado; revisão administrativa necessária")
        dropin.unlink()
        try:
            dropin.parent.rmdir()
        except OSError:
            pass
    run("/usr/bin/systemctl", "daemon-reload")


def bridge_info(bridge: str, uid: int) -> tuple[str, ipaddress.IPv4Network]:
    if bridge != f"incusbr-{uid}":
        raise Error("a bridge precisa pertencer ao usuário Polkit")
    result = run("/usr/sbin/ip", "-j", "-4", "addr", "show", "dev", bridge)
    try:
        rows = json.loads(result.stdout)
        addresses = rows[0]["addr_info"]
        record = next(x for x in addresses if x.get("family") == "inet" and isinstance(x.get("local"), str))
        gateway, prefix = record["local"], record["prefixlen"]
        network = ipaddress.ip_network(f"{gateway}/{prefix}", strict=False)
    except (IndexError, KeyError, StopIteration, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise Error("bridge sem IPv4 gerenciado") from exc
    if network.version != 4 or network.prefixlen > 24:
        raise Error("bridge precisa fornecer uma sub-rede IPv4 /24 ou maior")
    return gateway, network


def lease_addresses(bridge: str, uid: int) -> set[str]:
    addresses: set[str] = set()
    successes = 0
    for project in (f"user-{uid}", "default"):
        result = run_limited(["/usr/bin/incus", "--force-local", "--project", project,
                              "network", "list-leases", bridge, "--format", "json"],
                             output_limit_bytes=4_000_000)
        if result.returncode:
            continue
        successes += 1
        try:
            rows = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise Error("leases Incus inválidos") from exc
        if not isinstance(rows, list):
            raise Error("leases Incus inválidos")
        addresses.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", json.dumps(rows)))
    if not successes:
        raise Error("não foi possível consultar leases Incus nos projetos locais")
    return addresses


def choose_address(current: dict[str, object] | None, occupied: set[str], network: ipaddress.IPv4Network) -> tuple[str, int]:
    if current:
        address, port = current.get("address"), current.get("port")
        if isinstance(address, str) and type(port) is int:
            try:
                parsed = ipaddress.IPv4Address(address)
            except ipaddress.AddressValueError:
                raise Error("estado de VM restrita inválido") from None
            if (str(parsed) == address and parsed in network and
                    200 <= int(str(parsed).rsplit(".", 1)[1]) <= 254 and 20200 <= port <= 20254):
                return address, port
        raise Error("estado de VM restrita inválido")
    for last in range(200, 255):
        candidate = str(ipaddress.ip_address(int(network.network_address) + last))
        if ipaddress.ip_address(candidate) in network and candidate not in occupied:
            return candidate, 20000 + last
    raise Error("faixa reservada de IPs restritos esgotada")


def mac_for(uid: int, name_value: str) -> str:
    digest = hashlib.sha256(f"isolatevm-egress:{uid}:{name_value}".encode("ascii")).digest()
    return ":".join(["02", *(f"{byte:02x}" for byte in digest[:5])])


def squid_config(name_value: str, address: str, gateway: str, port: int, allow: list[dict[str, object]]) -> str:
    lines = [f"http_port {gateway}:{port}", f"acl vm_source src {address}"]
    for index, rule in enumerate(allow):
        kind, value, destination_port = rule["kind"], rule["value"], rule["port"]
        directive = "dstdomain" if kind == "domain" else "dst"
        lines += [f"acl destination_{index} {directive} {value}", f"acl destination_port_{index} port {destination_port}",
                  f"http_access allow vm_source destination_{index} destination_port_{index}"]
    lines += ["http_access deny vm_source", "http_access deny all", "cache deny all", "cache_effective_user proxy",
              f"cache_log stdio:{LOG / (name_value + '.cache.log')}",
              f"access_log stdio:{LOG / (name_value + '.access.log')}", "pid_filename none", "coredump_dir /tmp",
              f"visible_hostname isolatevm-{name_value}"]
    return "\n".join(lines) + "\n"


def write_config(name_value: str, content: str) -> None:
    CONFIG.mkdir(parents=True, exist_ok=True, mode=0o755)
    target = CONFIG / f"{name_value}.conf"
    fd, temporary = tempfile.mkstemp(prefix=f"{name_value}.", dir=CONFIG)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content); handle.flush(); os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        run("/usr/sbin/squid", "-k", "parse", "-f", temporary)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def prepare_logs(name_value: str) -> None:
    account = pwd.getpwnam("proxy")
    LOG.mkdir(parents=True, exist_ok=True, mode=0o750)
    info = LOG.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise Error("diretório de logs do proxy inseguro")
    # The proxy may write existing files but must not create or replace names
    # in this directory. This prevents a compromised proxy account from
    # planting symlinks that a later privileged apply would chown as root.
    os.chmod(LOG, 0o750)
    os.chown(LOG, 0, account.pw_gid)
    for suffix in (".cache.log", ".access.log"):
        target = LOG / f"{name_value}{suffix}"
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW |
                         getattr(os, "O_NONBLOCK", 0), 0o640)
        except OSError as exc:
            raise Error("arquivo de log do proxy inseguro") from exc
        try:
            file_info = os.fstat(fd)
            if (not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1 or
                    file_info.st_uid not in {0, account.pw_uid}):
                raise Error("arquivo de log do proxy inseguro")
            os.fchown(fd, account.pw_uid, account.pw_gid)
            os.fchmod(fd, 0o640)
        finally:
            os.close(fd)


def render_nft(data: dict[str, dict[str, object]]) -> str:
    lines = ["table bridge isolatevm_egress {", "  chain forward {", "    type filter hook forward priority filter; policy accept;"]
    safe_records: list[tuple[str, str, str, int]] = []
    for key, record in data.items():
        if not isinstance(key, str) or not isinstance(record, dict):
            raise Error("estado de firewall inválido")
        address, gateway, port, mac = (record.get("address"), record.get("gateway"),
                                       record.get("port"), record.get("mac"))
        try:
            parsed_address = ipaddress.IPv4Address(address)
            parsed_gateway = ipaddress.IPv4Address(gateway)
        except (ipaddress.AddressValueError, TypeError):
            raise Error("estado de firewall inválido") from None
        if (str(parsed_address) != address or str(parsed_gateway) != gateway or
                type(port) is not int or not 20000 <= port <= 20254 or
                not isinstance(mac, str) or not re.fullmatch(r"02(?::[0-9a-f]{2}){5}", mac)):
            raise Error("estado de firewall inválido")
        safe_records.append((mac, address, gateway, port))
    for mac, _address, _gateway, _port in safe_records:
        # ARP and DHCP broadcasts also get forwarded to peer VMs on a bridge.
        # Only host-bound packets are admitted by the input chain below.
        lines.append(f"    ether saddr {mac} drop")
    lines += ["  }", "  chain input {", "    type filter hook input priority filter; policy accept;"]
    for mac, address, gateway, port in safe_records:
        lines += [f"    ether saddr {mac} ether type arp accept",
                  f"    ether saddr {mac} udp dport 67 accept",
                  f"    ether saddr {mac} ip saddr {address} ip daddr {gateway} tcp dport {port} accept",
                  f"    ether saddr {mac} drop"]
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def apply_nft(data: dict[str, dict[str, object]]) -> None:
    if not data:
        run("/usr/sbin/nft", "delete", "table", "bridge", "isolatevm_egress", check=False)
        return
    payload = render_nft(data)
    current = run("/usr/sbin/nft", "list", "table", "bridge", "isolatevm_egress", check=False)
    if current.returncode == 0:
        # Delete and recreate the dedicated table in one nftables batch. nft
        # applies the batch transactionally, so a failed update retains the
        # previous filter instead of opening a direct-egress window.
        payload = "delete table bridge isolatevm_egress\n" + payload
    run("/usr/sbin/nft", "--check", "--file", "-", input_text=payload)
    run("/usr/sbin/nft", "--file", "-", input_text=payload)


def ensure_bridge_netfilter() -> None:
    """Incus needs this module before it accepts bridged IPv4/IPv6 filtering."""
    run("/usr/sbin/modprobe", "br_netfilter")
    marker = Path("/etc/modules-load.d/isolatevm-br-netfilter.conf")
    _write_root_file(marker, "# Required for Incus restricted-egress NIC source filtering.\nbr_netfilter\n")
    if not Path("/proc/sys/net/bridge/bridge-nf-call-iptables").is_file():
        raise Error("br_netfilter não disponibilizou os filtros de bridge necessários")


def unit(name_value: str, action: str) -> None:
    run("/usr/bin/systemctl", action, f"isolatevm-egress@{name_value}.service")


def firewall_service(action: str) -> None:
    run("/usr/bin/systemctl", action, FIREWALL_SERVICE)


def restore_firewall() -> None:
    ensure_bridge_netfilter()
    apply_nft(state())


def apply(request: dict[str, object], uid: int) -> dict[str, object]:
    if set(request) != {"version", "name", "bridge", "network_mode", "rules"}: raise Error("campos de pedido inválidos")
    name_value, bridge = name(request["name"]), request["bridge"]
    network_mode = request["network_mode"]
    allow = rules(request["rules"], network_mode)
    if not isinstance(bridge, str) or not NAME.fullmatch(bridge): raise Error("bridge inválida")
    gateway, network = bridge_info(bridge, uid)
    data = state()
    key = scoped_name(uid, name_value)
    existing = data.get(key)
    service_name = key
    legacy = False
    if existing is None and name_value in data:
        possible_legacy = data[name_value]
        if _legacy_owner(possible_legacy) == uid:
            existing = possible_legacy
            service_name = name_value
            legacy = True
    if existing:
        if existing.get("bridge") != bridge:
            raise Error("VM já está vinculada a outra bridge")
        recorded_uid = existing.get("owner_uid", _legacy_owner(existing))
        recorded_name = existing.get("name", name_value if legacy else None)
        if recorded_uid != uid or recorded_name != name_value:
            raise Error("política restrita pertence a outra VM ou usuário")
    occupied = lease_addresses(bridge, uid) | {str(x.get("address")) for x in data.values() if isinstance(x.get("address"), str)}
    address, port = choose_address(existing, occupied, network)
    old_mac = existing.get("mac") if existing else None
    if old_mac is not None:
        if not isinstance(old_mac, str) or not re.fullmatch(r"02(?::[0-9a-f]{2}){5}", old_mac):
            raise Error("estado de MAC da VM restrita inválido")
        mac = old_mac
    else:
        mac = mac_for(uid, name_value)
    record: dict[str, object] = {"bridge": bridge, "network_mode": network_mode,
                                 "address": address, "gateway": gateway, "port": port,
                                 "mac": mac, "rules": allow, "owner_uid": uid,
                                 "name": name_value, "service_name": service_name}
    ensure_bridge_netfilter()
    ensure_firewall_guard()
    if existing:
        # Stop the old listener before replacing its policy. Otherwise a VM
        # could keep using the previous, broader Squid ACL during the firewall
        # update/restart window.
        unit(service_name, "stop")
    prepare_logs(service_name)
    write_config(service_name, squid_config(service_name, address, gateway, port, allow))
    if legacy:
        del data[name_value]
    data[key] = record
    save_state(data)
    apply_nft(data)
    unit(service_name, "enable")
    unit(service_name, "restart")
    return {"address": address, "gateway": gateway, "port": port, "mac": mac}


def remove(request: dict[str, object], uid: int) -> None:
    if set(request) != {"version", "name"}: raise Error("campos de pedido inválidos")
    name_value = name(request["name"])
    data = state()
    key = scoped_name(uid, name_value)
    record = data.get(key)
    state_key = key
    if record is None and name_value in data:
        possible_legacy = data[name_value]
        if _legacy_owner(possible_legacy) != uid:
            raise Error("política restrita pertence a outro usuário")
        record = possible_legacy
        state_key = name_value
    if record is None:
        return
    recorded_uid = record.get("owner_uid", _legacy_owner(record))
    recorded_name = record.get("name", name_value if state_key == name_value else None)
    if recorded_uid != uid or recorded_name != name_value:
        raise Error("política restrita pertence a outra VM ou usuário")
    service_name = record.get("service_name", state_key)
    if not isinstance(service_name, str) or not re.fullmatch(r"(?:u[0-9]+-)?[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", service_name):
        raise Error("identificador de serviço de rede inválido")
    unit(service_name, "stop")
    unit(service_name, "disable")
    target = CONFIG / f"{service_name}.conf"
    if target.exists(): target.unlink()
    for suffix in (".cache.log", ".access.log"):
        target_log = LOG / f"{service_name}{suffix}"
        if target_log.exists(): target_log.unlink()
    del data[state_key]
    save_state(data)
    apply_nft(data)
    if not data:
        remove_firewall_guard()


def main() -> int:
    try:
        command = sys.argv[1] if len(sys.argv) == 2 else ""
        if command == "restore-firewall":
            require_systemd_root()
            uid = None
            request = None
        elif command == "install-firewall-guard":
            require_systemd_root()
            uid = None
            request = None
        elif command in {"apply", "remove"}:
            uid = require_root_and_uid()
            request = load_json()
        else:
            raise Error("operação não suportada")
        ensure_state_directory()
        lock_fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        lock_info = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0 or lock_info.st_nlink != 1:
            os.close(lock_fd)
            raise Error("arquivo de bloqueio inseguro; intervenção administrativa necessária")
        os.fchmod(lock_fd, 0o600)
        with os.fdopen(lock_fd, "a+", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if command == "apply": print(json.dumps(apply(request, uid), separators=(",", ":")))
            elif command == "remove": remove(request, uid)
            elif command == "restore-firewall": restore_firewall()
            else:
                if state():
                    ensure_firewall_guard()
        return 0
    except (Error, OSError, subprocess.TimeoutExpired) as exc:
        print(f"isolatevm-egress-helper: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__": raise SystemExit(main())
