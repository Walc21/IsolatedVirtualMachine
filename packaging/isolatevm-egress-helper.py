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
import subprocess
import sys
import tempfile


NAME = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
ROOT = Path("/var/lib/isolatevm/egress")
CONFIG = Path("/etc/isolatevm/egress")
LOG = Path("/var/log/isolatevm/egress")
STATE = ROOT / "state.json"
LOCK = ROOT / ".lock"


class Error(ValueError):
    pass


def run(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=input_text, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=45, check=False)
    if check and result.returncode:
        raise Error(result.stderr.strip().splitlines()[-1] if result.stderr.strip() else f"falhou: {args[0]}")
    return result


def require_root_and_uid() -> int:
    if os.geteuid() != 0:
        raise Error("helper exige root via Polkit")
    raw = os.environ.get("PKEXEC_UID", "")
    if not raw.isdigit() or int(raw) < 1000:
        raise Error("origem Polkit inválida")
    return int(raw)


def load_json() -> dict[str, object]:
    try:
        raw = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        raise Error("pedido JSON inválido") from exc
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise Error("versão de pedido inválida")
    return raw


def name(raw: object) -> str:
    if not isinstance(raw, str) or not NAME.fullmatch(raw):
        raise Error("nome de VM inválido")
    return raw


def rules(raw: object) -> list[dict[str, object]]:
    if not isinstance(raw, list) or not raw or len(raw) > 32:
        raise Error("lista de regras inválida")
    output: list[dict[str, object]] = []
    seen: set[tuple[str, str, int]] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"kind", "value", "port"}:
            raise Error("regra de saída inválida")
        kind, value, port = item["kind"], item["value"], item["port"]
        if kind not in {"domain", "ip", "cidr"} or not isinstance(value, str) or type(port) is not int or not 1 <= port <= 65535:
            raise Error("regra de saída inválida")
        if kind == "domain":
            value = value.lower().rstrip(".")
            if not DOMAIN.fullmatch(value): raise Error("domínio inválido")
        else:
            try:
                parsed = ipaddress.ip_network(value, strict=False) if kind == "cidr" else ipaddress.ip_address(value)
            except ValueError as exc:
                raise Error("IP ou CIDR inválido") from exc
            if parsed.version != 4: raise Error("somente IPv4 é suportado")
            value = str(parsed)
        key = (kind, value, port)
        if key in seen: raise Error("regra de saída duplicada")
        seen.add(key); output.append({"kind": kind, "value": value, "port": port})
    return output


def state() -> dict[str, dict[str, object]]:
    try:
        data = json.loads(STATE.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise Error("estado de rede inválido; intervenção administrativa necessária") from exc
    if not isinstance(data, dict) or any(not isinstance(k, str) or not isinstance(v, dict) for k, v in data.items()):
        raise Error("estado de rede inválido; intervenção administrativa necessária")
    return data


def save_state(data: dict[str, dict[str, object]]) -> None:
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, temporary = tempfile.mkstemp(prefix="state.", dir=ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, STATE)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


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


def lease_addresses(bridge: str) -> set[str]:
    result = run("/usr/bin/incus", "network", "list-leases", bridge, "--format", "json", check=False)
    if result.returncode:
        raise Error("não foi possível consultar leases Incus")
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise Error("leases Incus inválidos") from exc
    return set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", json.dumps(rows)))


def choose_address(current: dict[str, object] | None, occupied: set[str], network: ipaddress.IPv4Network) -> tuple[str, int]:
    if current:
        address, port = current.get("address"), current.get("port")
        if isinstance(address, str) and type(port) is int:
            parsed = ipaddress.ip_address(address)
            if parsed in network and 200 <= int(str(parsed).rsplit(".", 1)[1]) <= 254 and 20200 <= port <= 20254:
                return address, port
        raise Error("estado de VM restrita inválido")
    for last in range(200, 255):
        candidate = str(ipaddress.ip_address(int(network.network_address) + last))
        if ipaddress.ip_address(candidate) in network and candidate not in occupied:
            return candidate, 20000 + last
    raise Error("faixa reservada de IPs restritos esgotada")


def mac_for(name_value: str) -> str:
    digest = hashlib.sha256(f"isolatevm-egress:{name_value}".encode("ascii")).digest()
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
    os.chown(LOG, account.pw_uid, account.pw_gid)
    for suffix in (".cache.log", ".access.log"):
        target = LOG / f"{name_value}{suffix}"
        target.touch(exist_ok=True)
        os.chown(target, account.pw_uid, account.pw_gid)
        os.chmod(target, 0o640)


def render_nft(data: dict[str, dict[str, object]]) -> str:
    lines = ["table bridge isolatevm_egress {", "  chain forward {", "    type filter hook forward priority filter; policy accept;"]
    for record in data.values():
        lines += [f"    ether saddr {record['mac']} ether type arp accept",
                  f"    ether saddr {record['mac']} udp dport 67 accept",
                  f"    ether saddr {record['mac']} drop"]
    lines += ["  }", "  chain input {", "    type filter hook input priority filter; policy accept;"]
    for record in data.values():
        lines += [f"    ether saddr {record['mac']} ether type arp accept",
                  f"    ether saddr {record['mac']} udp dport 67 accept",
                  f"    ether saddr {record['mac']} ip saddr {record['address']} ip daddr {record['gateway']} tcp dport {record['port']} accept",
                  f"    ether saddr {record['mac']} drop"]
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def apply_nft(data: dict[str, dict[str, object]]) -> None:
    if not data:
        run("/usr/sbin/nft", "delete", "table", "bridge", "isolatevm_egress", check=False)
        return
    payload = render_nft(data)
    run("/usr/sbin/nft", "--check", "--file", "-", input_text=payload)
    run("/usr/sbin/nft", "delete", "table", "bridge", "isolatevm_egress", check=False)
    run("/usr/sbin/nft", "--file", "-", input_text=payload)


def ensure_bridge_netfilter() -> None:
    """Incus needs this module before it accepts bridged IPv4/IPv6 filtering."""
    run("/usr/sbin/modprobe", "br_netfilter")
    marker = Path("/etc/modules-load.d/isolatevm-br-netfilter.conf")
    marker.write_text("# Required for Incus restricted-egress NIC source filtering.\nbr_netfilter\n", encoding="utf-8")
    os.chmod(marker, 0o644)
    if not Path("/proc/sys/net/bridge/bridge-nf-call-iptables").is_file():
        raise Error("br_netfilter não disponibilizou os filtros de bridge necessários")


def unit(name_value: str, action: str) -> None:
    run("/usr/bin/systemctl", action, f"isolatevm-egress@{name_value}.service")


def apply(request: dict[str, object], uid: int) -> dict[str, object]:
    if set(request) != {"version", "name", "bridge", "rules"}: raise Error("campos de pedido inválidos")
    name_value, bridge, allow = name(request["name"]), request["bridge"], rules(request["rules"])
    if not isinstance(bridge, str) or not NAME.fullmatch(bridge): raise Error("bridge inválida")
    gateway, network = bridge_info(bridge, uid)
    data = state(); existing = data.get(name_value)
    if existing and existing.get("bridge") != bridge: raise Error("VM já está vinculada a outra bridge")
    occupied = lease_addresses(bridge) | {str(x.get("address")) for x in data.values() if isinstance(x.get("address"), str)}
    address, port = choose_address(existing, occupied, network)
    mac = mac_for(name_value)
    if existing and existing.get("mac") not in {None, mac}: raise Error("estado de MAC da VM restrita inválido")
    record: dict[str, object] = {"bridge": bridge, "address": address, "gateway": gateway, "port": port, "mac": mac, "rules": allow}
    prepare_logs(name_value)
    write_config(name_value, squid_config(name_value, address, gateway, port, allow))
    unit(name_value, "enable")
    unit(name_value, "restart")
    ensure_bridge_netfilter()
    data[name_value] = record
    save_state(data)
    apply_nft(data)
    return {"address": address, "gateway": gateway, "port": port, "mac": mac}


def remove(request: dict[str, object]) -> None:
    if set(request) != {"version", "name"}: raise Error("campos de pedido inválidos")
    name_value = name(request["name"])
    data = state()
    if name_value not in data: return
    unit(name_value, "stop")
    unit(name_value, "disable")
    target = CONFIG / f"{name_value}.conf"
    if target.exists(): target.unlink()
    for suffix in (".cache.log", ".access.log"):
        target_log = LOG / f"{name_value}{suffix}"
        if target_log.exists(): target_log.unlink()
    del data[name_value]
    save_state(data)
    apply_nft(data)


def main() -> int:
    try:
        uid = require_root_and_uid(); command = sys.argv[1] if len(sys.argv) == 2 else ""
        request = load_json()
        ROOT.mkdir(parents=True, exist_ok=True, mode=0o750)
        with open(LOCK, "a+", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if command == "apply": print(json.dumps(apply(request, uid), separators=(",", ":")))
            elif command == "remove": remove(request)
            else: raise Error("operação não suportada")
        return 0
    except (Error, OSError, subprocess.TimeoutExpired) as exc:
        print(f"isolatevm-egress-helper: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__": raise SystemExit(main())
