"""Typed client for the small Polkit-authorized restricted-egress helper."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

from .model import Manifest, PROXIED_NETWORK_MODES, ValidationError, _name


HELPER = Path("/usr/lib/isolatevm/isolatevm-egress-helper")


class EgressError(RuntimeError):
    pass


@dataclass(frozen=True)
class EgressRuntime:
    address: str
    gateway: str
    port: int
    mac: str

    @property
    def proxy_url(self) -> str:
        return f"http://{self.gateway}:{self.port}"


def request_for(manifest: Manifest) -> dict[str, object]:
    if manifest.networkMode not in PROXIED_NETWORK_MODES or not manifest.bridge:
        raise ValidationError("Ação de proxy exige uma rede restricted ou LAN-only válida")
    if manifest.bridge != f"incusbr-{os.getuid()}":
        raise ValidationError("Proxy restrito exige a bridge Incus de usuário incusbr-<UID>")
    return {"version": 1, "name": manifest.name, "bridge": manifest.bridge,
            "network_mode": manifest.networkMode,
            "rules": [{"kind": rule.kind, "value": rule.value, "port": rule.port}
                      for rule in manifest.egress]}


def _runtime(raw: object) -> EgressRuntime:
    if not isinstance(raw, dict) or set(raw) != {"address", "gateway", "port", "mac"}:
        raise EgressError("Resposta inválida do helper de rede")
    address, gateway, port, mac = raw["address"], raw["gateway"], raw["port"], raw["mac"]
    try:
        parsed_address = ipaddress.IPv4Address(address)
        parsed_gateway = ipaddress.IPv4Address(gateway)
    except (ipaddress.AddressValueError, TypeError):
        raise EgressError("Resposta inválida do helper de rede") from None
    if (str(parsed_address) != address or str(parsed_gateway) != gateway or type(port) is not int or
            not 20000 <= port <= 20254 or not isinstance(mac, str) or
            not re.fullmatch(r"02(?::[0-9a-f]{2}){5}", mac)):
        raise EgressError("Resposta inválida do helper de rede")
    return EgressRuntime(address, gateway, port, mac)


def apply(manifest: Manifest) -> EgressRuntime:
    helper = HELPER
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise EgressError("Helper de rede restrita não está instalado")
    payload = json.dumps(request_for(manifest), separators=(",", ":"))
    try:
        result = subprocess.run(["/usr/bin/pkexec", str(helper), "apply"], input=payload, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EgressError("Não foi possível autorizar a política de rede restrita") from exc
    if result.returncode:
        detail = result.stderr.strip().splitlines()[-1:] or ["autorização ou configuração recusada"]
        raise EgressError(f"Política de rede restrita não aplicada: {detail[0]}")
    try:
        return _runtime(json.loads(result.stdout))
    except (json.JSONDecodeError, EgressError) as exc:
        raise EgressError("Helper de rede retornou resultado inválido") from exc


def remove(name: str) -> None:
    name = _name(name, "VM")
    helper = HELPER
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise EgressError("Helper de rede restrita não está instalado")
    try:
        result = subprocess.run(["/usr/bin/pkexec", str(helper), "remove"], input=json.dumps({"version": 1, "name": name}),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EgressError("Não foi possível remover a política de rede restrita") from exc
    if result.returncode:
        detail = result.stderr.strip().splitlines()[-1:] or ["autorização ou configuração recusada"]
        raise EgressError(f"Política de rede restrita pendente: {detail[0]}")
