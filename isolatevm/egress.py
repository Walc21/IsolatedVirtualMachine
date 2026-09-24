"""Typed client for the small Polkit-authorized restricted-egress helper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess

from .model import Manifest, ValidationError


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
    if manifest.networkMode != "restricted" or not manifest.bridge:
        raise ValidationError("Ação de proxy exige uma rede restricted válida")
    return {"version": 1, "name": manifest.name, "bridge": manifest.bridge,
            "rules": [{"kind": rule.kind, "value": rule.value, "port": rule.port}
                      for rule in manifest.egress]}


def _runtime(raw: object) -> EgressRuntime:
    if not isinstance(raw, dict) or set(raw) != {"address", "gateway", "port", "mac"}:
        raise EgressError("Resposta inválida do helper de rede")
    address, gateway, port, mac = raw["address"], raw["gateway"], raw["port"], raw["mac"]
    if (not isinstance(address, str) or not isinstance(gateway, str) or type(port) is not int or
            not 20000 <= port <= 20254 or not isinstance(mac, str) or
            len(mac.split(":")) != 6 or any(len(part) != 2 or any(c not in "0123456789abcdef" for c in part) for part in mac.split(":"))):
        raise EgressError("Resposta inválida do helper de rede")
    return EgressRuntime(address, gateway, port, mac)


def apply(manifest: Manifest) -> EgressRuntime:
    helper = Path(os.environ.get("ISOLATEVM_EGRESS_HELPER", HELPER))
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise EgressError("Helper de rede restrita não está instalado")
    payload = json.dumps(request_for(manifest), separators=(",", ":"))
    try:
        result = subprocess.run(["pkexec", str(helper), "apply"], input=payload, text=True,
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
    if not isinstance(name, str) or not name:
        raise ValidationError("Nome da VM inválido")
    helper = Path(os.environ.get("ISOLATEVM_EGRESS_HELPER", HELPER))
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise EgressError("Helper de rede restrita não está instalado")
    try:
        result = subprocess.run(["pkexec", str(helper), "remove"], input=json.dumps({"version": 1, "name": name}),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EgressError("Não foi possível remover a política de rede restrita") from exc
    if result.returncode:
        detail = result.stderr.strip().splitlines()[-1:] or ["autorização ou configuração recusada"]
        raise EgressError(f"Política de rede restrita pendente: {detail[0]}")
