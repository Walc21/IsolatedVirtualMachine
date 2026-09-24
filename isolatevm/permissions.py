"""Interpret effective Incus devices without overstating isolation guarantees."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .workspace_volume import WORKSPACE_DEVICE


NETWORK_SAFE_DEVICE_TYPES = {"disk", "nic", "tpm", "none"}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def describe_effective(config: dict[str, Any], local: dict[str, Any]) -> dict[str, Any]:
    """Use expanded devices for visibility and local devices only for ownership."""
    devices = _mapping(config.get("devices"))
    local_devices = _mapping(local.get("devices"))
    local_settings = _mapping(local.get("config"))
    managed_instance = str(local_settings.get("user.isolatevm.managed", "")).lower() == "true" and not local.get("profiles")
    security_profile = str(local_settings.get("user.isolatevm.security-profile") or "externo/desconhecido")
    mounts: list[dict[str, Any]] = []
    volumes: list[dict[str, str]] = []
    nics: list[dict[str, str]] = []
    other_devices: list[dict[str, str]] = []
    possible_network_devices: list[str] = []
    warnings: list[str] = []
    managed_workspace_volume = False

    for name, raw in devices.items():
        if not isinstance(name, str) or not isinstance(raw, dict):
            warnings.append("Configuração de dispositivo Incus inesperada; revise o YAML expandido.")
            continue
        kind = str(raw.get("type", "desconhecido"))
        if kind == "disk":
            path = str(raw.get("path", ""))
            if path == "/": continue
            source = str(raw.get("source", ""))
            if Path(source).is_absolute():
                mounts.append({"device": name,
                               "managed": managed_instance and name.startswith("isovm") and name[5:].isdigit() and name in local_devices,
                               "source": source, "path": path or "?",
                               "mode": "RO" if str(raw.get("readonly", "false")).lower() == "true" else "RW"})
                if source in {"/", str(Path.home())} or any(part in {".ssh", ".gnupg", ".aws", ".kube", ".docker"} for part in Path(source).parts):
                    warnings.append(f"Mount amplo ou sensível detectado: {source}.")
            else:
                volumes.append({"device": name, "source": source or "não informado", "path": path or "?"})
                managed_workspace_volume = managed_workspace_volume or (
                    name == WORKSPACE_DEVICE and managed_instance and name in local_devices and
                    local_settings.get("user.isolatevm.lifecycle-disposition") == "persist-workspace" and
                    local_settings.get("user.isolatevm.workspace-volume") == source and
                    source and not Path(source).is_absolute() and path == "/workspace" and
                    raw.get("pool") == _mapping(local_devices.get(name)).get("pool"))
        elif kind == "nic":
            nics.append({"device": name, "network": str(raw.get("network") or raw.get("parent") or "não informada"),
                         "nictype": str(raw.get("nictype") or "não informado")})
        else:
            other = {"device": name, "type": kind,
                     "managed": managed_instance and ((kind == "usb" and name.startswith("isousb") and name[6:].isdigit()) or (kind == "gpu" and name.startswith("isogpu") and name[6:].isdigit())) and name in local_devices}
            if kind == "usb":
                identity = f"{raw.get('vendorid', '?')}:{raw.get('productid', '?')}"
                if raw.get("serial"):
                    identity += f" · serial {raw['serial']}"
                elif raw.get("busnum") is not None and raw.get("devnum") is not None:
                    identity += f" · bus {raw['busnum']} device {raw['devnum']}"
                other["identity"] = identity
            elif kind == "gpu":
                other["identity"] = str(raw.get("pci", "PCI desconhecido"))
            other_devices.append(other)
            if kind not in NETWORK_SAFE_DEVICE_TYPES:
                possible_network_devices.append(f"{name} ({kind})")

    if nics and possible_network_devices:
        network = "Conectada por NIC e outros dispositivos; política de saída não verificada"
    elif nics:
        network = "Conectada por NIC; política de saída não verificada"
    elif possible_network_devices:
        network = "Sem NIC Incus, mas outros dispositivos podem fornecer rede"
    else:
        network = "Sem NIC ou proxy Incus detectado; verifique mounts e configuração externa"
    if possible_network_devices:
        warnings.append("Proxy, passthrough ou dispositivo não classificado pode criar acesso de rede fora de uma NIC Incus.")
    unexpected_volumes = [item for item in volumes
                          if not (managed_workspace_volume and item["device"] == WORKSPACE_DEVICE)]
    if security_profile == "maximum-isolation" and (mounts or unexpected_volumes or nics or any(x["type"] not in {"tpm", "none"} for x in other_devices)):
        warnings.append("Perfil Máximo isolamento diverge dos dispositivos efetivos; revise alterações externas.")
    expanded_settings = _mapping(config.get("config"))
    weak_keys = [key for key in expanded_settings if isinstance(key, str) and
                 (key.startswith("raw.") or key in {"security.privileged", "security.nesting"})]
    if weak_keys:
        warnings.append("Configurações avançadas presentes: " + ", ".join(sorted(weak_keys)) + ".")
    profiles = config.get("profiles")
    if not isinstance(profiles, list): profiles = []
    profiles = [x for x in profiles if isinstance(x, str)]
    can_block_network = managed_instance and len(nics) == 1 and nics[0]["device"] == "eth0" and not possible_network_devices
    return {"mounts": mounts, "volumes": volumes, "nics": nics,
            "other_devices": other_devices, "possible_network_devices": possible_network_devices,
            "network": network, "warnings": warnings, "profiles": profiles,
            "security_profile": security_profile, "can_block_network": can_block_network}
