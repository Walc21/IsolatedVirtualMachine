"""Read-only before/after previews derived from effective Incus configuration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import Mount, ValidationError


@dataclass(frozen=True)
class ChangePreview:
    title: str
    before: tuple[str, ...]
    after: tuple[str, ...]
    note: str = ""

    def text(self) -> str:
        lines = [self.title, "", *("- " + item for item in self.before),
                 *("+ " + item for item in self.after)]
        if self.note:
            lines += ["", self.note]
        return "\n".join(lines)


def _rows(effective: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = effective.get(key)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValidationError("Configuração efetiva incompleta; revise a VM no Incus")
    return rows


def resources(effective: dict[str, Any], cpu: int, memory_mib: int) -> ChangePreview:
    expanded = effective.get("config")
    settings = expanded.get("config") if isinstance(expanded, dict) else None
    if not isinstance(settings, dict):
        raise ValidationError("Recursos efetivos indisponíveis")
    old_cpu = settings.get("limits.cpu")
    old_memory = settings.get("limits.memory")
    if not isinstance(old_cpu, str) or not isinstance(old_memory, str):
        raise ValidationError("CPU/RAM efetivas indisponíveis; não é seguro gerar um diff")
    if old_cpu == str(cpu) and old_memory == f"{memory_mib}MiB":
        raise ValidationError("CPU e RAM já possuem os valores escolhidos")
    return ChangePreview("RECURSOS", (f"CPU: {old_cpu}; RAM: {old_memory}",),
                         (f"CPU: {cpu}; RAM: {memory_mib}MiB",),
                         "A VM pode precisar reiniciar para refletir os novos limites.")


def mount_add(effective: dict[str, Any], mount: Mount) -> ChangePreview:
    rows = _rows(effective, "mounts") + _rows(effective, "volumes")
    guest = Path(mount.guest)
    if any(isinstance(item.get("path"), str) and item["path"].startswith("/") and
           (guest == Path(item["path"]) or guest in Path(item["path"]).parents or
            Path(item["path"]) in guest.parents) for item in rows):
        raise ValidationError("Destino se sobrepõe a um disco ou mount existente")
    return ChangePreview("MOUNTS", (f"{mount.guest}: sem mount do host",),
                         (f"{mount.host} → {mount.guest} [{mount.mode.upper()}]",),
                         "O acesso ao host permanece até a remoção do dispositivo. A VM pode precisar reiniciar.")


def mount_remove(effective: dict[str, Any], device: str) -> ChangePreview:
    item = next((item for item in _rows(effective, "mounts")
                 if item.get("device") == device and item.get("managed")), None)
    if item is None:
        raise ValidationError("Mount gerenciado não está mais presente; atualize a tela")
    return ChangePreview("MOUNTS", (f"{item['source']} → {item['path']} [{item['mode']}]",),
                         (f"{item['path']}: sem mount do host",),
                         "A remoção não apaga os arquivos do host. A VM pode precisar reiniciar.")


def network_block(effective: dict[str, Any]) -> ChangePreview:
    nics = _rows(effective, "nics")
    if not effective.get("can_block_network") or len(nics) != 1:
        raise ValidationError("A configuração efetiva não permite bloquear a NIC com segurança")
    nic = nics[0]
    return ChangePreview("REDE", (f"eth0: {nic.get('network', 'bridge desconhecida')}",),
                         ("eth0: removida; sem NIC Incus gerenciada",),
                         "Outros caminhos de rede no host ou no guest exigem inspeção separada.")


def network_restore(effective: dict[str, Any], bridge: str) -> ChangePreview:
    if _rows(effective, "nics"):
        raise ValidationError("A VM já possui NIC; atualize a tela")
    if effective.get("security_profile") == "maximum-isolation":
        raise ValidationError("Máximo isolamento impede restaurar uma NIC")
    note = ("A allowlist/proxy restrito será reaplicada pelo backend."
            if effective.get("security_profile") == "restricted-development" else
            "Rede normal não filtra domínios; a saída depende da bridge e do host.")
    return ChangePreview("REDE", ("eth0: ausente",), (f"eth0: bridge {bridge}",), note)


def device_add(effective: dict[str, Any], kind: str, description: str,
               identity: str) -> ChangePreview:
    if kind not in {"USB", "GPU"}:
        raise ValidationError("Tipo de dispositivo não suportado")
    if effective.get("security_profile") == "maximum-isolation":
        raise ValidationError("Máximo isolamento impede repassar dispositivos")
    count = sum(item.get("type") == kind.lower() and item.get("managed")
                for item in _rows(effective, "other_devices"))
    return ChangePreview("DISPOSITIVOS", (f"{kind} gerenciados: {count}",),
                         (f"{kind} gerenciados: {count + 1}",
                          f"{kind} {identity}: {description} disponível à VM"),
                         "O passthrough pode retirar o dispositivo do host ou afetar outros dispositivos equivalentes.")


def device_remove(effective: dict[str, Any], device: str) -> ChangePreview:
    item = next((item for item in _rows(effective, "other_devices")
                 if item.get("device") == device and item.get("managed")), None)
    if item is None:
        raise ValidationError("Dispositivo gerenciado não está mais presente; atualize a tela")
    expanded = effective.get("config")
    devices = expanded.get("devices") if isinstance(expanded, dict) else None
    config = devices.get(device) if isinstance(devices, dict) else None
    identity = ""
    if isinstance(config, dict):
        if item["type"] == "usb":
            identity = f" {config.get('vendorid', '?')}:{config.get('productid', '?')}"
            if config.get("serial"):
                identity += f" · serial {config['serial']}"
            elif config.get("busnum") is not None and config.get("devnum") is not None:
                identity += f" · bus {config['busnum']} device {config['devnum']}"
        elif item["type"] == "gpu":
            identity = f" PCI {config.get('pci', '?')}"
    return ChangePreview("DISPOSITIVOS", (f"{device}: {item['type']}{identity} anexado",),
                         (f"{device}: removido da configuração Incus",),
                         "A VM pode precisar reiniciar; o estado do dispositivo físico no host deve ser conferido.")
