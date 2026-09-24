"""Read-only before/after previews derived from effective Incus configuration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Any

from .cpu import format_cpu_set, parse_cpu_set
from .model import Mount, ValidationError


@dataclass(frozen=True)
class ChangePreview:
    title: str
    before: tuple[str, ...]
    after: tuple[str, ...]
    note: str = ""
    equivalent: tuple[tuple[str, ...], ...] = ()

    def text(self) -> str:
        lines = [self.title, "", *("- " + item for item in self.before),
                 *("+ " + item for item in self.after)]
        if self.note:
            lines += ["", self.note]
        if self.equivalent:
            lines += ["", "Comando Incus equivalente (informativo; não executado):"]
            lines.extend(shlex.join(("incus", *args)) for args in self.equivalent)
        return "\n".join(lines)


def _equivalent(*args: str) -> tuple[tuple[str, ...], ...]:
    return (args,)


def _next_slot(effective: dict[str, Any], prefix: str, limit: int) -> str:
    expanded = effective.get("config")
    devices = expanded.get("devices") if isinstance(expanded, dict) else None
    if not isinstance(devices, dict):
        raise ValidationError("Dispositivos efetivos indisponíveis para mostrar o comando equivalente")
    return next((f"{prefix}{index}" for index in range(limit)
                 if f"{prefix}{index}" not in devices), "")


def _rows(effective: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = effective.get(key)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValidationError("Configuração efetiva incompleta; revise a VM no Incus")
    return rows


def resources(effective: dict[str, Any], cpu: int, memory_mib: int,
              vm_name: str | None = None) -> ChangePreview:
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
                         "A VM pode precisar reiniciar para refletir os novos limites.",
                         _equivalent("config", "set", vm_name or "<VM>",
                                     f"limits.cpu={cpu}", f"limits.memory={memory_mib}MiB"))


def cpu_pin(effective: dict[str, Any], cpu_spec: str,
            vm_name: str | None = None) -> ChangePreview:
    expanded = effective.get("config")
    settings = expanded.get("config") if isinstance(expanded, dict) else None
    current = settings.get("limits.cpu") if isinstance(settings, dict) else None
    if not isinstance(current, str):
        raise ValidationError("CPU efetiva indisponível; não é seguro gerar um diff")
    normalized = format_cpu_set(parse_cpu_set(cpu_spec))
    if current == normalized:
        raise ValidationError("A VM já usa esse pinning de CPU")
    return ChangePreview("PINNING DE CPU", (f"limits.cpu: {current} · alocação dinâmica ou pinning atual",),
                         (f"limits.cpu: {normalized} · threads lógicas do host selecionadas",),
                         "A VM deve estar parada. Pinning não reserva essas CPUs exclusivamente; o Incus pode compartilhar threads com outras cargas.",
                         _equivalent("config", "set", vm_name or "<VM>",
                                     f"limits.cpu={normalized}"))


def root_disk_grow(effective: dict[str, Any], size_gib: int,
                   vm_name: str | None = None) -> ChangePreview:
    expanded = effective.get("config")
    devices = expanded.get("devices") if isinstance(expanded, dict) else None
    root = devices.get("root") if isinstance(devices, dict) else None
    if not isinstance(root, dict) or root.get("type") != "disk" or root.get("path") != "/":
        raise ValidationError("Disco raiz efetivo indisponível; atualize a configuração da VM")
    current = root.get("size")
    match = re.fullmatch(r"([1-9][0-9]{0,3})GiB", current) if isinstance(current, str) else None
    if match is None:
        raise ValidationError("Tamanho atual do disco raiz não está em GiB inteiros")
    if type(size_gib) is not int or not 8 <= size_gib <= 2048:
        raise ValidationError("Disco: esperado inteiro entre 8 e 2048 GiB")
    old = int(match.group(1))
    if size_gib <= old:
        raise ValidationError("O disco pode apenas ser aumentado e o novo tamanho deve ser maior")
    return ChangePreview("DISCO RAIZ", (f"root: {old} GiB",), (f"root: {size_gib} GiB",),
                         "A operação só aumenta o disco e não pode ser desfeita por redução. A VM deve estar parada. "
                         "A partição e o sistema de arquivos do guest podem exigir expansão após o próximo boot.",
                         _equivalent("config", "device", "set", vm_name or "<VM>", "root",
                                     f"size={size_gib}GiB"))


def data_volume_add(effective: dict[str, Any], pool: str, volume: str, size_gib: int,
                    guest_path: str, readonly: bool, vm_name: str | None = None) -> ChangePreview:
    for current in _rows(effective, "mounts") + _rows(effective, "volumes"):
        existing = current.get("path")
        if not isinstance(existing, str) or not existing.startswith("/"):
            continue
        old, new = Path(existing), Path(guest_path)
        if old == new or old in new.parents or new in old.parents:
            raise ValidationError(f"Volume de dados: destino {guest_path} se sobrepõe a {existing}")
    slot = _next_slot(effective, "isodata", 32)
    if not slot:
        raise ValidationError("Limite de 32 discos de dados gerenciados alcançado")
    display = f"{volume} · {size_gib} GiB · {pool} → {guest_path} · {'RO' if readonly else 'RW'}"
    owner = vm_name or "<VM>"
    create = ("storage", "volume", "create", pool, volume, f"size={size_gib}GiB",
              "user.isolatevm.managed=true", f"user.isolatevm.owner={owner}",
              f"user.isolatevm.size-gib={size_gib}", "user.isolatevm.kind=data")
    attach = ("config", "device", "add", vm_name or "<VM>", slot, "disk",
              f"pool={pool}", f"source={volume}", f"path={guest_path}",
              f"readonly={'true' if readonly else 'false'}")
    return ChangePreview("DISCO DE DADOS", (f"{guest_path}: sem volume de dados",), (display,),
                         "Será criado um volume customizado Incus e anexado à VM parada. Ele é separado do disco raiz e pode não estar incluído em snapshots ou backups da VM.",
                         (create, attach))


def data_volume_remove(effective: dict[str, Any], device: str,
                       vm_name: str | None = None) -> ChangePreview:
    item = next((row for row in _rows(effective, "volumes")
                 if row.get("device") == device), None)
    if item is None or not re.fullmatch(r"isodata(?:[0-9]|[12][0-9]|3[01])", device):
        raise ValidationError("Disco de dados gerenciado não está mais presente; atualize a tela")
    expanded = effective.get("config")
    devices = expanded.get("devices") if isinstance(expanded, dict) else None
    raw = devices.get(device) if isinstance(devices, dict) else None
    if not isinstance(raw, dict) or raw.get("type") != "disk":
        raise ValidationError("Configuração efetiva do disco de dados indisponível")
    pool, volume = raw.get("pool"), raw.get("source")
    if not isinstance(pool, str) or not isinstance(volume, str):
        raise ValidationError("Pool ou volume do disco de dados não pôde ser confirmado")
    return ChangePreview("EXCLUIR DISCO DE DADOS",
                         (f"{pool}/{volume} → {item.get('path', '?')} anexado",),
                         (f"{pool}/{volume}: removido definitivamente",),
                         "A VM deve estar parada. Os dados do volume customizado serão excluídos depois que a desconexão for confirmada; isso não remove nem altera o disco raiz.",
                         (_equivalent("config", "device", "remove", vm_name or "<VM>", device)[0],
                          _equivalent("storage", "volume", "delete", pool, volume)[0]))


def mount_add(effective: dict[str, Any], mount: Mount,
              vm_name: str | None = None) -> ChangePreview:
    rows = _rows(effective, "mounts") + _rows(effective, "volumes")
    guest = Path(mount.guest)
    if any(isinstance(item.get("path"), str) and item["path"].startswith("/") and
           (guest == Path(item["path"]) or guest in Path(item["path"]).parents or
            Path(item["path"]) in guest.parents) for item in rows):
        raise ValidationError("Destino se sobrepõe a um disco ou mount existente")
    slot = _next_slot(effective, "isovm", 100)
    if not slot:
        raise ValidationError("Limite de mounts gerenciados alcançado")
    return ChangePreview("MOUNTS", (f"{mount.guest}: sem mount do host",),
                         (f"{mount.host} → {mount.guest} [{mount.mode.upper()}]",),
                         "O acesso ao host permanece até a remoção do dispositivo. A VM pode precisar reiniciar.",
                         _equivalent("config", "device", "add", vm_name or "<VM>", slot, "disk",
                                     f"source={mount.host}", f"path={mount.guest}",
                                     f"readonly={'true' if mount.mode == 'ro' else 'false'}"))


def mount_remove(effective: dict[str, Any], device: str,
                 vm_name: str | None = None) -> ChangePreview:
    item = next((item for item in _rows(effective, "mounts")
                 if item.get("device") == device and item.get("managed")), None)
    if item is None:
        raise ValidationError("Mount gerenciado não está mais presente; atualize a tela")
    return ChangePreview("MOUNTS", (f"{item['source']} → {item['path']} [{item['mode']}]",),
                         (f"{item['path']}: sem mount do host",),
                         "A remoção não apaga os arquivos do host. A VM pode precisar reiniciar.",
                         _equivalent("config", "device", "remove", vm_name or "<VM>", device))


def network_block(effective: dict[str, Any], vm_name: str | None = None) -> ChangePreview:
    nics = _rows(effective, "nics")
    if not effective.get("can_block_network") or len(nics) != 1:
        raise ValidationError("A configuração efetiva não permite bloquear a NIC com segurança")
    nic = nics[0]
    return ChangePreview("REDE", (f"eth0: {nic.get('network', 'bridge desconhecida')}",),
                         ("eth0: removida; sem NIC Incus gerenciada",),
                         "Outros caminhos de rede no host ou no guest exigem inspeção separada.",
                         _equivalent("config", "device", "remove", vm_name or "<VM>", "eth0"))


def network_restore(effective: dict[str, Any], bridge: str,
                    vm_name: str | None = None) -> ChangePreview:
    if _rows(effective, "nics"):
        raise ValidationError("A VM já possui NIC; atualize a tela")
    if effective.get("security_profile") == "maximum-isolation":
        raise ValidationError("Máximo isolamento impede restaurar uma NIC")
    note = ("A allowlist/proxy restrito será reaplicada pelo backend."
            if effective.get("security_profile") == "restricted-development" else
            "Rede normal não filtra domínios; a saída depende da bridge e do host.")
    return ChangePreview("REDE", ("eth0: ausente",), (f"eth0: bridge {bridge}",), note,
                         _equivalent("config", "device", "add", vm_name or "<VM>",
                                     "eth0", "nic", f"network={bridge}", "name=eth0"))


def device_add(effective: dict[str, Any], kind: str, description: str,
               identity: str, vm_name: str | None = None,
               attributes: tuple[str, ...] = ()) -> ChangePreview:
    if kind not in {"USB", "GPU", "PCI"}:
        raise ValidationError("Tipo de dispositivo não suportado")
    if effective.get("security_profile") == "maximum-isolation":
        raise ValidationError("Máximo isolamento impede repassar dispositivos")
    count = sum(item.get("type") == kind.lower() and item.get("managed")
                for item in _rows(effective, "other_devices"))
    operation: tuple[tuple[str, ...], ...] = ()
    if attributes:
        prefix, limit, device_type = {
            "USB": ("isousb", 32, "usb"),
            "GPU": ("isogpu", 8, "gpu"),
            "PCI": ("isopci", 8, "pci"),
        }[kind]
        slot = _next_slot(effective, prefix, limit)
        if not slot:
            raise ValidationError(f"Limite de dispositivos {kind} gerenciados alcançado")
        operation = _equivalent("config", "device", "add", vm_name or "<VM>",
                                slot, device_type, *attributes)
    return ChangePreview("DISPOSITIVOS", (f"{kind} gerenciados: {count}",),
                         (f"{kind} gerenciados: {count + 1}",
                          f"{kind} {identity}: {description} disponível à VM"),
                         ("PCI bruto exige VM desligada e autorização do projeto Incus; ele pode retirar o dispositivo do host. "
                          "IOMMU, firmware e estado do host determinam se o passthrough funciona com segurança."
                          if kind == "PCI" else
                          "O passthrough pode retirar o dispositivo do host ou afetar outros dispositivos equivalentes."),
                         operation)


def device_remove(effective: dict[str, Any], device: str,
                  vm_name: str | None = None) -> ChangePreview:
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
        elif item["type"] == "pci":
            identity = f" endereço {config.get('address', '?')}"
    return ChangePreview("DISPOSITIVOS", (f"{device}: {item['type']}{identity} anexado",),
                         (f"{device}: removido da configuração Incus",),
                         "A VM pode precisar reiniciar; o estado do dispositivo físico no host deve ser conferido.",
                         _equivalent("config", "device", "remove", vm_name or "<VM>", device))
