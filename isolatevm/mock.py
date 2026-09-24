"""In-memory IncusService implementation for development and UI tests."""
from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Callable

from .incus import IncusError, ProvisioningStatus, VM
from .model import INITIAL_SNAPSHOT, Manifest, Mount, ValidationError, _integer, _name
from .metrics import MetricsSnapshot
from .permissions import describe_effective
from .usb import UsbDevice, host_usb_devices
from .gpu import GpuDevice, host_gpu_devices
from .workspace_volume import WORKSPACE_DEVICE, volume_name as workspace_volume_name


class MockIncus:
    """In-memory adapter for UI development; cannot affect host Incus."""
    def __init__(self) -> None:
        self.items: dict[str, tuple[Manifest, str]] = {}
        self.shots: dict[str, list[str]] = {}
        self.mount_state: dict[str, dict[str, Mount]] = {}
        self.network_state: dict[str, bool] = {}
        self.usb_state: dict[str, dict[str, UsbDevice]] = {}
        self.gpu_state: dict[str, dict[str, GpuDevice]] = {}
        self.secret_state: dict[str, set[str]] = {}
        self.copy_state: dict[str, str] = {}
        self.workspace_volumes: dict[str, dict[str, Any]] = {}

    def list_vms(self) -> list[VM]:
        return [VM(m.name, state, str(m.cpu), f"{m.memoryMiB}MiB", f"{m.diskGiB}GiB",
                   "—", f"Ubuntu {m.release}", len(self.mount_state.get(m.name, {})), len(self.shots.get(m.name, [])),
                   m.securityProfile,
                   "NIC presente · saída não verificada" if self.network_state.get(m.name) else "Sem NIC Incus · rede externa não verificada",
                   self.copy_state.get(m.name, "none"), m.lifecycleDisposition)
                for m, state in self.items.values()]

    def provisioning_status(self, name: str) -> ProvisioningStatus:
        if name not in self.items: raise IncusError("VM não encontrada")
        return ProvisioningStatus("simulado", None, 0)

    def pools(self) -> list[str]: return ["default"]
    def bridges(self) -> list[str]: return ["incusbr0"]

    def image_info(self, release: str) -> dict[str, str]:
        if release not in {"22.04", "24.04", "26.04"}: raise ValidationError("Versão Ubuntu não aceita")
        return {"alias": f"images:ubuntu/{release}/cloud", "fingerprint": "simulado",
                "architecture": "x86_64", "size": "simulado", "uploaded_at": "simulado"}

    def pool_space(self, pool: str) -> tuple[int, int] | None:
        if pool not in self.pools(): raise IncusError("Pool não encontrado")
        return 80 * 1024**3, 100 * 1024**3

    def preflight(self, manifest: Manifest) -> dict[str, str]:
        if manifest.name in self.items:
            raise IncusError("Já existe uma VM com esse nome")
        Manifest.parse(manifest.to_dict())
        if manifest.pool not in self.pools(): raise IncusError("Pool não encontrado")
        if manifest.networkMode in {"normal", "restricted"} and manifest.bridge not in self.bridges():
            raise IncusError("Bridge não encontrada")
        return self.image_info(manifest.release)

    def create(self, manifest: Manifest, progress: Callable[[str], None] | None = None) -> None:
        if progress: progress("Validando manifesto mock")
        self.preflight(manifest)
        self.items[manifest.name] = (manifest, "Stopped")
        self.mount_state[manifest.name] = {f"isovm{i}": mount for i, mount in enumerate(manifest.mounts)}
        self.network_state[manifest.name] = manifest.networkMode != "offline"
        self.copy_state[manifest.name] = "pending" if manifest.copies else "none"
        if manifest.lifecycleDisposition == "restore-initial-on-close":
            self.shots[manifest.name] = [INITIAL_SNAPSHOT]
        elif manifest.lifecycleDisposition == "persist-workspace":
            self.shots[manifest.name] = [INITIAL_SNAPSHOT]
            self.workspace_volumes[workspace_volume_name(manifest.name)] = {
                "owner": manifest.name, "sizeGiB": manifest.workspaceSizeGiB, "files": {}}
        if progress: progress("VM simulada criada e parada")

    def change_state(self, name: str, action: str) -> None:
        if name not in self.items or action not in {"start", "stop", "restart", "force-stop"}:
            raise IncusError("VM ou ação inválida")
        m, _ = self.items[name]
        self.items[name] = (m, "Stopped" if action in {"stop", "force-stop"} else "Running")

    def delete(self, name: str) -> None:
        if name not in self.items: raise IncusError("VM não encontrada")
        manifest, _ = self.items[name]
        if manifest.lifecycleDisposition == "persist-workspace":
            volume = workspace_volume_name(name)
            owned = self.workspace_volumes.get(volume)
            if not owned or owned.get("owner") != name:
                raise IncusError("Propriedade do volume /workspace não pôde ser confirmada")
            del self.workspace_volumes[volume]
        del self.items[name]
        self.shots.pop(name, None)
        self.mount_state.pop(name, None)
        self.network_state.pop(name, None)
        self.usb_state.pop(name, None)
        self.gpu_state.pop(name, None)
        self.copy_state.pop(name, None)

    def snapshots(self, name: str) -> list[str]: return self.shots.get(name, [])

    def snapshot(self, name: str, snapshot: str) -> None:
        if name not in self.items: raise IncusError("VM não encontrada")
        _name(snapshot, "Snapshot")
        if snapshot == INITIAL_SNAPSHOT:
            raise ValidationError("Esse nome é reservado ao snapshot inicial do ciclo descartável")
        self.shots.setdefault(name, []).append(snapshot)

    def restore_snapshot(self, name: str, snapshot: str) -> None:
        if snapshot not in self.snapshots(name): raise IncusError("Snapshot não encontrado")
        manifest, _ = self.items[name]
        self.items[name] = (manifest, "Stopped")

    def rename_snapshot(self, name: str, snapshot: str, replacement: str) -> None:
        if snapshot == INITIAL_SNAPSHOT:
            raise ValidationError("O snapshot inicial do ciclo descartável não pode ser renomeado")
        _name(name, "VM"); _name(snapshot, "Snapshot"); _name(replacement, "Novo snapshot")
        if snapshot not in self.snapshots(name): raise IncusError("Snapshot não encontrado")
        if replacement in self.snapshots(name): raise IncusError("Snapshot com esse nome já existe")
        self.shots[name][self.shots[name].index(snapshot)] = replacement

    def delete_snapshot(self, name: str, snapshot: str) -> None:
        if snapshot == INITIAL_SNAPSHOT:
            raise ValidationError("O snapshot inicial do ciclo descartável não pode ser excluído")
        if snapshot not in self.snapshots(name): raise IncusError("Snapshot não encontrado")
        self.shots[name].remove(snapshot)

    def clone(self, source: str, target: str) -> None:
        if source not in self.items or target in self.items: raise IncusError("Origem ou destino inválido")
        manifest, _ = self.items[source]
        data = manifest.to_dict(); data["name"] = _name(target, "Nova VM")
        if manifest.lifecycleDisposition != "persist-workspace":
            data.pop("lifecycle", None)
        self.create(Manifest.parse(data, check_copy_sources=False))
        if self.copy_state.get(source) == "done":
            self.copy_state[target] = "done"
        self.mount_state[target] = dict(self.mount_state.get(source, {}))
        self.network_state[target] = self.network_state[source]
        if manifest.lifecycleDisposition == "persist-workspace":
            source_volume = self.workspace_volumes.get(workspace_volume_name(source))
            if not source_volume or source_volume.get("owner") != source:
                self.delete(target)
                raise IncusError("Volume /workspace de origem não pôde ser confirmado")
            self.workspace_volumes[workspace_volume_name(target)]["files"] = dict(source_volume["files"])

    def effective(self, name: str) -> dict[str, Any]:
        if name not in self.items: raise IncusError("VM não encontrada")
        manifest, _ = self.items[name]
        devices = {key: {"type": "disk", "source": x.host, "path": x.guest,
                         "readonly": str(x.mode == "ro").lower()}
                   for key, x in self.mount_state.get(name, {}).items()}
        devices["root"] = {"type": "disk", "path": "/", "pool": manifest.pool,
                           "size": f"{manifest.diskGiB}GiB"}
        if manifest.lifecycleDisposition == "persist-workspace":
            devices[WORKSPACE_DEVICE] = {
                "type": "disk", "pool": manifest.pool,
                "source": workspace_volume_name(name), "path": "/workspace",
                "initial.uid": "1000", "initial.gid": "1000", "initial.mode": "0750"}
        if self.network_state[name]:
            devices["eth0"] = {"type": "nic", "network": manifest.bridge, "name": "eth0",
                               **({"security.ipv4_filtering": "true", "security.ipv6_filtering": "true"}
                                  if manifest.networkMode == "restricted" else {})}
        devices.update({slot: {"type": "usb", "vendorid": item.vendor_id, "productid": item.product_id,
                               **({"busnum": str(item.busnum), "devnum": str(item.devnum)}
                                  if item.busnum is not None and item.devnum is not None else {}),
                               **({"serial": item.serial} if item.serial else {}),
                               "required": "false"} for slot, item in self.usb_state.get(name, {}).items()})
        devices.update({slot: {"type": "gpu", "pci": item.pci, "vendorid": item.vendor_id,
                               "productid": item.product_id, "gputype": "physical"} for slot, item in self.gpu_state.get(name, {}).items()})
        config = {"type": "virtual-machine", "profiles": [],
                  "config": {"limits.cpu": str(manifest.cpu),
                             "limits.memory": f"{manifest.memoryMiB}MiB",
                             "user.isolatevm.managed": "true",
                             "user.isolatevm.security-profile": manifest.securityProfile,
                             "user.isolatevm.lifecycle-disposition": manifest.lifecycleDisposition,
                             "user.isolatevm.copy-state": self.copy_state.get(name, "none")},
                  "devices": devices}
        if manifest.lifecycleDisposition == "persist-workspace":
            config["config"]["user.isolatevm.workspace-volume"] = workspace_volume_name(name)
        summary = describe_effective(config, config)
        summary["config"] = config
        return summary

    def verify_managed_lifecycle(self, name: str, disposition: str,
                                 pool: str | None = None,
                                 workspace_size_gib: int | None = None) -> bool:
        item = self.items.get(name)
        if item is None or item[0].lifecycleDisposition != disposition:
            return False
        if disposition in {"delete-on-close", "restore-initial-on-close"}:
            return True
        if disposition != "persist-workspace":
            return False
        volume = self.workspace_volumes.get(workspace_volume_name(name))
        manifest = item[0]
        return bool(volume and volume.get("owner") == name and
                    (pool is None or pool == manifest.pool) and
                    (workspace_size_gib is None or workspace_size_gib == manifest.workspaceSizeGiB))

    def add_mount(self, name: str, mount: Mount) -> None:
        if name not in self.items: raise IncusError("VM não encontrada")
        if self.items[name][0].securityProfile == "maximum-isolation":
            raise ValidationError("Máximo isolamento impede compartilhar pastas do host")
        validated = Mount.parse({"host": mount.host, "guest": mount.guest, "mode": mount.mode})
        destination = Path(validated.guest)
        if any(destination == Path(copy.guest) or destination in Path(copy.guest).parents or
               Path(copy.guest) in destination.parents for copy in self.items[name][0].copies):
            raise ValidationError("Mount se sobrepõe ao destino de uma cópia única")
        current = self.effective(name)
        guest = Path(validated.guest)
        if any(guest == Path(x["path"]) or guest in Path(x["path"]).parents or
               Path(x["path"]) in guest.parents
               for x in current["mounts"] + current["volumes"]):
            raise ValidationError("Destino se sobrepõe a outro mount ou volume")
        owned = self.mount_state[name]
        device = next((f"isovm{i}" for i in range(100) if f"isovm{i}" not in owned), None)
        if not device: raise IncusError("Limite de mounts alcançado")
        owned[device] = validated

    def remove_mount(self, name: str, device: str) -> None:
        if name not in self.items: raise IncusError("VM não encontrada")
        if not device.startswith("isovm") or not device[5:].isdigit():
            raise ValidationError("Dispositivo inválido")
        if device not in self.mount_state[name]: raise ValidationError("Mount não encontrado")
        del self.mount_state[name][device]

    def host_usb_devices(self) -> list[UsbDevice]: return host_usb_devices()

    def add_usb_device(self, name: str, device: UsbDevice) -> None:
        if name not in self.items: raise IncusError("VM não encontrada")
        if self.items[name][0].securityProfile == "maximum-isolation":
            raise ValidationError("Máximo isolamento impede repassar dispositivos USB")
        owned = self.usb_state.setdefault(name, {})
        slot = next((f"isousb{i}" for i in range(32) if f"isousb{i}" not in owned), None)
        if slot is None: raise IncusError("Limite de dispositivos USB alcançado")
        owned[slot] = device

    def remove_usb_device(self, name: str, device: str) -> None:
        if name not in self.items or device not in self.usb_state.get(name, {}):
            raise ValidationError("Dispositivo USB gerenciado não encontrado")
        del self.usb_state[name][device]

    def host_gpu_devices(self) -> list[GpuDevice]: return host_gpu_devices()

    def add_gpu_device(self, name: str, device: GpuDevice) -> None:
        if name not in self.items: raise IncusError("VM não encontrada")
        if self.items[name][0].securityProfile == "maximum-isolation": raise ValidationError("Máximo isolamento impede repassar GPU")
        owned = self.gpu_state.setdefault(name, {}); slot = next((f"isogpu{i}" for i in range(8) if f"isogpu{i}" not in owned), None)
        if slot is None: raise IncusError("Limite de GPUs alcançado")
        owned[slot] = device

    def remove_gpu_device(self, name: str, device: str) -> None:
        if name not in self.items or device not in self.gpu_state.get(name, {}): raise ValidationError("GPU gerenciada não encontrada")
        del self.gpu_state[name][device]

    def block_network(self, name: str) -> None:
        if name not in self.items: raise IncusError("VM não encontrada")
        if self.items[name][0].networkMode == "offline": raise IncusError("VM originalmente offline")
        self.network_state[name] = False

    def restore_network(self, name: str, bridge: str) -> None:
        if name not in self.items or bridge not in self.bridges(): raise IncusError("VM ou bridge inválida")
        if self.items[name][0].securityProfile == "maximum-isolation":
            raise ValidationError("Máximo isolamento impede restaurar uma NIC")
        if self.items[name][0].bridge != bridge: raise ValidationError("Bridge não corresponde à política original")
        if self.network_state[name]: raise IncusError("Rede já ativa")
        self.network_state[name] = True

    def set_resources(self, name: str, cpu: int, memory_mib: int) -> None:
        if name not in self.items: raise IncusError("VM não encontrada")
        _integer(cpu, 1, 64, "CPU")
        _integer(memory_mib, 512, 262144, "RAM")
        manifest, state = self.items[name]
        data = manifest.to_dict()
        data["resources"]["cpu"] = cpu
        data["resources"]["memoryMiB"] = memory_mib
        self.items[name] = (Manifest.parse(data), state)

    def inject_secrets(self, name: str, retrieve: Callable[[tuple[str, ...]], dict[str, str]]) -> None:
        if name not in self.items:
            raise IncusError("VM não encontrada")
        manifest, state = self.items[name]
        if state != "Running":
            raise IncusError("Ligue a VM antes de usar secrets temporários")
        if not manifest.secrets or manifest.securityProfile == "maximum-isolation":
            raise ValidationError("Manifesto sem referências de secrets ou perfil incompatível")
        # Mock mode records names only and never asks the host vault for values.
        self.secret_state[name] = set(manifest.secrets)

    def clear_secrets(self, name: str) -> None:
        if name not in self.items or self.items[name][1] != "Running":
            raise IncusError("VM não encontrada ou parada")
        self.secret_state[name] = set()

    def apply_copies(self, name: str, progress: Callable[[str], None] | None = None) -> str:
        if name not in self.items or self.items[name][1] != "Running":
            raise IncusError("Ligue a VM antes de copiar arquivos")
        manifest = self.items[name][0]
        if not manifest.copies:
            raise ValidationError("Manifesto sem cópias declaradas")
        if self.copy_state.get(name) == "done":
            return "simulado"
        if self.copy_state.get(name) != "pending":
            raise ValidationError("Cópia não pendente")
        if progress: progress("Cópia única simulada, sem ler arquivos do host")
        self.copy_state[name] = "done"
        return "simulado"

    def terminal_argv(self, name: str) -> list[str]:
        raise IncusError("Terminal indisponível no modo mock")

    def guest_login_argv(self, name: str) -> list[str]:
        raise IncusError("Login gráfico indisponível no modo mock")

    def console_argv(self, name: str) -> list[str]:
        raise IncusError("Console VGA indisponível no modo mock")

    def export_full(self, name: str, destination: Path) -> None:
        raise IncusError("Backup completo indisponível no modo mock")

    def export_workspace(self, name: str, destination: Path) -> None:
        raise IncusError("Exportação de /workspace indisponível no modo mock")

    def metrics(self, name: str) -> MetricsSnapshot:
        if name not in self.items: raise IncusError("VM não encontrada")
        manifest, state = self.items[name]
        if state != "Running":
            return MetricsSnapshot(None, None, None, None, None, None, None, None)
        return MetricsSnapshot(int(time.monotonic() * 250_000_000), 1024**3,
                               manifest.memoryMiB * 1024**2, 2 * 1024**3,
                               manifest.diskGiB * 1024**3, 150_000, 75_000, 600)
