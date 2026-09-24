"""Typed Incus adapter. No shell, arbitrary command or automatic privilege escalation."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Protocol
from urllib.parse import unquote, urlsplit

import yaml

from .api import ApiError, IncusUnixApi
from .access import local_socket
from .egress import EgressError, apply as apply_egress, remove as remove_egress
from .model import Manifest, Mount, ValidationError, _integer, _name
from .metrics import MetricsSnapshot, parse_state
from .permissions import NETWORK_SAFE_DEVICE_TYPES, describe_effective
from .provision import cloud_config
from .storage import data_dir, load_instance_manifest, saved_network_bridge
from .usb import UsbDevice, host_usb_devices
from .gpu import GpuDevice, host_gpu_devices


class IncusError(RuntimeError):
    def __init__(self, message: str, technical: str | None = None) -> None:
        super().__init__(message)
        self.technical = technical


def _friendly_error(detail: str) -> str:
    lower = detail.lower()
    if "permission denied" in lower or "not authorized" in lower:
        return "Sem autorização para acessar o Incus local. Verifique o grupo e o projeto configurados."
    if "no space left" in lower or "not enough space" in lower:
        return "Espaço insuficiente no pool de armazenamento selecionado."
    if "already exists" in lower:
        return "Já existe um recurso com esse nome."
    if "not found" in lower or "doesn't exist" in lower:
        return "Recurso Incus não encontrado. Atualize o dashboard e tente novamente."
    if "not running" in lower:
        return "A VM precisa estar em execução para esta ação."
    return "A operação Incus falhou. Abra os detalhes técnicos para verificar a causa."


@dataclass(frozen=True)
class VM:
    name: str
    status: str
    cpu: str
    memory: str
    disk: str
    ip: str
    os: str
    mounts: int
    snapshots: int = 0
    security_profile: str = "externo/desconhecido"
    network_policy: str = "não verificada"


@dataclass(frozen=True)
class ProvisioningStatus:
    status: str
    stage: str | None
    error_count: int


class IncusService(Protocol):
    def list_vms(self) -> list[VM]: ...
    def pools(self) -> list[str]: ...
    def bridges(self) -> list[str]: ...
    def image_info(self, release: str) -> dict[str, str]: ...
    def preflight(self, manifest: Manifest) -> dict[str, str]: ...
    def pool_space(self, pool: str) -> tuple[int, int] | None: ...
    def create(self, manifest: Manifest, progress: Callable[[str], None] | None = None) -> None: ...
    def change_state(self, name: str, action: str) -> None: ...
    def delete(self, name: str) -> None: ...
    def snapshots(self, name: str) -> list[str]: ...
    def snapshot(self, name: str, snapshot: str) -> None: ...
    def rename_snapshot(self, name: str, snapshot: str, replacement: str) -> None: ...
    def restore_snapshot(self, name: str, snapshot: str) -> None: ...
    def delete_snapshot(self, name: str, snapshot: str) -> None: ...
    def clone(self, source: str, target: str) -> None: ...
    def effective(self, name: str) -> dict[str, Any]: ...
    def add_mount(self, name: str, mount: Mount) -> None: ...
    def remove_mount(self, name: str, device: str) -> None: ...
    def host_usb_devices(self) -> list[UsbDevice]: ...
    def add_usb_device(self, name: str, device: UsbDevice) -> None: ...
    def remove_usb_device(self, name: str, device: str) -> None: ...
    def host_gpu_devices(self) -> list[GpuDevice]: ...
    def add_gpu_device(self, name: str, device: GpuDevice) -> None: ...
    def remove_gpu_device(self, name: str, device: str) -> None: ...
    def block_network(self, name: str) -> None: ...
    def restore_network(self, name: str, bridge: str) -> None: ...
    def set_resources(self, name: str, cpu: int, memory_mib: int) -> None: ...
    def terminal_argv(self, name: str) -> list[str]: ...
    def guest_login_argv(self, name: str) -> list[str]: ...
    def console_argv(self, name: str) -> list[str]: ...
    def export_full(self, name: str, destination: Path) -> None: ...
    def metrics(self, name: str) -> MetricsSnapshot: ...
    def provisioning_status(self, name: str) -> ProvisioningStatus: ...


class LocalIncus:
    def __init__(self) -> None:
        binary = shutil.which("incus")
        if binary is None:
            raise IncusError("Incus não está instalado. Abra Diagnóstico do Host.")
        self.binary = str(Path(binary).resolve())
        socket_path, self.access_mode = local_socket()
        if socket_path is None:
            raise IncusError("Sem acesso ao socket Incus local. Abra Diagnóstico do Host.")
        self._confined_approved = self.access_mode != "confined"
        self.client_config_dir = data_dir() / "incus-client"
        self.client_config_dir.mkdir(mode=0o700, exist_ok=True)
        # The user socket can initialize Incus/create a user project on first
        # contact, so do not probe it before the operator approves connection.
        self.api: IncusUnixApi | None = None
        if self.access_mode == "admin":
            try:
                self.api = IncusUnixApi(socket_path)
                self.api.get("/1.0")
            except ApiError as exc:
                raise IncusError("Não foi possível acessar o socket Incus selecionado. Abra Diagnóstico do Host.", str(exc)) from exc

    def approve_confined_connection(self) -> None:
        self._confined_approved = True

    @property
    def confined_connection_pending(self) -> bool:
        return self.access_mode == "confined" and not self._confined_approved

    def _require_connection_approval(self) -> None:
        if getattr(self, "access_mode", "admin") == "confined" and not self._confined_approved:
            raise IncusError("Confirme a conexão ao socket de usuário antes de consultar ou alterar o Incus.")

    def _run(self, *args: str, timeout: int = 120, ok_returncodes: tuple[int, ...] = (0,)) -> str:
        # Only fixed operations call this private method. User data remains a single argv item.
        self._require_connection_approval()
        try:
            env = {**os.environ, "LC_ALL": "C", "INCUS_CONF": str(self.client_config_dir)}
            env.pop("INCUS_REMOTE", None)
            env.pop("INCUS_SOCKET", None)
            env.pop("INCUS_DIR", None)
            env.pop("INCUS_PROJECT", None)
            result = subprocess.run([self.binary, "--force-local", *args],
                                    check=False, text=True, capture_output=True,
                                    timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:
            raise IncusError("Operação Incus excedeu o tempo permitido") from exc
        if result.returncode not in ok_returncodes or (result.returncode and not result.stdout.strip()):
            detail = (result.stderr or result.stdout).strip()[:600]
            raise IncusError(_friendly_error(detail), detail or f"Incus retornou erro {result.returncode}")
        return result.stdout

    def provisioning_status(self, name: str) -> ProvisioningStatus:
        _name(name, "VM")
        output = self._run("exec", name, "--", "cloud-init", "status", "--format=json",
                           timeout=30, ok_returncodes=(0, 1, 2))
        try:
            payload = json.loads(output)
        except ValueError as exc:
            raise IncusError("Estado cloud-init inválido recebido do guest") from exc
        if not isinstance(payload, dict):
            raise IncusError("Estado cloud-init inválido recebido do guest")
        raw_status = payload.get("extended_status") or payload.get("status")
        status = raw_status if isinstance(raw_status, str) and raw_status in {"running", "done", "error", "disabled", "degraded done"} else "unknown"
        raw_stage = payload.get("stage")
        stage = raw_stage if isinstance(raw_stage, str) and raw_stage in {"init-local", "init", "modules-config", "modules-final"} else None
        errors = payload.get("errors")
        error_count = len(errors) if isinstance(errors, list) else 0
        recoverable = payload.get("recoverable_errors")
        if isinstance(recoverable, dict):
            error_count += sum(len(value) for value in recoverable.values() if isinstance(value, list))
        return ProvisioningStatus(status, stage, error_count)

    def _json(self, *args: str) -> Any:
        try:
            return json.loads(self._run(*args))
        except (ValueError, TypeError) as exc:
            raise IncusError("Resposta JSON inválida do Incus") from exc

    def _query_instance(self, name: str, suffix: str) -> Any:
        _name(name, "VM")
        if suffix not in {"state", "snapshots"}:
            raise ValidationError("Consulta Incus não permitida")
        endpoint = f"/1.0/instances/{name}/{suffix}"
        if getattr(self, "access_mode", "admin") == "confined":
            # Unlike high-level CLI commands, `incus query` does not select
            # the per-user project automatically.
            endpoint += f"?project=user-{os.geteuid()}"
        return self._json("query", endpoint)

    def _read(self, endpoint: str, *cli: str) -> Any:
        if self.api is not None:
            try: return self.api.get(endpoint)
            except ApiError: pass
        return self._json(*cli)

    def list_vms(self) -> list[VM]:
        rows = self._read("/1.0/instances?recursion=2", "list", "--format", "json")
        if not isinstance(rows, list):
            raise IncusError("Lista de instâncias inválida")
        out = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("type") != "virtual-machine":
                continue
            cfg = row.get("expanded_config") or row.get("config") or {}
            devices = row.get("expanded_devices") or row.get("devices") or {}
            state = row.get("state") or {}
            if not isinstance(cfg, dict): cfg = {}
            if not isinstance(devices, dict): devices = {}
            if not isinstance(state, dict): state = {}
            devices = {key: value for key, value in devices.items() if isinstance(value, dict)}
            addresses = state.get("network") or {}
            if not isinstance(addresses, dict): addresses = {}
            ips = [addr.get("address", "") for nic in addresses.values()
                   if isinstance(nic, dict) for addr in nic.get("addresses", [])
                   if isinstance(addr, dict) and addr.get("family") == "inet" and addr.get("scope") == "global"]
            root = next((d for d in devices.values() if d.get("type") == "disk" and d.get("path") == "/"), {})
            mount_count = sum(d.get("type") == "disk" and d.get("path") != "/"
                              and isinstance(d.get("source"), str) and Path(d["source"]).is_absolute()
                              for d in devices.values())
            snapshots = row.get("snapshots") or []
            nics = [d for d in devices.values() if d.get("type") == "nic"]
            possible_network = [d for d in devices.values() if d.get("type") not in NETWORK_SAFE_DEVICE_TYPES]
            if nics and possible_network:
                network_policy = "NIC e outros dispositivos · saída não verificada"
            elif nics:
                network_policy = "NIC presente · saída não verificada"
            elif possible_network:
                network_policy = "Sem NIC; outro dispositivo pode fornecer rede"
            else:
                network_policy = "Sem NIC Incus · rede externa não verificada"
            image_os = str(cfg.get("image.os") or "—")
            image_release = str(cfg.get("image.release") or "")
            out.append(VM(row.get("name", "?"), row.get("status", "Desconhecido"),
                          str(cfg.get("limits.cpu", "—")), str(cfg.get("limits.memory", "—")),
                          str(root.get("size", "—")), ips[0] if ips else "—",
                          f"{image_os} {image_release}".strip(), mount_count, len(snapshots),
                          str(cfg.get("user.isolatevm.security-profile") or "externo/desconhecido"),
                          network_policy))
        return out

    def pools(self) -> list[str]:
        try:
            rows = self._read("/1.0/storage-pools?recursion=1", "storage", "list", "--format", "json")
        except IncusError:
            if self.access_mode != "confined":
                raise
            # The user socket can read a named pool but cannot enumerate all
            # pools. Its project profile identifies the pool assigned to it.
            profile = yaml.safe_load(self._run("profile", "show", "default"))
            devices = profile.get("devices") if isinstance(profile, dict) else None
            root = devices.get("root") if isinstance(devices, dict) else None
            pool = root.get("pool") if isinstance(root, dict) else None
            if not isinstance(pool, str) or not pool:
                raise IncusError("O perfil do projeto Incus não indica um pool de armazenamento")
            _name(pool, "Pool")
            self._run("storage", "show", pool)
            return [pool]
        if not isinstance(rows, list):
            raise IncusError("Lista de pools inválida recebida do Incus")
        return [x["name"] for x in rows if isinstance(x, dict) and isinstance(x.get("name"), str)]

    def bridges(self) -> list[str]:
        return [x["name"] for x in self._read("/1.0/networks?recursion=1", "network", "list", "--format", "json")
                if x.get("name") and x.get("managed") and x.get("type") == "bridge"]

    def image_info(self, release: str) -> dict[str, str]:
        if release not in {"22.04", "24.04", "26.04"}:
            raise ValidationError("Versão Ubuntu não aceita")
        alias = f"images:ubuntu/{release}/cloud"
        rows = self._json("image", "list", alias, "--format", "json")
        if not isinstance(rows, list):
            raise IncusError("Metadados da imagem inválidos")
        image_alias = alias.split(":", 1)[1]
        matches = [row for row in rows if isinstance(row, dict)
                   and row.get("type") == "virtual-machine"
                   and row.get("architecture") == platform.machine()
                   and isinstance(row.get("aliases"), list)
                   and any(isinstance(entry, dict) and entry.get("name") == image_alias
                           for entry in row["aliases"])]
        if len(matches) != 1:
            raise IncusError("Imagem Ubuntu cloud para esta arquitetura indisponível ou ambígua")
        image = matches[0]
        size = image.get("size")
        return {"alias": alias,
                "fingerprint": str(image.get("fingerprint") or "indisponível"),
                "architecture": str(image["architecture"]),
                "size": f"{size} bytes ({size / 1024**2:.1f} MiB)" if type(size) is int and size >= 0 else "indisponível",
                "uploaded_at": str(image.get("uploaded_at") or "indisponível")}

    def pool_space(self, pool: str) -> tuple[int, int] | None:
        _name(pool, "Pool")
        try:
            if self.api is None:
                data = yaml.safe_load(self._run("storage", "show", pool, "--resources"))
            else:
                data = self.api.get(f"/1.0/storage-pools/{pool}/resources")
        except (ApiError, IncusError, yaml.YAMLError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("space"), dict):
            return None
        space = data["space"]
        total, used = space.get("total"), space.get("used")
        if type(total) is not int or type(used) is not int or total <= 0 or used < 0 or used > total:
            return None
        return total - used, total

    def _check_host_mount_policy(self, mounts: tuple[Mount, ...]) -> None:
        if not mounts or getattr(self, "access_mode", "admin") != "confined":
            return
        # Incus assigns the user socket to this project; its restrictions can
        # reject host-path disks even though the root disk is allowed.
        project = yaml.safe_load(self._run("project", "show", f"user-{os.geteuid()}"))
        if not isinstance(project, dict) or not isinstance(project.get("config"), dict):
            raise IncusError("Não foi possível verificar a política de mounts do projeto Incus")
        config = project["config"]
        if str(config.get("restricted", "false")).lower() != "true":
            return
        if config.get("restricted.devices.disk", "managed") != "allow":
            raise IncusError("O projeto Incus restrito não permite compartilhar caminhos do host. Peça ao operador para revisar restricted.devices.disk.")
        allowed = [Path(part.strip()).resolve() for part in
                   str(config.get("restricted.devices.disk.paths", "")).split(",") if part.strip()]
        if allowed and any(not any(Path(mount.host).is_relative_to(prefix) for prefix in allowed)
                           for mount in mounts):
            raise IncusError("Um caminho solicitado não está na lista de mounts permitidos pelo projeto Incus")

    def _check_usb_policy(self) -> None:
        if getattr(self, "access_mode", "admin") != "confined": return
        project = yaml.safe_load(self._run("project", "show", f"user-{os.geteuid()}"))
        config = project.get("config") if isinstance(project, dict) else None
        if not isinstance(config, dict) or str(config.get("restricted", "false")).lower() != "true": return
        if config.get("restricted.devices.usb", "block") != "allow":
            raise IncusError("O projeto Incus restrito bloqueia USB. Um administrador precisa liberar restricted.devices.usb para este projeto antes da anexação explícita.")

    def preflight(self, manifest: Manifest) -> dict[str, str]:
        self._check_host_mount_policy(manifest.mounts)
        if manifest.pool not in self.pools():
            raise IncusError(f"Pool de armazenamento inexistente: {manifest.pool}")
        if manifest.networkMode in {"normal", "restricted"} and manifest.bridge not in self.bridges():
            raise IncusError(f"Bridge Incus inexistente: {manifest.bridge}")
        if any(vm.name == manifest.name for vm in self.list_vms()):
            raise IncusError("Já existe uma VM com esse nome")
        # Revalidate paths immediately before the side effect.
        Manifest.parse(manifest.to_dict())
        return self.image_info(manifest.release)

    def create(self, manifest: Manifest, progress: Callable[[str], None] | None = None) -> None:
        if progress: progress("Validando nome, pool, bridge, caminhos e imagem")
        self.preflight(manifest)
        image = f"images:ubuntu/{manifest.release}/cloud"
        args = ["create", image, manifest.name, "--vm", "--no-profiles",
                "-d", "root,type=disk", "-d", "root,path=/",
                "-d", f"root,pool={manifest.pool}", "-d", f"root,size={manifest.diskGiB}GiB",
                "-c", f"limits.cpu={manifest.cpu}", "-c", f"limits.memory={manifest.memoryMiB}MiB",
                "-c", "user.isolatevm.managed=true",
                "-c", f"user.isolatevm.security-profile={manifest.securityProfile}"]
        for key, value in manifest.environment:
            args += ["-c", f"environment.{key}={value}"]
        runtime = None
        if manifest.networkMode == "restricted":
            if progress: progress("Autorizando proxy de saída e bloqueio de conexões diretas")
            try:
                runtime = apply_egress(manifest)
            except EgressError as exc:
                raise IncusError(str(exc)) from exc
        cloud = cloud_config(manifest, runtime.proxy_url if runtime else None)
        if cloud:
            args += ["-c", "cloud-init.user-data=" + cloud]
        created = False
        try:
            if progress: progress("Baixando imagem se necessário; criando disco e VM parada")
            self._run(*args, timeout=1200)
            created = True
            if manifest.networkMode == "normal":
                if progress: progress("Conectando NIC eth0 à bridge autorizada")
                self._run("config", "device", "add", manifest.name, "eth0", "nic",
                          f"network={manifest.bridge}", "name=eth0", timeout=300)
            elif manifest.networkMode == "restricted":
                if progress: progress("Conectando NIC filtrada ao proxy de saída")
                self._run("config", "device", "add", manifest.name, "eth0", "nic",
                          f"network={manifest.bridge}", "name=eth0", f"ipv4.address={runtime.address}",
                          f"hwaddr={runtime.mac}", "ipv6.address=none", "security.ipv4_filtering=true", "security.ipv6_filtering=true",
                          "security.port_isolation=true", timeout=300)
            for index, mount in enumerate(manifest.mounts):
                if progress: progress(f"Aplicando mount {index + 1}/{len(manifest.mounts)}")
                self._run("config", "device", "add", manifest.name, f"isovm{index}", "disk",
                          f"source={mount.host}", f"path={mount.guest}",
                          f"readonly={'true' if mount.mode == 'ro' else 'false'}")
        except Exception as exc:
            if created:
                if progress: progress("Falha; tentando remover a VM incompleta")
                try:
                    self._run("delete", manifest.name, "--force", timeout=300)
                except IncusError as cleanup:
                    raise IncusError(f"Criação falhou; limpeza manual necessária para {manifest.name}: {cleanup}") from exc
            if runtime is not None:
                try:
                    remove_egress(manifest.name)
                except EgressError:
                    pass
            if created:
                raise
            raise IncusError(f"Criação de {manifest.name} não foi confirmada. Atualize a lista Incus antes de tentar novamente.",
                             str(exc)) from exc
        if progress: progress("VM criada e parada")

    def change_state(self, name: str, action: str) -> None:
        _name(name, "VM")
        if action not in {"start", "stop", "restart", "force-stop"}:
            raise ValidationError("Ação não permitida")
        if action == "force-stop":
            self._run("stop", name, "--force", timeout=120)
        else:
            self._run(action, name, timeout=300)

    def delete(self, name: str) -> None:
        _name(name, "VM")
        restricted = self._security_profile(name) == "restricted-development"
        self._run("delete", name, "--force", timeout=300)
        if restricted:
            try:
                remove_egress(name)
            except EgressError as exc:
                raise IncusError(f"VM removida, mas a limpeza do proxy restrito ficou pendente: {exc}") from exc

    def snapshots(self, name: str) -> list[str]:
        _name(name, "VM")
        result = self._query_instance(name, "snapshots")
        rows = result.get("metadata", result) if isinstance(result, dict) else result
        if not isinstance(rows, list):
            raise IncusError("Lista de snapshots inválida recebida do Incus")
        return [unquote(urlsplit(x).path.rsplit("/", 1)[-1]) for x in rows if isinstance(x, str)]

    def snapshot(self, name: str, snapshot: str) -> None:
        _name(name, "VM")
        _name(snapshot, "Snapshot")
        self._run("snapshot", "create", name, snapshot, timeout=300)

    def rename_snapshot(self, name: str, snapshot: str, replacement: str) -> None:
        _name(name, "VM"); _name(snapshot, "Snapshot"); _name(replacement, "Novo snapshot")
        if snapshot == replacement:
            raise ValidationError("Escolha um nome diferente para o snapshot")
        self._run("snapshot", "rename", name, snapshot, replacement, timeout=300)

    def restore_snapshot(self, name: str, snapshot: str) -> None:
        _name(name, "VM"); _name(snapshot, "Snapshot")
        self._run("snapshot", "restore", name, snapshot, timeout=600)

    def delete_snapshot(self, name: str, snapshot: str) -> None:
        _name(name, "VM"); _name(snapshot, "Snapshot")
        self._run("snapshot", "delete", name, snapshot, timeout=300)

    def clone(self, source: str, target: str) -> None:
        _name(source, "VM")
        _name(target, "Nova VM")
        if any(vm.name == target for vm in self.list_vms()):
            raise IncusError("Já existe uma VM com esse nome")
        self._run("copy", source, target, timeout=1200)

    def effective(self, name: str) -> dict[str, Any]:
        _name(name, "VM")
        config = yaml.safe_load(self._run("config", "show", name, "--expanded"))
        local = yaml.safe_load(self._run("config", "show", name))
        if not isinstance(config, dict):
            raise IncusError("Configuração efetiva inválida")
        summary = describe_effective(config, local if isinstance(local, dict) else {})
        summary["config"] = _redact_config(config)
        return summary

    def add_mount(self, name: str, mount: Mount) -> None:
        _name(name, "VM")
        if self._security_profile(name) == "maximum-isolation":
            raise ValidationError("Máximo isolamento impede compartilhar pastas do host")
        mount = Mount.parse({"host": mount.host, "guest": mount.guest, "mode": mount.mode})
        self._check_host_mount_policy((mount,))
        current = self.effective(name)
        guest = Path(mount.guest)
        if any(guest == Path(x["path"]) or guest in Path(x["path"]).parents or Path(x["path"]) in guest.parents
               for x in current["mounts"] + current["volumes"]):
            raise ValidationError("Destino se sobrepõe a outro mount")
        used = set(current["config"].get("devices", {}))
        device = next((f"isovm{i}" for i in range(100) if f"isovm{i}" not in used), None)
        if not device: raise IncusError("Limite de mounts gerenciados alcançado")
        self._run("config", "device", "add", name, device, "disk", f"source={mount.host}",
                  f"path={mount.guest}", f"readonly={'true' if mount.mode == 'ro' else 'false'}")

    def remove_mount(self, name: str, device: str) -> None:
        _name(name, "VM")
        if not device.startswith("isovm") or not device[5:].isdigit():
            raise ValidationError("Somente mounts gerenciados podem ser removidos")
        current = self.effective(name)
        if not any(x["device"] == device and x["managed"] for x in current["mounts"]):
            raise ValidationError("Mount gerenciado não encontrado")
        self._run("config", "device", "remove", name, device)

    def host_usb_devices(self) -> list[UsbDevice]:
        return host_usb_devices()

    def add_usb_device(self, name: str, device: UsbDevice) -> None:
        _name(name, "VM")
        if self._security_profile(name) == "maximum-isolation":
            raise ValidationError("Máximo isolamento impede repassar dispositivos USB")
        if not isinstance(device, UsbDevice) or not re.fullmatch(r"[0-9a-f]{4}", device.vendor_id) or not re.fullmatch(r"[0-9a-f]{4}", device.product_id):
            raise ValidationError("Dispositivo USB inválido")
        self._check_usb_policy()
        current = self._local_devices(name)
        used = set(current)
        slot = next((f"isousb{i}" for i in range(32) if f"isousb{i}" not in used), None)
        if slot is None: raise IncusError("Limite de 32 dispositivos USB gerenciados alcançado")
        self._run("config", "device", "add", name, slot, "usb", f"vendorid={device.vendor_id}",
                  f"productid={device.product_id}", "required=false", timeout=300)

    def remove_usb_device(self, name: str, device: str) -> None:
        _name(name, "VM")
        if not re.fullmatch(r"isousb(?:[0-9]|[12][0-9]|3[01])", device):
            raise ValidationError("Somente dispositivos USB gerenciados podem ser removidos")
        current = self._local_devices(name)
        raw = current.get(device)
        if not isinstance(raw, dict) or raw.get("type") != "usb":
            raise ValidationError("Dispositivo USB gerenciado não encontrado")
        self._run("config", "device", "remove", name, device, timeout=300)

    def host_gpu_devices(self) -> list[GpuDevice]: return host_gpu_devices()

    def add_gpu_device(self, name: str, device: GpuDevice) -> None:
        _name(name, "VM")
        if self._security_profile(name) == "maximum-isolation": raise ValidationError("Máximo isolamento impede repassar GPU")
        if not isinstance(device, GpuDevice) or not re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", device.pci) or not re.fullmatch(r"[0-9a-f]{4}", device.vendor_id) or not re.fullmatch(r"[0-9a-f]{4}", device.product_id):
            raise ValidationError("GPU inválida")
        current = self._local_devices(name); used = set(current)
        slot = next((f"isogpu{i}" for i in range(8) if f"isogpu{i}" not in used), None)
        if slot is None: raise IncusError("Limite de GPUs gerenciadas alcançado")
        self._run("config", "device", "add", name, slot, "gpu", "gputype=physical", f"pci={device.pci}",
                  f"vendorid={device.vendor_id}", f"productid={device.product_id}", timeout=300)

    def remove_gpu_device(self, name: str, device: str) -> None:
        _name(name, "VM")
        if not re.fullmatch(r"isogpu[0-7]", device): raise ValidationError("Somente GPUs gerenciadas podem ser removidas")
        raw = self._local_devices(name).get(device)
        if not isinstance(raw, dict) or raw.get("type") != "gpu": raise ValidationError("GPU gerenciada não encontrada")
        self._run("config", "device", "remove", name, device, timeout=300)

    def _local_devices(self, name: str) -> dict[str, Any]:
        _name(name, "VM")
        local = yaml.safe_load(self._run("config", "show", name))
        if not isinstance(local, dict) or local.get("profiles"):
            raise IncusError("Controle de rede disponível apenas para VMs sem perfis herdados")
        settings = local.get("config") or {}
        if not isinstance(settings, dict) or str(settings.get("user.isolatevm.managed", "")).lower() != "true":
            raise IncusError("Controle de rede disponível apenas para VMs criadas pelo IsolateVM")
        devices = local.get("devices") or {}
        if not isinstance(devices, dict) or any(not isinstance(value, dict) for value in devices.values()):
            raise IncusError("Dispositivos Incus inválidos; controle de rede indisponível")
        return devices

    def _security_profile(self, name: str) -> str | None:
        _name(name, "VM")
        local = yaml.safe_load(self._run("config", "show", name))
        if not isinstance(local, dict):
            raise IncusError("Configuração Incus inválida")
        settings = local.get("config") or {}
        if not isinstance(settings, dict):
            raise IncusError("Configuração Incus inválida")
        value = settings.get("user.isolatevm.security-profile")
        return str(value) if value is not None else None

    def block_network(self, name: str) -> None:
        devices = self._local_devices(name)
        nic = devices.get("eth0")
        if not isinstance(nic, dict) or nic.get("type") != "nic":
            raise IncusError("Nenhuma NIC eth0 gerenciada para bloquear")
        if not saved_network_bridge(name) or nic.get("network") != saved_network_bridge(name):
            raise IncusError("NIC não corresponde à política salva; bloqueio automático indisponível")
        if sum(d.get("type") == "nic" for d in devices.values()) != 1:
            raise IncusError("Há outras NICs; bloqueio total não pode ser garantido")
        if any(d.get("type") not in NETWORK_SAFE_DEVICE_TYPES for d in devices.values()):
            raise IncusError("Há proxy ou dispositivo não classificado; bloqueio total não pode ser garantido")
        self._run("config", "device", "remove", name, "eth0", timeout=300)

    def restore_network(self, name: str, bridge: str) -> None:
        _name(bridge, "Bridge")
        profile = self._security_profile(name)
        if profile == "maximum-isolation":
            raise ValidationError("Máximo isolamento impede restaurar uma NIC")
        if saved_network_bridge(name) != bridge:
            raise ValidationError("Bridge não corresponde à política salva da VM")
        devices = self._local_devices(name)
        if "eth0" in devices:
            raise IncusError("Já existe dispositivo eth0")
        if any(d.get("type") == "nic" for d in devices.values()):
            raise IncusError("A VM já possui uma NIC")
        if bridge not in self.bridges():
            raise IncusError("Bridge Incus não encontrada")
        if profile == "restricted-development":
            try:
                manifest = load_instance_manifest(name)
            except ValidationError as exc:
                raise IncusError("Manifesto restrito original indisponível; restauração automática recusada") from exc
            if manifest.networkMode != "restricted" or manifest.bridge != bridge:
                raise IncusError("Manifesto não corresponde à política restrita salva")
            try:
                runtime = apply_egress(manifest)
            except EgressError as exc:
                raise IncusError(str(exc)) from exc
            self._run("config", "device", "add", name, "eth0", "nic", f"network={bridge}", "name=eth0",
                      f"ipv4.address={runtime.address}", f"hwaddr={runtime.mac}", "ipv6.address=none",
                      "security.ipv4_filtering=true", "security.ipv6_filtering=true", "security.port_isolation=true",
                      timeout=300)
            return
        self._run("config", "device", "add", name, "eth0", "nic", f"network={bridge}", "name=eth0", timeout=300)

    def set_resources(self, name: str, cpu: int, memory_mib: int) -> None:
        _name(name, "VM")
        _integer(cpu, 1, 64, "CPU")
        _integer(memory_mib, 512, 262144, "RAM")
        self._run("config", "set", name, f"limits.cpu={cpu}", f"limits.memory={memory_mib}MiB", timeout=300)

    def terminal_argv(self, name: str) -> list[str]:
        self._require_connection_approval()
        _name(name, "VM")
        return [self.binary, "--force-local", "exec", name, "--", "/bin/bash"]

    def guest_login_argv(self, name: str) -> list[str]:
        self._require_connection_approval()
        _name(name, "VM")
        return [self.binary, "--force-local", "exec", name, "--mode", "interactive",
                "--", "/usr/bin/passwd", "ubuntu"]

    def console_argv(self, name: str) -> list[str]:
        self._require_connection_approval()
        _name(name, "VM")
        if not (shutil.which("remote-viewer") or shutil.which("spicy")):
            raise IncusError("Console VGA indisponível: instale virt-viewer ou um cliente SPICE compatível.")
        return [self.binary, "--force-local", "console", name, "--type", "vga"]

    def export_full(self, name: str, destination: Path) -> None:
        _name(name, "VM")
        if not destination.is_absolute() or not destination.name.endswith(".tar.gz"):
            raise ValidationError("Backup completo: escolha um destino absoluto terminado em .tar.gz")
        try:
            parent = destination.parent.resolve(strict=True)
            if not parent.is_dir():
                raise ValidationError("Backup completo: pasta de destino inválida")
            target = parent / destination.name
            if target.exists() or target.is_symlink():
                raise ValidationError("Backup completo: destino já existe; escolha outro nome")
            with tempfile.TemporaryDirectory(prefix=".isolatevm-backup-", dir=parent) as stage:
                temporary = Path(stage) / f"{name}.tar.gz"
                self._run("export", name, str(temporary), timeout=7200)
                if not temporary.is_file() or temporary.is_symlink():
                    raise IncusError("O Incus não produziu um arquivo de backup válido")
                # Incus may create the archive with a permissive mode. Backups
                # contain guest data and Incus agent credentials. Restrict the
                # inode while it is still inside the private staging directory.
                os.chmod(temporary, 0o600)
                # Hard-link is atomic on this filesystem and refuses an existing target.
                os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise ValidationError("Backup completo: destino criado por outro processo; escolha outro nome") from exc
        except OSError as exc:
            raise IncusError("Não foi possível gravar o backup completo", str(exc)) from exc

    def metrics(self, name: str) -> MetricsSnapshot:
        _name(name, "VM")
        endpoint = f"/1.0/instances/{name}/state"
        if self.api is not None:
            try:
                return parse_state(self.api.get(endpoint))
            except ApiError:
                pass
            except ValueError as exc:
                raise IncusError("Estado de métricas inválido recebido do Incus") from exc
        payload = self._query_instance(name, "state")
        if isinstance(payload, dict) and "metadata" in payload:
            payload = payload["metadata"]
        try:
            return parse_state(payload)
        except ValueError as exc:
            raise IncusError("Estado de métricas inválido recebido do Incus") from exc



def _redact_config(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[OCULTO]" if key.lower().startswith(("user.", "environment.", "cloud-init.", "raw."))
                or any(word in key.lower() for word in
                       ("secret", "token", "password", "passwd", "credential", "api_key", "apikey", "private_key", "access_key"))
                else _redact_config(item) for key, item in value.items()}
    if isinstance(value, list): return [_redact_config(x) for x in value]
    return value
