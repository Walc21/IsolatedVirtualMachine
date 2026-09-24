"""Typed Incus adapter. No shell, arbitrary command or automatic privilege escalation."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Protocol
from urllib.parse import unquote, urlsplit

import yaml

from .api import ApiError, IncusUnixApi
from .access import local_socket
from .copy_source import CopySourceError, MAX_COPY_BYTES, MAX_COPY_FILES, open_source_file, scan_source
from .egress import EgressError, apply as apply_egress, remove as remove_egress
from .model import INITIAL_SNAPSHOT, Manifest, Mount, ValidationError, _integer, _name
from .metrics import MetricsSnapshot, parse_state
from .permissions import NETWORK_SAFE_DEVICE_TYPES, describe_effective
from .provision import cloud_config
from .storage import data_dir, load_instance_manifest, saved_network_bridge
from .usb import UsbDevice, host_usb_devices
from .gpu import GpuDevice, host_gpu_devices
from .workspace_volume import WORKSPACE_DEVICE, volume_name as workspace_volume_name


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
    copy_state: str = "none"
    lifecycle_disposition: str = "persistent"


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
    def verify_managed_lifecycle(self, name: str, disposition: str,
                                 pool: str | None = None,
                                 workspace_size_gib: int | None = None) -> bool: ...
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
    def inject_secrets(self, name: str, retrieve: Callable[[tuple[str, ...]], dict[str, str]]) -> None: ...
    def clear_secrets(self, name: str) -> None: ...
    def apply_copies(self, name: str, progress: Callable[[str], None] | None = None) -> str: ...
    def terminal_argv(self, name: str) -> list[str]: ...
    def guest_login_argv(self, name: str) -> list[str]: ...
    def console_argv(self, name: str) -> list[str]: ...
    def export_full(self, name: str, destination: Path) -> None: ...
    def export_workspace(self, name: str, destination: Path) -> None: ...
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

    def _run(self, *args: str, timeout: int = 120, ok_returncodes: tuple[int, ...] = (0,),
             stdin: str | None = None) -> str:
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
                                    timeout=timeout, env=env, input=stdin)
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
                          network_policy,
                          str(cfg.get("user.isolatevm.copy-state") or "none"),
                          str(cfg.get("user.isolatevm.lifecycle-disposition") or "persistent")))
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
        workspace_volume = None
        if manifest.lifecycleDisposition == "persist-workspace":
            workspace_volume = workspace_volume_name(manifest.name)
            if self._workspace_volume_exists(manifest.pool, workspace_volume):
                raise IncusError(f"O volume persistente reservado já existe: {workspace_volume}; verifique órfãos antes de reutilizar")
        image = f"images:ubuntu/{manifest.release}/cloud"
        args = ["create", image, manifest.name, "--vm", "--no-profiles"]
        if workspace_volume is None:
            args += ["-d", "root,type=disk", "-d", "root,path=/",
                     "-d", f"root,pool={manifest.pool}", "-d", f"root,size={manifest.diskGiB}GiB",
                     "-c", f"limits.cpu={manifest.cpu}", "-c", f"limits.memory={manifest.memoryMiB}MiB",
                     "-c", "user.isolatevm.managed=true",
                     "-c", f"user.isolatevm.security-profile={manifest.securityProfile}",
                     "-c", f"user.isolatevm.lifecycle-disposition={manifest.lifecycleDisposition}"]
        if manifest.copies and workspace_volume is None:
            args += ["-c", "user.isolatevm.copy-state=pending"]
        if workspace_volume is None:
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
        if cloud and workspace_volume is None:
            args += ["-c", "cloud-init.user-data=" + cloud]
        create_stdin = None
        if workspace_volume is not None:
            config: dict[str, str] = {
                "limits.cpu": str(manifest.cpu),
                "limits.memory": f"{manifest.memoryMiB}MiB",
                "user.isolatevm.managed": "true",
                "user.isolatevm.security-profile": manifest.securityProfile,
                "user.isolatevm.lifecycle-disposition": manifest.lifecycleDisposition,
                "user.isolatevm.workspace-volume": workspace_volume,
            }
            if manifest.copies:
                config["user.isolatevm.copy-state"] = "pending"
            config.update({f"environment.{key}": value for key, value in manifest.environment})
            if cloud:
                config["cloud-init.user-data"] = cloud
            payload = {
                "config": config,
                "devices": {
                    "root": {"type": "disk", "path": "/", "pool": manifest.pool,
                             "size": f"{manifest.diskGiB}GiB"},
                    WORKSPACE_DEVICE: {
                        "type": "disk", "pool": manifest.pool,
                        "source": workspace_volume, "path": "/workspace"},
                },
                "profiles": [],
            }
            create_stdin = yaml.safe_dump(payload, sort_keys=False)
        created = False
        created_workspace = False
        try:
            if workspace_volume is not None:
                if progress: progress(f"Criando volume /workspace de {manifest.workspaceSizeGiB} GiB")
                try:
                    self._run("storage", "volume", "create", manifest.pool, workspace_volume,
                              f"size={manifest.workspaceSizeGiB}GiB",
                              "user.isolatevm.managed=true",
                              f"user.isolatevm.owner={manifest.name}",
                              f"user.isolatevm.size-gib={manifest.workspaceSizeGiB}", timeout=600)
                    created_workspace = True
                except IncusError as exc:
                    # A CLI timeout can leave the create result uncertain. Only
                    # treat the resource as ours if its ownership markers prove it.
                    try:
                        self._verify_workspace_volume(manifest.pool, workspace_volume,
                                                      manifest.name, manifest.workspaceSizeGiB)
                    except Exception:
                        raise IncusError(f"Criação do volume /workspace não confirmada; verifique {workspace_volume} antes de tentar novamente",
                                         str(exc)) from exc
                    raise IncusError(f"O volume /workspace {workspace_volume} foi criado, mas a confirmação da operação falhou; ele foi preservado para revisão",
                                     str(exc)) from exc
            if progress: progress("Baixando imagem se necessário; criando disco e VM parada")
            self._run(*args, timeout=1200, stdin=create_stdin)
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
            if manifest.lifecycleDisposition in {"restore-initial-on-close", "persist-workspace"}:
                if progress: progress("Criando snapshot inicial protegido")
                self._run("snapshot", "create", manifest.name, INITIAL_SNAPSHOT, timeout=300)
        except Exception as exc:
            if created:
                if progress: progress("Falha; tentando remover a VM incompleta")
                try:
                    self._run("delete", manifest.name, "--force", timeout=300)
                except IncusError as cleanup:
                    raise IncusError(f"Criação falhou; limpeza manual necessária para {manifest.name}: {cleanup}") from exc
            if created_workspace and workspace_volume is not None:
                try:
                    self._verify_workspace_volume(manifest.pool, workspace_volume,
                                                  manifest.name, manifest.workspaceSizeGiB)
                    self._run("storage", "volume", "delete", manifest.pool, workspace_volume, timeout=300)
                except Exception as cleanup:
                    raise IncusError(f"Criação falhou; volume /workspace preservado ou limpeza pendente: {workspace_volume} ({cleanup})") from exc
            if runtime is not None:
                try:
                    remove_egress(manifest.name)
                except EgressError:
                    pass
            if created:
                raise
            raise IncusError(f"Criação de {manifest.name} não foi confirmada. Atualize a lista Incus antes de tentar novamente.",
                             (exc.technical if isinstance(exc, IncusError) and exc.technical else str(exc))) from exc
        if progress: progress("VM criada e parada")

    def change_state(self, name: str, action: str) -> None:
        _name(name, "VM")
        if action not in {"start", "stop", "restart", "force-stop"}:
            raise ValidationError("Ação não permitida")
        if action == "force-stop":
            self._run("stop", name, "--force", timeout=120)
        else:
            self._run(action, name, timeout=300)

    def _secret_vm_manifest(self, name: str, *, cleanup: bool = False) -> Manifest:
        self._require_connection_approval()
        _name(name, "VM")
        manifest = load_instance_manifest(name)
        if manifest.name != name or not manifest.secrets:
            raise ValidationError("A VM não possui referências de secrets no manifesto IsolateVM")
        # Require the locally managed, profile-free VM contract before sending
        # credential bytes through the Incus guest-agent channel.
        self._local_devices(name)
        if not cleanup and self._security_profile(name) != manifest.securityProfile:
            raise ValidationError("O perfil Incus mudou desde a criação; entrega de secrets cancelada")
        if not cleanup and manifest.securityProfile == "maximum-isolation":
            raise ValidationError("Máximo isolamento impede disponibilizar secrets ao guest")
        vm = next((item for item in self.list_vms() if item.name == name), None)
        if vm is None or vm.status != "Running":
            raise IncusError("Ligue a VM e aguarde o agente Incus antes de usar secrets temporários")
        return manifest

    def _send_guest_secret_payload(self, name: str, payload: bytes) -> None:
        env = {**os.environ, "LC_ALL": "C", "INCUS_CONF": str(self.client_config_dir)}
        for key in ("INCUS_REMOTE", "INCUS_SOCKET", "INCUS_DIR", "INCUS_PROJECT"):
            env.pop(key, None)
        argv = [self.binary, "--force-local", "--quiet", "exec", name,
                "--force-noninteractive", "--user", "0", "--",
                "/usr/bin/python3", "/usr/local/lib/isolatevm/inject-secrets"]
        try:
            result = subprocess.run(argv, input=payload, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False, timeout=60, env=env)
        except subprocess.TimeoutExpired:
            raise IncusError("A entrega de secrets excedeu o tempo permitido; a resposta do guest foi suprimida") from None
        if result.returncode:
            raise IncusError("O guest não aceitou a atualização de secrets temporários",
                             f"incus exec retornou {result.returncode}; saída suprimida para proteger credenciais")

    def inject_secrets(self, name: str, retrieve: Callable[[tuple[str, ...]], dict[str, str]]) -> None:
        manifest = self._secret_vm_manifest(name)
        values = retrieve(manifest.secrets)
        if not isinstance(values, dict) or set(values) != set(manifest.secrets):
            raise ValidationError("O cofre não retornou exatamente os secrets referenciados pela VM")
        for value in values.values():
            if not isinstance(value, str) or not value or "\x00" in value or len(value.encode("utf-8")) > 16 * 1024:
                raise ValidationError("Valor de secret inválido")
        payload = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > 600 * 1024:
            raise ValidationError("Payload de secrets excede o limite permitido")
        self._send_guest_secret_payload(name, payload)

    def clear_secrets(self, name: str) -> None:
        # Clearing only removes managed runtime files, so keep the recovery
        # path available even if an operator changed the VM's security profile.
        self._secret_vm_manifest(name, cleanup=True)
        self._send_guest_secret_payload(name, b"{}")

    def _send_guest_copy(self, name: str, operation: tuple[str, ...],
                         source: Any = None, timeout: int = 120) -> None:
        env = {**os.environ, "LC_ALL": "C", "INCUS_CONF": str(self.client_config_dir)}
        for key in ("INCUS_REMOTE", "INCUS_SOCKET", "INCUS_DIR", "INCUS_PROJECT"):
            env.pop(key, None)
        argv = [self.binary, "--force-local", "--quiet", "exec", name,
                "--force-noninteractive", "--user", "0", "--", "/usr/bin/python3",
                "/usr/local/lib/isolatevm/copy-files", *operation]
        try:
            result = subprocess.run(argv, stdin=source if source is not None else subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    check=False, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            raise IncusError("Cópia excedeu o tempo permitido; verifique o estado pendente") from None
        if result.returncode:
            raise IncusError("O guest recusou uma cópia; o estado continua pendente",
                             f"incus exec retornou {result.returncode}; saída suprimida")

    def apply_copies(self, name: str, progress: Callable[[str], None] | None = None) -> str:
        self._require_connection_approval()
        _name(name, "VM")
        manifest = load_instance_manifest(name)
        if manifest.name != name or not manifest.copies:
            raise ValidationError("A VM não possui cópias únicas no manifesto local")
        devices = self._local_devices(name)
        if self._security_profile(name) != manifest.securityProfile or manifest.securityProfile == "maximum-isolation":
            raise ValidationError("Perfil Incus incompatível com as cópias declaradas")
        local = yaml.safe_load(self._run("config", "show", name))
        settings = local.get("config") if isinstance(local, dict) else None
        if not isinstance(settings, dict):
            raise IncusError("Configuração Incus inválida para a cópia")
        state = settings.get("user.isolatevm.copy-state")
        if state == "done":
            return str(settings.get("user.isolatevm.copy-sha256") or "")
        if state != "pending":
            raise ValidationError("A VM não possui uma cópia pendente autorizada")
        vm = next((item for item in self.list_vms() if item.name == name), None)
        if vm is None or vm.status != "Running":
            raise IncusError("Ligue a VM antes de copiar arquivos uma vez para seu disco")
        for device in devices.values():
            if device.get("type") != "disk" or device.get("path") == "/":
                continue
            path = device.get("path")
            if not isinstance(path, str) or not path.startswith("/"):
                raise ValidationError("Cópia: dispositivo disk desconhecido na VM")
            disk_path = Path(path)
            if any(Path(copy.guest) == disk_path or Path(copy.guest) in disk_path.parents or
                   disk_path in Path(copy.guest).parents for copy in manifest.copies):
                raise ValidationError("Cópia: destino sobreposto a um mount Incus efetivo")

        scanned = []
        total_files = total_bytes = 0
        for copy in manifest.copies:
            try:
                entries = scan_source(copy.host, copy.kind, copy.include_hidden)
            except CopySourceError as exc:
                raise ValidationError(str(exc)) from None
            total_files += sum(not entry.directory for entry in entries)
            total_bytes += sum(entry.size for entry in entries)
            scanned.append((copy, entries))
        if total_files > MAX_COPY_FILES or total_bytes > MAX_COPY_BYTES:
            raise ValidationError("Cópia: limite total de 2048 arquivos ou 1 GiB excedido")

        if progress: progress("Aguardando agente Incus e helper de cópia no guest")
        deadline = time.monotonic() + 180
        while True:
            try:
                self._run("exec", name, "--force-noninteractive", "--user", "0", "--",
                          "/usr/bin/test", "-f", "/usr/local/lib/isolatevm/copy-files", timeout=20)
                break
            except IncusError:
                if time.monotonic() >= deadline:
                    raise IncusError("Agente Incus ou helper de cópia não ficou pronto em três minutos") from None
                time.sleep(3)

        receipt = hashlib.sha256()
        copied = 0
        for copy, entries in scanned:
            for entry in entries:
                target = copy.guest + ("/" + "/".join(entry.relative) if entry.relative else "")
                if entry.directory:
                    self._send_guest_copy(name, ("dir", target))
                    receipt.update(f"dir\0{target}\n".encode("utf-8"))
                    continue
                try:
                    with open_source_file(entry.path) as source:
                        before = os.fstat(source.fileno())
                        if before.st_size != entry.size or bool(before.st_mode & 0o111) != entry.executable:
                            raise ValidationError("Cópia: arquivo de origem mudou durante o provisionamento")
                        hasher = hashlib.sha256()
                        while block := source.read(1024 * 1024):
                            hasher.update(block)
                        if os.fstat(source.fileno()).st_size != before.st_size:
                            raise ValidationError("Cópia: arquivo de origem mudou durante a leitura")
                        source.seek(0)
                        mode = 0o700 if entry.executable else 0o600
                        self._send_guest_copy(name, ("file", target, str(before.st_size),
                                                      hasher.hexdigest(), f"{mode:04o}"),
                                              source, timeout=max(120, min(1800, before.st_size // (512 * 1024) + 120)))
                except CopySourceError as exc:
                    raise ValidationError(str(exc)) from None
                receipt.update(f"file\0{target}\0{before.st_size}\0{hasher.hexdigest()}\n".encode("utf-8"))
                copied += 1
                if progress: progress(f"Arquivos copiados: {copied}/{total_files}")
        digest = receipt.hexdigest()
        self._run("config", "set", name, f"user.isolatevm.copy-sha256={digest}",
                  "user.isolatevm.copy-state=done")
        return digest

    def _workspace_volume_exists(self, pool: str, volume: str) -> bool:
        _name(pool, "Pool"); _name(volume, "Volume")
        rows = self._json("storage", "volume", "list", pool, "--format", "json")
        if not isinstance(rows, list):
            raise IncusError("Lista de volumes customizados inválida")
        return any(isinstance(row, dict) and row.get("name") == volume and
                   row.get("type", "custom") == "custom" for row in rows)

    def _verify_workspace_volume(self, pool: str, volume: str, owner: str,
                                 size_gib: int | None = None) -> dict[str, Any]:
        _name(pool, "Pool"); _name(volume, "Volume"); _name(owner, "VM")
        try:
            raw = yaml.safe_load(self._run("storage", "volume", "show", pool, volume))
        except yaml.YAMLError as exc:
            raise IncusError(f"Resposta inválida para o volume persistente {volume}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("config"), dict):
            raise IncusError(f"Metadados inválidos do volume persistente {volume}")
        config = raw["config"]
        if (raw.get("type", "custom") != "custom" or raw.get("content_type") != "filesystem" or
                config.get("user.isolatevm.managed") != "true" or
                config.get("user.isolatevm.owner") != owner):
            raise IncusError(f"Propriedade ou tipo do volume persistente não pôde ser confirmado: {volume}")
        if size_gib is not None:
            if config.get("user.isolatevm.size-gib") != str(size_gib):
                raise IncusError(f"Tamanho declarado do volume persistente não confere: {volume}")
            actual = config.get("size")
            if actual not in {f"{size_gib}GiB", str(size_gib * 1024**3)}:
                raise IncusError(f"Limite de tamanho do volume persistente não pôde ser confirmado: {volume}")
        return raw

    def _local_instance_config(self, name: str) -> dict[str, Any]:
        local = yaml.safe_load(self._run("config", "show", name))
        if not isinstance(local, dict):
            raise IncusError(f"Configuração local inválida para {name}")
        return local

    def _verify_workspace_device(self, name: str, local: dict[str, Any],
                                 pool: str | None = None,
                                 size_gib: int | None = None) -> tuple[str, str]:
        settings, devices = local.get("config"), local.get("devices")
        if not isinstance(settings, dict) or not isinstance(devices, dict):
            raise IncusError(f"Configuração de /workspace inválida para {name}")
        volume = settings.get("user.isolatevm.workspace-volume")
        if not isinstance(volume, str) or volume != workspace_volume_name(name):
            raise IncusError(f"Marcador do volume /workspace não confere para {name}")
        device = devices.get(WORKSPACE_DEVICE)
        expected_source = volume
        if (not isinstance(device, dict) or device.get("type") != "disk" or
                (pool is not None and device.get("pool") != pool) or
                device.get("source") != expected_source or device.get("path") != "/workspace" or
                any(key in device for key in ("initial.uid", "initial.gid", "initial.mode")) or
                str(device.get("readonly", "false")).lower() != "false"):
            raise IncusError(f"Dispositivo /workspace não confere para {name}")
        actual_pool = device.get("pool")
        if not isinstance(actual_pool, str):
            raise IncusError(f"Pool do volume /workspace não pôde ser confirmado para {name}")
        self._verify_workspace_volume(actual_pool, volume, name, size_gib)
        return actual_pool, volume

    def delete(self, name: str) -> None:
        _name(name, "VM")
        restricted = self._security_profile(name) == "restricted-development"
        local = self._local_instance_config(name)
        settings = local.get("config") if isinstance(local.get("config"), dict) else {}
        disposition = settings.get("user.isolatevm.lifecycle-disposition")
        workspace_marker = settings.get("user.isolatevm.workspace-volume")
        workspace: tuple[str, str] | None = None
        if disposition == "persist-workspace" or workspace_marker is not None:
            if (settings.get("user.isolatevm.managed") != "true" or
                    disposition != "persist-workspace" or local.get("profiles") != []):
                raise IncusError(f"Propriedade da VM/volume /workspace não pôde ser confirmada: {name}; nada foi excluído")
            workspace = self._verify_workspace_device(name, local)
        self._run("delete", name, "--force", timeout=300)
        if workspace is not None:
            pool, volume = workspace
            try:
                self._run("storage", "volume", "delete", pool, volume, timeout=300)
            except IncusError as exc:
                raise IncusError(f"VM removida, mas os dados persistentes de /workspace continuam no volume {volume} ({pool}); revise ou remova esse volume manualmente: {exc}") from exc
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
        if snapshot == INITIAL_SNAPSHOT:
            raise ValidationError("Esse nome é reservado ao snapshot inicial do ciclo descartável")
        self._run("snapshot", "create", name, snapshot, timeout=300)

    def rename_snapshot(self, name: str, snapshot: str, replacement: str) -> None:
        _name(name, "VM"); _name(snapshot, "Snapshot"); _name(replacement, "Novo snapshot")
        if snapshot == INITIAL_SNAPSHOT:
            raise ValidationError("O snapshot inicial do ciclo descartável não pode ser renomeado")
        if snapshot == replacement:
            raise ValidationError("Escolha um nome diferente para o snapshot")
        self._run("snapshot", "rename", name, snapshot, replacement, timeout=300)

    def restore_snapshot(self, name: str, snapshot: str) -> None:
        _name(name, "VM"); _name(snapshot, "Snapshot")
        self._run("snapshot", "restore", name, snapshot, timeout=600)

    def delete_snapshot(self, name: str, snapshot: str) -> None:
        _name(name, "VM"); _name(snapshot, "Snapshot")
        if snapshot == INITIAL_SNAPSHOT:
            raise ValidationError("O snapshot inicial do ciclo descartável não pode ser excluído")
        self._run("snapshot", "delete", name, snapshot, timeout=300)

    def clone(self, source: str, target: str) -> None:
        _name(source, "VM")
        _name(target, "Nova VM")
        vms = self.list_vms()
        if any(vm.name == target for vm in vms):
            raise IncusError("Já existe uma VM com esse nome")
        source_local = self._local_instance_config(source)
        source_settings = source_local.get("config") if isinstance(source_local.get("config"), dict) else {}
        source_disposition = source_settings.get("user.isolatevm.lifecycle-disposition")
        workspace: tuple[str, str, int] | None = None
        target_volume: str | None = None
        if source_disposition == "persist-workspace":
            source_vm = next((vm for vm in vms if vm.name == source), None)
            if source_vm is None:
                raise IncusError(f"VM de origem não encontrada: {source}")
            if source_vm.status != "Stopped":
                raise IncusError("Pare a VM antes de clonar /workspace para manter os dados consistentes")
            pool, source_volume = self._verify_workspace_device(source, source_local)
            volume_data = self._verify_workspace_volume(pool, source_volume, source)
            size_marker = volume_data["config"].get("user.isolatevm.size-gib")
            if not isinstance(size_marker, str) or not size_marker.isdigit():
                raise IncusError(f"Tamanho do volume /workspace da origem não pôde ser confirmado: {source}")
            workspace = (pool, source_volume, int(size_marker))
            target_volume = workspace_volume_name(target)
            if self._workspace_volume_exists(pool, target_volume):
                raise IncusError(f"O volume do clone já existe: {target_volume}; verifique órfãos antes de reutilizar")
        volume_created = False
        instance_created = False
        # A clone is persistent by default; disposable behavior requires a new
        try:
        # explicit choice for ordinary VMs. A persisted /workspace clone keeps
        # that explicit choice and gets a private copy of the custom volume.
            if workspace is not None and target_volume is not None:
                pool, source_volume, size_gib = workspace
                self._run("storage", "volume", "copy", f"{pool}/{source_volume}",
                          f"{pool}/{target_volume}", timeout=1200)
                volume_created = True
                self._run("storage", "volume", "set", pool, target_volume,
                          f"user.isolatevm.owner={target}", timeout=300)
            self._run("copy", source, target,
                      *( ["--instance-only"] if workspace is not None else [] ), timeout=1200)
            instance_created = True
            if workspace is not None and target_volume is not None:
                pool, _source_volume, size_gib = workspace
                self._run("config", "device", "set", target, WORKSPACE_DEVICE,
                          f"source={target_volume}", timeout=300)
                self._run("config", "set", target,
                          "user.isolatevm.lifecycle-disposition=persist-workspace",
                          f"user.isolatevm.workspace-volume={target_volume}", timeout=300)
                self._verify_workspace_volume(pool, target_volume, target, size_gib)
                if INITIAL_SNAPSHOT in self.snapshots(target):
                    raise IncusError(f"Clone contém snapshot reservado inesperado; recusando /workspace: {target}")
                self._run("snapshot", "create", target, INITIAL_SNAPSHOT, timeout=300)
            else:
                self._run("config", "set", target, "user.isolatevm.lifecycle-disposition=persistent")
        except Exception as exc:
            cleanup_errors: list[str] = []
            if instance_created:
                try: self._run("delete", target, "--force", timeout=300)
                except IncusError as cleanup: cleanup_errors.append(f"VM {target}: {cleanup}")
            if volume_created and target_volume is not None and workspace is not None:
                try:
                    try:
                        self._verify_workspace_volume(workspace[0], target_volume, target, workspace[2])
                    except IncusError:
                        # A volume copy initially inherits the source owner marker.
                        self._verify_workspace_volume(workspace[0], target_volume,
                                                      source, workspace[2])
                    self._run("storage", "volume", "delete", workspace[0], target_volume, timeout=300)
                except Exception as cleanup: cleanup_errors.append(f"volume {target_volume}: {cleanup}")
            if cleanup_errors:
                raise IncusError(f"Clone falhou; a limpeza falhou e exige revisão: {'; '.join(cleanup_errors)}") from exc
            raise

    def effective(self, name: str) -> dict[str, Any]:
        _name(name, "VM")
        config = yaml.safe_load(self._run("config", "show", name, "--expanded"))
        local = yaml.safe_load(self._run("config", "show", name))
        if not isinstance(config, dict):
            raise IncusError("Configuração efetiva inválida")
        summary = describe_effective(config, local if isinstance(local, dict) else {})
        summary["config"] = _redact_config(config)
        return summary

    def verify_managed_lifecycle(self, name: str, disposition: str,
                                 pool: str | None = None,
                                 workspace_size_gib: int | None = None) -> bool:
        _name(name, "VM")
        if disposition not in {"delete-on-close", "restore-initial-on-close", "persist-workspace"}:
            return False
        local = self._local_instance_config(name)
        settings = local.get("config")
        if not (isinstance(settings, dict) and
                settings.get("user.isolatevm.managed") == "true" and
                settings.get("user.isolatevm.lifecycle-disposition") == disposition and
                local.get("profiles") == []):
            return False
        if disposition != "persist-workspace":
            return True
        self._verify_workspace_device(name, local, pool, workspace_size_gib)
        return True

    def add_mount(self, name: str, mount: Mount) -> None:
        _name(name, "VM")
        if self._security_profile(name) == "maximum-isolation":
            raise ValidationError("Máximo isolamento impede compartilhar pastas do host")
        mount = Mount.parse({"host": mount.host, "guest": mount.guest, "mode": mount.mode})
        try:
            declared_copies = load_instance_manifest(name).copies
        except (OSError, ValidationError):
            declared_copies = ()
        destination = Path(mount.guest)
        if any(destination == Path(copy.guest) or destination in Path(copy.guest).parents or
               Path(copy.guest) in destination.parents for copy in declared_copies):
            raise ValidationError("Mount se sobrepõe ao destino de uma cópia única")
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
        if (type(device.busnum) is not int or not 1 <= device.busnum <= 255 or
                type(device.devnum) is not int or not 1 <= device.devnum <= 127):
            raise ValidationError("USB sem endereço de barramento/dispositivo atual; atualize a lista")
        self._check_usb_policy()
        current_devices = host_usb_devices()
        live = next((item for item in current_devices if item.path == device.path), None)
        stable_identity = lambda item: (item.path, item.vendor_id, item.product_id,
                                        item.busnum, item.devnum, item.serial)
        if live is None or stable_identity(live) != stable_identity(device):
            raise ValidationError("O dispositivo USB mudou desde a seleção; atualize a lista e revise novamente")
        serial_matches = [item for item in current_devices
                          if device.serial and item.vendor_id == device.vendor_id and
                          item.product_id == device.product_id and item.serial == device.serial]
        current = self._local_devices(name)
        used = set(current)
        slot = next((f"isousb{i}" for i in range(32) if f"isousb{i}" not in used), None)
        if slot is None: raise IncusError("Limite de 32 dispositivos USB gerenciados alcançado")
        identity = ([f"serial={device.serial}"] if len(serial_matches) == 1 else
                    [f"busnum={device.busnum}", f"devnum={device.devnum}"])
        self._run("config", "device", "add", name, slot, "usb", f"vendorid={device.vendor_id}",
                  f"productid={device.product_id}", *identity, "required=false", timeout=300)

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

    def export_workspace(self, name: str, destination: Path) -> None:
        _name(name, "VM")
        if not destination.is_absolute() or not destination.name.endswith(".tar.gz"):
            raise ValidationError("Exportação de /workspace: escolha um destino absoluto terminado em .tar.gz")
        local = self._local_instance_config(name)
        settings = local.get("config") if isinstance(local.get("config"), dict) else {}
        if (settings.get("user.isolatevm.lifecycle-disposition") != "persist-workspace" or
                settings.get("user.isolatevm.managed") != "true" or local.get("profiles") != []):
            raise IncusError(f"Volume persistente /workspace não pôde ser confirmado para {name}")
        pool, volume = self._verify_workspace_device(name, local)
        try:
            parent = destination.parent.resolve(strict=True)
            if not parent.is_dir():
                raise ValidationError("Exportação de /workspace: pasta de destino inválida")
            target = parent / destination.name
            if target.exists() or target.is_symlink():
                raise ValidationError("Exportação de /workspace: destino já existe; escolha outro nome")
            with tempfile.TemporaryDirectory(prefix=".isolatevm-workspace-", dir=parent) as stage:
                temporary = Path(stage) / f"{name}-workspace.tar.gz"
                self._run("storage", "volume", "export", pool, volume, str(temporary), timeout=7200)
                if not temporary.is_file() or temporary.is_symlink():
                    raise IncusError("O Incus não produziu um arquivo de exportação válido para /workspace")
                os.chmod(temporary, 0o600)
                os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise ValidationError("Exportação de /workspace: destino criado por outro processo; escolha outro nome") from exc
        except OSError as exc:
            raise IncusError("Não foi possível gravar a exportação de /workspace", str(exc)) from exc

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
