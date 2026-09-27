"""Local audit and template store. Incus remains the VM state source."""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile

import yaml

from .model import Manifest, ValidationError, _name


MAX_MANIFEST_BYTES = 64_000
MAX_AUDIT_BYTES = 16 * 1024 * 1024
MAX_SETTINGS_BYTES = 64_000


def _read_manifest(path: Path) -> str:
    """Read a regular manifest without following links or allocating without a bound."""
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("Arquivo de manifesto inválido")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValidationError("Manifesto muito grande")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValidationError("Manifesto não está codificado em UTF-8") from None
    except OSError as exc:
        raise ValidationError("Arquivo de manifesto indisponível ou inválido") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def data_dir() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
    path = base / "isolatevm"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def audit(action: str, vm: str, result: str, source: str = "gui") -> None:
    if action not in {"create", "start", "stop", "restart", "delete", "snapshot", "snapshot-restore", "snapshot-delete", "mount-add", "mount-remove", "usb-add", "usb-remove", "gpu-add", "gpu-remove", "pci-add", "pci-remove", "disk-volume-add", "disk-volume-delete", "network-block", "network-restore", "resources", "disk-grow", "cpu-pin", "clone", "template", "export", "backup-full", "backup-workspace", "backup-data-volume", "secret-store", "secret-delete", "secret-inject", "secret-clear", "copy-files", "disposable-retain"}:
        raise ValidationError("Ação de auditoria desconhecida")
    if (not isinstance(vm, str) or not vm or len(vm) > 128 or
            not isinstance(source, str) or not source or len(source) > 64):
        raise ValidationError("Metadados de auditoria inválidos")
    event = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "action": action, "vm": vm, "result": str(result)[:2048], "source": source}
    encoded = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    path = data_dir() / "audit.jsonl"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_size + len(encoded) > MAX_AUDIT_BYTES):
            raise ValidationError("Arquivo de auditoria inválido ou acima do limite")
        os.fchmod(fd, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ValidationError("Não foi possível gravar o registro de auditoria completo")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def history(limit: int = 200) -> list[dict]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValidationError("Limite do histórico inválido")
    path = data_dir() / "audit.jsonl"
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        fcntl.flock(fd, fcntl.LOCK_SH)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_size > MAX_AUDIT_BYTES):
            raise ValidationError("Arquivo de auditoria inválido ou acima do limite")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_AUDIT_BYTES + 1)
        if len(raw) > MAX_AUDIT_BYTES:
            raise ValidationError("Arquivo de auditoria acima do limite")
        lines = raw.decode("utf-8").splitlines()[-limit:]
        entries = []
        field_limits = {"time": 64, "action": 64, "vm": 128,
                        "result": 2048, "source": 64}
        for line in lines:
            if not line.strip():
                continue
            entry = json.loads(line)
            if (not isinstance(entry, dict) or set(entry) != set(field_limits) or
                    any(not isinstance(value, str) or len(value) > field_limits[key]
                        for key, value in entry.items())):
                raise ValidationError("Registro do histórico de auditoria inválido")
            entries.append(entry)
        return entries[::-1]
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValidationError("Arquivo de auditoria inválido ou indisponível") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def save_template(name: str, manifest: Manifest) -> Path:
    _name(name, "Template")
    folder = data_dir() / "templates"
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / f"{name}.yaml"
    # Paths are personal; templates intentionally omit mounts and VM name.
    data = manifest.to_dict()
    data["name"] = name
    data["mounts"] = []
    data.pop("copies", None)
    data["metadata"]["template"] = name
    clean = Manifest.parse(data)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise ValidationError("Template já existe; escolha outro nome ou salve uma nova versão") from None
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(clean.to_yaml())
    return path


def save_template_versioned(name: str, manifest: Manifest) -> Path:
    _name(name, "Template")
    base = name[:56].rstrip("-")
    for number in range(1, 10_000):
        versioned = f"{base}-v{number:04d}"
        try:
            return save_template(versioned, manifest)
        except ValidationError:
            path = data_dir() / "templates" / f"{versioned}.yaml"
            if not path.exists() and not path.is_symlink():
                raise
    raise ValidationError("Limite de versões do template atingido")


def templates() -> list[str]:
    folder = data_dir() / "templates"
    if not folder.exists(): return []
    return sorted(p.stem for p in folder.glob("*.yaml") if p.is_file() and not p.is_symlink())


def load_template(name: str) -> Manifest:
    _name(name, "Template")
    path = data_dir() / "templates" / f"{name}.yaml"
    return Manifest.from_yaml(_read_manifest(path))


def save_instance_manifest(manifest: Manifest) -> Path:
    folder = data_dir() / "instances"
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / f"{manifest.name}.yaml"
    fd, temporary = tempfile.mkstemp(prefix=f".{manifest.name}.", suffix=".yaml", dir=folder)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(manifest.to_yaml())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def load_instance_manifest(name: str) -> Manifest:
    _name(name, "VM")
    path = data_dir() / "instances" / f"{name}.yaml"
    try:
        text = _read_manifest(path)
    except ValidationError as exc:
        raise ValidationError("Não há manifesto local válido desta VM") from exc
    return Manifest.from_yaml(text, check_copy_sources=False)


def saved_network_bridge(name: str) -> str | None:
    _name(name, "VM")
    path = data_dir() / "instances" / f"{name}.yaml"
    try:
        data = yaml.safe_load(_read_manifest(path))
        if not isinstance(data, dict):
            return None
        network = data.get("network", {})
        if not isinstance(network, dict):
            return None
        bridge = network.get("bridge") if network.get("mode") in {"normal", "restricted", "lan-only"} else None
        return _name(bridge, "Bridge") if bridge else None
    except (OSError, AttributeError, TypeError, ValidationError, yaml.YAMLError):
        return None


def remove_instance_manifest(name: str) -> None:
    _name(name, "VM")
    (data_dir() / "instances" / f"{name}.yaml").unlink(missing_ok=True)


def export_manifest(manifest: Manifest, destination: Path) -> None:
    # An export contains authorized paths, but never credential values.
    if destination.suffix.lower() not in {".yaml", ".yml"}:
        raise ValidationError("Use extensão .yaml ou .yml")
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise ValidationError("Arquivo já existe; escolha outro nome ou use Exportar versão") from None
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(manifest.to_yaml())


def export_manifest_versioned(manifest: Manifest, directory: Path) -> Path:
    if not directory.is_dir() or directory.is_symlink():
        raise ValidationError("Escolha uma pasta existente para exportar versões")
    for number in range(1, 10_000):
        destination = directory / f"{manifest.name}-v{number:04d}.yaml"
        try:
            export_manifest(manifest, destination)
            return destination
        except ValidationError as exc:
            if not destination.exists() and not destination.is_symlink():
                raise
    raise ValidationError("Limite de versões do manifesto atingido")


def import_manifest(source: Path) -> Manifest:
    return Manifest.from_yaml(_read_manifest(source))


def load_theme() -> str:
    value = _read_settings().get("theme")
    return value if value in {"system", "light", "dark"} else "system"


def _read_settings() -> dict:
    path = data_dir() / "settings.json"
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_size > MAX_SETTINGS_BYTES):
            return {}
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_SETTINGS_BYTES + 1)
        if len(raw) > MAX_SETTINGS_BYTES:
            return {}
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, AttributeError, RecursionError):
        return {}
    finally:
        if fd >= 0:
            os.close(fd)


def _write_settings(value: dict) -> None:
    folder = data_dir()
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="settings-",
                                         suffix=".json", dir=folder, delete=False) as stream:
            name = stream.name
            json.dump(value, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, folder / "settings.json")
        name = None
        directory_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def save_theme(theme: str) -> None:
    if theme not in {"system", "light", "dark"}:
        raise ValidationError("Tema inválido")
    value = _read_settings()
    value["theme"] = theme
    _write_settings(value)


def load_auto_snapshot() -> bool:
    return _read_settings().get("autoSnapshotBeforeChange") is True


def save_auto_snapshot(enabled: bool) -> None:
    if type(enabled) is not bool:
        raise ValidationError("Preferência de snapshot inválida")
    value = _read_settings()
    value["autoSnapshotBeforeChange"] = enabled
    _write_settings(value)


def first_run() -> bool:
    return not (data_dir() / "onboarding.done").exists()


def complete_onboarding() -> None:
    path = data_dir() / "onboarding.done"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.close(fd)
