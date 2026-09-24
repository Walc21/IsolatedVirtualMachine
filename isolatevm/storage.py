"""Local audit and template store. Incus remains the VM state source."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path

import yaml

from .model import Manifest, ValidationError, _name


def data_dir() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
    path = base / "isolatevm"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def audit(action: str, vm: str, result: str, source: str = "gui") -> None:
    if action not in {"create", "start", "stop", "restart", "delete", "snapshot", "snapshot-restore", "snapshot-delete", "mount-add", "mount-remove", "usb-add", "usb-remove", "gpu-add", "gpu-remove", "network-block", "network-restore", "resources", "clone", "template", "export", "backup-full"}:
        raise ValidationError("Ação de auditoria desconhecida")
    event = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "action": action, "vm": vm, "result": result, "source": source}
    path = data_dir() / "audit.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


def history(limit: int = 200) -> list[dict]:
    path = data_dir() / "audit.jsonl"
    if not path.exists(): return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()[-limit:] if line.strip()][::-1]


def save_template(name: str, manifest: Manifest) -> Path:
    _name(name, "Template")
    folder = data_dir() / "templates"
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / f"{name}.yaml"
    # Paths are personal; templates intentionally omit mounts and VM name.
    data = manifest.to_dict()
    data["name"] = name
    data["mounts"] = []
    data["metadata"] = {"template": name}
    clean = Manifest.parse(data)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(clean.to_yaml())
    return path


def templates() -> list[str]:
    folder = data_dir() / "templates"
    if not folder.exists(): return []
    return sorted(p.stem for p in folder.glob("*.yaml") if p.is_file() and not p.is_symlink())


def load_template(name: str) -> Manifest:
    _name(name, "Template")
    path = data_dir() / "templates" / f"{name}.yaml"
    if path.is_symlink(): raise ValidationError("Template symlink bloqueado")
    return Manifest.from_yaml(path.read_text(encoding="utf-8"))


def save_instance_manifest(manifest: Manifest) -> Path:
    folder = data_dir() / "instances"
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / f"{manifest.name}.yaml"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(manifest.to_yaml())
    return path


def load_instance_manifest(name: str) -> Manifest:
    _name(name, "VM")
    path = data_dir() / "instances" / f"{name}.yaml"
    if path.is_symlink() or not path.is_file():
        raise ValidationError("Não há manifesto local desta VM")
    return Manifest.from_yaml(path.read_text(encoding="utf-8"))


def saved_network_bridge(name: str) -> str | None:
    _name(name, "VM")
    path = data_dir() / "instances" / f"{name}.yaml"
    if path.is_symlink() or not path.is_file(): return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        network = data.get("network", {})
        bridge = network.get("bridge") if network.get("mode") in {"normal", "restricted"} else None
        return _name(bridge, "Bridge") if bridge else None
    except (OSError, AttributeError, ValidationError, yaml.YAMLError):
        return None


def remove_instance_manifest(name: str) -> None:
    _name(name, "VM")
    (data_dir() / "instances" / f"{name}.yaml").unlink(missing_ok=True)


def export_manifest(manifest: Manifest, destination: Path) -> None:
    # An export contains authorized paths, but never credential values.
    if destination.suffix.lower() not in {".yaml", ".yml"}:
        raise ValidationError("Use extensão .yaml ou .yml")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(manifest.to_yaml())


def import_manifest(source: Path) -> Manifest:
    if source.is_symlink() or not source.is_file():
        raise ValidationError("Arquivo de manifesto inválido")
    return Manifest.from_yaml(source.read_text(encoding="utf-8"))


def load_theme() -> str:
    path = data_dir() / "settings.json"
    if not path.is_file() or path.is_symlink(): return "system"
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get("theme")
        return value if value in {"system", "light", "dark"} else "system"
    except (OSError, ValueError, AttributeError):
        return "system"


def save_theme(theme: str) -> None:
    if theme not in {"system", "light", "dark"}:
        raise ValidationError("Tema inválido")
    path = data_dir() / "settings.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({"theme": theme}, stream)


def first_run() -> bool:
    return not (data_dir() / "onboarding.done").exists()


def complete_onboarding() -> None:
    path = data_dir() / "onboarding.done"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.close(fd)
