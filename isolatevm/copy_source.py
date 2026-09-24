"""Bounded inspection and descriptor-based reads of explicit host copy sources."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import BinaryIO


MAX_COPY_BYTES = 1024**3
MAX_COPY_FILES = 2048
MAX_COPY_DEPTH = 16
SENSITIVE_NAMES = {".ssh", ".gnupg", ".aws", ".config", ".local", ".docker", ".kube"}


class CopySourceError(ValueError):
    pass


@dataclass(frozen=True)
class SourceEntry:
    path: Path
    relative: tuple[str, ...]
    directory: bool
    size: int = 0
    executable: bool = False


def _component(name: str, include_hidden: bool) -> None:
    try:
        length = len(name.encode("utf-8"))
    except UnicodeEncodeError:
        raise CopySourceError("Cópia: nome de arquivo não é UTF-8 válido") from None
    if (not name or name in {".", ".."} or length > 255 or
            any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise CopySourceError("Cópia: nome de arquivo inválido")
    if name in SENSITIVE_NAMES:
        raise CopySourceError(f"Cópia: caminho sensível bloqueado: {name}")
    if name.startswith(".") and not include_hidden:
        raise CopySourceError("Cópia: arquivos ocultos exigem autorização explícita")


def source_reference(value: object, kind: str, include_hidden: bool) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or ".." in Path(value).parts:
        raise CopySourceError("Cópia: origem precisa ser um caminho absoluto sem '..'")
    if kind not in {"file", "directory"} or type(include_hidden) is not bool:
        raise CopySourceError("Cópia: tipo de origem ou permissão de ocultos inválidos")
    raw = Path(value)
    home = Path.home().resolve()
    try:
        relative = raw.relative_to(home)
    except ValueError:
        raise CopySourceError("Cópia: escolha um caminho específico dentro do HOME") from None
    if not relative.parts or len(relative.parts) > MAX_COPY_DEPTH:
        raise CopySourceError("Cópia: escolha um caminho específico dentro do HOME")
    for component in relative.parts:
        _component(component, include_hidden)
    return raw


def canonical_source(value: object, kind: str, include_hidden: bool) -> Path:
    raw = source_reference(value, kind, include_hidden)
    for part in (raw, *raw.parents):
        if part.is_symlink():
            raise CopySourceError("Cópia: symlinks na origem não são aceitos")
    try:
        resolved = raw.resolve(strict=True)
        home = Path.home().resolve(strict=True)
        resolved.relative_to(home)
        info = resolved.lstat()
        if info.st_dev != home.stat().st_dev:
            raise CopySourceError("Cópia: origem em outro filesystem/mount não é aceita")
        if kind == "file" and not stat.S_ISREG(info.st_mode):
            raise CopySourceError("Cópia: a origem declarada como arquivo não é regular")
        if kind == "directory" and not stat.S_ISDIR(info.st_mode):
            raise CopySourceError("Cópia: a origem declarada como pasta não é diretório regular")
        return resolved
    except (OSError, ValueError) as exc:
        if isinstance(exc, CopySourceError):
            raise
        raise CopySourceError("Cópia: origem indisponível ou fora do HOME") from None


def scan_source(value: object, kind: str, include_hidden: bool) -> tuple[SourceEntry, ...]:
    source = canonical_source(value, kind, include_hidden)
    if kind == "file":
        info = source.lstat()
        if info.st_size > MAX_COPY_BYTES:
            raise CopySourceError("Cópia: arquivo excede 1 GiB")
        return (SourceEntry(source, (), False, info.st_size, bool(info.st_mode & 0o111)),)

    entries: list[SourceEntry] = []
    files = 0
    total = 0
    base_device = source.stat().st_dev

    def fail_walk(error: OSError) -> None:
        raise CopySourceError("Cópia: não foi possível ler toda a pasta") from error

    for current, dirs, names in os.walk(source, topdown=True, followlinks=False, onerror=fail_walk):
        directory = Path(current)
        relative = directory.relative_to(source).parts
        if len(relative) > MAX_COPY_DEPTH:
            raise CopySourceError("Cópia: pasta excede 16 níveis")
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_dev != base_device:
            raise CopySourceError("Cópia: pasta mudou ou contém outro filesystem")
        entries.append(SourceEntry(directory, relative, True))
        dirs.sort(); names.sort()
        for name in dirs:
            _component(name, include_hidden)
            child = directory / name
            child_info = child.lstat()
            if not stat.S_ISDIR(child_info.st_mode) or child_info.st_dev != base_device:
                raise CopySourceError("Cópia: symlink, mount ou tipo especial dentro da pasta")
        for name in names:
            _component(name, include_hidden)
            child = directory / name
            child_info = child.lstat()
            if not stat.S_ISREG(child_info.st_mode) or child_info.st_dev != base_device:
                raise CopySourceError("Cópia: symlink, mount ou tipo especial dentro da pasta")
            files += 1
            total += child_info.st_size
            if files > MAX_COPY_FILES or total > MAX_COPY_BYTES:
                raise CopySourceError("Cópia: limite de 2048 arquivos ou 1 GiB excedido")
            entries.append(SourceEntry(child, (*relative, name), False,
                                       child_info.st_size, bool(child_info.st_mode & 0o111)))
    return tuple(entries)


def open_source_file(path: Path) -> BinaryIO:
    """Open every component with O_NOFOLLOW so a swapped symlink cannot escape HOME."""
    home = Path.home().resolve(strict=True)
    try:
        parts = path.relative_to(home).parts
    except ValueError:
        raise CopySourceError("Cópia: origem fora do HOME") from None
    if not parts:
        raise CopySourceError("Cópia: origem inválida")
    directory_flag = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = os.open(home, directory_flag)
    try:
        home_device = os.fstat(current_fd).st_dev
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flag, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
            if os.fstat(current_fd).st_dev != home_device:
                raise CopySourceError("Cópia: origem mudou para outro filesystem")
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current_fd)
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_dev != home_device or info.st_size > MAX_COPY_BYTES:
                raise CopySourceError("Cópia: origem mudou ou não é arquivo regular")
            return os.fdopen(file_fd, "rb")
        except Exception:
            os.close(file_fd)
            raise
    except OSError:
        raise CopySourceError("Cópia: origem mudou ou não pode ser aberta com segurança") from None
    finally:
        os.close(current_fd)
