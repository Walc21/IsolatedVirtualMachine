#!/usr/bin/python3
"""Install explicitly delivered credentials into the guest's volatile /run."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


SECRET_DIR = Path("/run/isolatevm-secrets")
SECRET_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
RESERVED = {"PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "IFS", "ENV",
            "BASH_ENV", "PYTHONPATH", "PYTHONHOME"}
MAX_SECRET_BYTES = 16 * 1024
MAX_INPUT_BYTES = 600 * 1024


def run_is_tmpfs(mountinfo: Path = Path("/proc/self/mountinfo")) -> bool:
    try:
        lines = mountinfo.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in lines:
        before, separator, after = line.partition(" - ")
        if not separator:
            continue
        fields = before.split()
        filesystem = after.split()
        if len(fields) > 4 and filesystem and fields[4] == "/run":
            return filesystem[0] == "tmpfs"
    return False


def _validated(payload: object) -> dict[str, bytes]:
    if not isinstance(payload, dict) or len(payload) > 32:
        raise ValueError("invalid payload")
    result: dict[str, bytes] = {}
    for name, value in payload.items():
        if (not isinstance(name, str) or not SECRET_NAME.fullmatch(name) or name in RESERVED or
                name.startswith("LD_") or not isinstance(value, str) or not value or "\x00" in value):
            raise ValueError("invalid payload")
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_SECRET_BYTES:
            raise ValueError("invalid payload")
        result[name] = encoded
    return result


def _read_index(directory: Path, owner_uid: int) -> set[str]:
    path = directory / ".isolatevm-index"
    try:
        info = path.lstat()
    except FileNotFoundError:
        return set()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("unsafe index")
    raw = path.read_bytes()
    if len(raw) > 4096:
        raise ValueError("unsafe index")
    names = json.loads(raw.decode("utf-8"))
    if (not isinstance(names, list) or len(names) > 32 or
            any(not isinstance(name, str) or not SECRET_NAME.fullmatch(name) for name in names)):
        raise ValueError("unsafe index")
    return set(names)


def _atomic_write(directory: Path, filename: str, data: bytes, owner_uid: int,
                  owner_gid: int, mode: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".isolatevm-", dir=directory)
    try:
        os.fchown(fd, owner_uid, owner_gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / filename)
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def apply_payload(payload: object, directory: Path = SECRET_DIR, *, owner_uid: int,
                  guest_gid: int) -> tuple[list[str], list[str]]:
    values = _validated(payload)
    directory = Path(directory)
    parent_info = directory.parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != owner_uid:
        raise ValueError("unsafe runtime parent")
    directory.mkdir(mode=0o750, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid:
        raise ValueError("unsafe runtime directory")
    os.chown(directory, owner_uid, guest_gid)
    os.chmod(directory, 0o750)

    previous = _read_index(directory, owner_uid)
    removed: list[str] = []
    try:
        for name in sorted(previous - values.keys()):
            target = directory / name
            try:
                target_info = target.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(target_info.st_mode) or target_info.st_uid != owner_uid:
                raise ValueError("unsafe managed file")
            target.unlink()
            removed.append(name)

        for name, value in sorted(values.items()):
            target = directory / name
            try:
                target_info = target.lstat()
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(target_info.st_mode) or target_info.st_uid != owner_uid:
                    raise ValueError("unsafe target")
            _atomic_write(directory, name, value, owner_uid, guest_gid, 0o640)

        index = json.dumps(sorted(values), separators=(",", ":")).encode("utf-8")
        _atomic_write(directory, ".isolatevm-index", index, owner_uid, guest_gid, 0o600)
    except Exception:
        # A failed update must not leave a partially delivered credential set.
        for name in previous | values.keys():
            target = directory / name
            try:
                target_info = target.lstat()
                if target_info.st_uid == owner_uid and (stat.S_ISREG(target_info.st_mode) or
                                                        stat.S_ISLNK(target_info.st_mode)):
                    target.unlink()
            except OSError:
                pass
        try:
            (directory / ".isolatevm-index").unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return sorted(values), removed


def main() -> int:
    try:
        if os.geteuid() != 0 or not run_is_tmpfs():
            raise ValueError("runtime storage is unavailable")
        import pwd
        guest_user = pwd.getpwnam("ubuntu")
        if guest_user.pw_uid != 1000:
            raise ValueError("unexpected guest user")
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("oversized payload")
        payload = json.loads(raw.decode("utf-8"))
        stored, removed = apply_payload(payload, owner_uid=0, guest_gid=guest_user.pw_gid)
        sys.stdout.write(json.dumps({"stored": stored, "removed": removed}, separators=(",", ":")))
        return 0
    except Exception:
        # Keep diagnostic output independent of the credential payload.
        sys.stderr.write("Secret runtime update failed; check VM agent, user, and /run.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
