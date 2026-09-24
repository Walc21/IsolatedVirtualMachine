#!/usr/bin/python3
"""Receive explicit one-time host copies on the VM root disk via Incus stdin."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import sys
from typing import BinaryIO


MAX_FILE_BYTES = 1024**3
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _parts(destination: str) -> tuple[str, ...]:
    if not isinstance(destination, str) or len(destination) > 2048:
        raise ValueError("invalid destination")
    parts = destination.split("/")
    try:
        invalid = (len(parts) < 4 or parts[:3] != ["", "home", "ubuntu"] or
                   any(not part or part in {".", ".."} or
                       any(ord(char) < 32 or ord(char) == 127 for char in part) or
                       len(part.encode("utf-8")) > 255 for part in parts[3:]) or
                   parts[3].startswith("."))
    except UnicodeEncodeError:
        invalid = True
    if invalid:
        raise ValueError("invalid destination")
    return tuple(parts[1:])


def _open_destination(destination: str, *, root: Path, uid: int, gid: int,
                      include_final: bool) -> tuple[int, str]:
    parts = _parts(destination)
    directory_parts = parts if include_final else parts[:-1]
    directory_flag = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open(root, directory_flag)
    root_device = os.fstat(current).st_dev
    try:
        for index, component in enumerate(directory_parts):
            created = False
            if index >= 2:
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    created = True
                except FileExistsError:
                    pass
            next_fd = os.open(component, directory_flag, dir_fd=current)
            os.close(current)
            current = next_fd
            info = os.fstat(current)
            if not stat.S_ISDIR(info.st_mode) or info.st_dev != root_device:
                raise ValueError("destination is not on the guest root disk")
            if created:
                os.fchown(current, uid, gid)
                os.fchmod(current, 0o700)
        return current, parts[-1]
    except Exception:
        os.close(current)
        raise


def apply_directory(destination: str, *, root: Path, uid: int, gid: int) -> None:
    fd, _ = _open_destination(destination, root=root, uid=uid, gid=gid, include_final=True)
    os.close(fd)


def _matching_existing(parent: int, name: str, *, uid: int, gid: int,
                       mode: int, size: int, digest: str) -> bool:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid or
                info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode or info.st_size != size):
            return False
        hasher = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while block := stream.read(1024 * 1024):
                hasher.update(block)
        return hasher.hexdigest() == digest
    finally:
        os.close(fd)


def apply_file(destination: str, stream: BinaryIO, size: int, digest: str,
               mode: int, *, root: Path, uid: int, gid: int) -> None:
    if (type(size) is not int or not 0 <= size <= MAX_FILE_BYTES or
            not isinstance(digest, str) or not SHA256.fullmatch(digest) or mode not in {0o600, 0o700}):
        raise ValueError("invalid file metadata")
    parent, name = _open_destination(destination, root=root, uid=uid, gid=gid,
                                     include_final=False)
    temporary = ".isolatevm-copy-" + secrets.token_hex(16)
    fd = -1
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        count = 0
        hasher = hashlib.sha256()
        with os.fdopen(fd, "wb", closefd=False) as output:
            while block := stream.read(1024 * 1024):
                count += len(block)
                if count > size:
                    raise ValueError("oversized payload")
                output.write(block)
                hasher.update(block)
            output.flush()
            os.fsync(fd)
        if count != size or hasher.hexdigest() != digest:
            raise ValueError("payload digest mismatch")
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        try:
            os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent,
                    follow_symlinks=False)
        except FileExistsError:
            if not _matching_existing(parent, name, uid=uid, gid=gid,
                                      mode=mode, size=size, digest=digest):
                raise ValueError("destination already exists with different content") from None
        os.fsync(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def main() -> int:
    try:
        if os.geteuid() != 0:
            raise ValueError("root agent access required")
        user = pwd.getpwnam("ubuntu")
        if user.pw_uid != 1000:
            raise ValueError("unexpected guest user")
        args = sys.argv[1:]
        if len(args) == 2 and args[0] == "dir":
            apply_directory(args[1], root=Path("/"), uid=user.pw_uid, gid=user.pw_gid)
        elif len(args) == 5 and args[0] == "file":
            apply_file(args[1], sys.stdin.buffer, int(args[2]), args[3], int(args[4], 8),
                       root=Path("/"), uid=user.pw_uid, gid=user.pw_gid)
        else:
            raise ValueError("invalid operation")
        return 0
    except Exception:
        sys.stderr.write("One-time guest copy failed; check source, target, and Incus agent.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
