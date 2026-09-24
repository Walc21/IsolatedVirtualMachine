"""Small, read-only parsers for packages observed inside a guest VM."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any


@dataclass(frozen=True)
class SoftwareInventoryEntry:
    manager: str
    package: str
    status: str
    version: str | None = None


def normalize_name(value: str, manager: str) -> str:
    value = value.strip()
    if manager == "apt":
        value = value.partition(":")[0]
        return value.casefold()
    if manager in {"pip", "pipx"}:
        return re.sub(r"[-_.]+", "-", value).casefold()
    return value.casefold()


def package_name(spec: str, manager: str) -> str:
    if manager in {"pip", "pipx"} and "==" in spec:
        return spec.split("==", 1)[0]
    if manager == "npm" and "@" in spec:
        return spec.rsplit("@", 1)[0]
    if manager == "cargo" and "@" in spec:
        return spec.rsplit("@", 1)[0]
    if manager == "go" and "@" in spec:
        return spec.rsplit("@", 1)[0]
    return spec


def expected_version(spec: str, manager: str) -> str | None:
    if manager in {"pip", "pipx"} and "==" in spec:
        return spec.split("==", 1)[1]
    if manager in {"npm", "cargo", "go"} and "@" in spec:
        value = spec.rsplit("@", 1)[1]
        if manager == "npm" and not re.match(r"^v?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?$", value):
            return None
        return value
    return None


def _version(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = " ".join(value.split())
    if not value or len(value) > 160 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def parse_dpkg(output: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or fields[2].strip() != "installed":
            continue
        name, version = normalize_name(fields[0], "apt"), _version(fields[1])
        if name and version:
            found[name] = version
    return found


def parse_pip(output: str) -> dict[str, str]:
    payload = json.loads(output)
    if not isinstance(payload, list) or len(payload) > 100_000:
        raise ValueError("Formato pip list inválido")
    found = {}
    for row in payload:
        if not isinstance(row, dict):
            continue
        name, version = row.get("name"), _version(row.get("version"))
        if isinstance(name, str) and version:
            found[normalize_name(name, "pip")] = version
    return found


def parse_pipx(output: str) -> dict[str, str]:
    payload = json.loads(output)
    venvs = payload.get("venvs") if isinstance(payload, dict) else None
    if not isinstance(venvs, dict) or len(venvs) > 10_000:
        raise ValueError("Formato pipx list inválido")
    found = {}
    for environment, value in venvs.items():
        if not isinstance(value, dict):
            continue
        metadata = value.get("metadata")
        if not isinstance(metadata, dict):
            metadata = value
        main = metadata.get("main_package")
        if not isinstance(main, dict):
            continue
        name = main.get("package") or environment
        version = _version(main.get("package_version"))
        if isinstance(name, str) and version:
            found[normalize_name(name, "pipx")] = version
    return found


def parse_npm(output: str) -> dict[str, str]:
    payload = json.loads(output)
    dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
    if not isinstance(dependencies, dict) or len(dependencies) > 100_000:
        raise ValueError("Formato npm list inválido")
    found = {}
    for name, value in dependencies.items():
        if isinstance(name, str) and isinstance(value, dict):
            version = _version(value.get("version"))
            if version:
                found[normalize_name(name, "npm")] = version
    return found


def parse_cargo(output: str) -> dict[str, str]:
    found = {}
    for line in output.splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_.+-]+)\s+v([^\s:]+):", line.strip())
        if match:
            found[normalize_name(match.group(1), "cargo")] = match.group(2)
    return found


def parse_go(output: str, requested_module: str) -> str | None:
    return parse_go_modules(output, [requested_module]).get(requested_module.casefold())


def parse_go_modules(output: str, requested_modules: list[str]) -> dict[str, str]:
    requested = {module.casefold() for module in requested_modules}
    found = {}
    for line in output.splitlines():
        match = re.match(r"\s*mod\s+(\S+)\s+(\S+)", line)
        if match and match.group(1).casefold() in requested:
            version = _version(match.group(2))
            if version:
                found[match.group(1).casefold()] = version
    return found


def parse_rustc(output: str) -> str | None:
    match = re.search(r"^rustc\s+(\S+)", output, flags=re.MULTILINE)
    return _version(match.group(1)) if match else None


def entries_for(manager: str, requested: list[str], found: dict[str, str]) -> list[SoftwareInventoryEntry]:
    result = []
    for spec in requested:
        version = found.get(normalize_name(package_name(spec, manager), manager))
        if version is None:
            status = "missing"
        else:
            expected = expected_version(spec, manager)
            status = ("version-mismatch" if expected is not None and
                      version.removeprefix("v").casefold() != expected.removeprefix("v").casefold()
                      else "installed")
        result.append(SoftwareInventoryEntry(manager, spec, status, version))
    return result


def unavailable_entries(manager: str, requested: list[str]) -> list[SoftwareInventoryEntry]:
    return [SoftwareInventoryEntry(manager, spec, "unavailable") for spec in requested]
