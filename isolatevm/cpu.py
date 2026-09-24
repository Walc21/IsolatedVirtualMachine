"""Strict CPU ID parsing for explicit Incus VM pinning."""
from __future__ import annotations

import re
from typing import Any

CPU_ITEM = re.compile(r"(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*))?\Z")

class CPUSelectionError(ValueError):
    """Invalid host CPU selection supplied by a user or Incus response."""


def parse_cpu_set(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise CPUSelectionError("CPU pinning: informe IDs ou intervalos, por exemplo 0-3,6")
    result: set[int] = set()
    for item in value.split(","):
        match = CPU_ITEM.fullmatch(item)
        if match is None:
            raise CPUSelectionError("CPU pinning: use uma lista como 0-3,6 sem espaços")
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if start > end or end > 4095 or end - start > 63:
            raise CPUSelectionError("CPU pinning: intervalo inválido ou grande demais")
        values = set(range(start, end + 1))
        if result & values:
            raise CPUSelectionError("CPU pinning: IDs repetidos")
        result.update(values)
        if len(result) > 64:
            raise CPUSelectionError("CPU pinning: limite de 64 vCPUs atingido")
    return tuple(sorted(result))


def format_cpu_set(cpu_ids: tuple[int, ...]) -> str:
    if not cpu_ids:
        raise CPUSelectionError("CPU pinning: selecione ao menos um ID")
    groups: list[tuple[int, int]] = []
    start = previous = cpu_ids[0]
    for cpu_id in cpu_ids[1:]:
        if cpu_id == previous + 1:
            previous = cpu_id
            continue
        groups.append((start, previous))
        start = previous = cpu_id
    groups.append((start, previous))
    # Incus interprets a bare integer as a vCPU count. Explicit singleton
    # ranges retain the selected host CPU identity (including CPU 0).
    return ",".join(f"{first}-{last}" for first, last in groups)


def cpu_ids(resources: Any) -> tuple[int, ...]:
    """Extract online, non-isolated logical CPU IDs from Incus resources data."""
    if not isinstance(resources, dict) or not isinstance(resources.get("cpu"), dict):
        raise CPUSelectionError("Recursos de CPU Incus indisponíveis")
    result: set[int] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            ident = value.get("id")
            online = value.get("online")
            isolated = value.get("isolated", False)
            # A CPU thread object also contains ``thread`` (its index within
            # a core). Socket/core identifiers are not host CPU IDs.
            if (type(ident) is int and ident >= 0 and type(value.get("thread")) is int
                    and online is True and isolated is not True):
                result.add(ident)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(resources["cpu"])
    return tuple(sorted(result))
