"""Parse the read-only Incus instance state into explicitly labelled counters."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class MetricsSnapshot:
    cpu_ns: int | None
    memory_bytes: int | None
    memory_total_bytes: int | None
    disk_bytes: int | None
    disk_total_bytes: int | None
    network_rx_bytes: int | None
    network_tx_bytes: int | None
    uptime_seconds: int | None


def cpu_percent_between(before: MetricsSnapshot, after: MetricsSnapshot,
                        elapsed_seconds: float, allocated_cpus: int | None) -> float | None:
    if (allocated_cpus is None or allocated_cpus <= 0 or elapsed_seconds <= 0
            or before.cpu_ns is None or after.cpu_ns is None or after.cpu_ns < before.cpu_ns):
        return None
    return (after.cpu_ns - before.cpu_ns) / (elapsed_seconds * 1_000_000_000 * allocated_cpus) * 100


def _counter(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def parse_state(state: Any) -> MetricsSnapshot:
    if not isinstance(state, dict):
        raise ValueError("Estado Incus inválido")
    cpu = state.get("cpu") if state.get("cpu") is not None else {}
    memory = state.get("memory") if state.get("memory") is not None else {}
    disks = state.get("disk") if state.get("disk") is not None else {}
    networks = state.get("network") if state.get("network") is not None else {}
    if not all(isinstance(x, dict) for x in (cpu, memory, disks, networks)):
        raise ValueError("Contadores Incus inválidos")
    root = disks.get("root") or {}
    if not isinstance(root, dict): root = {}
    received: list[int] = []
    sent: list[int] = []
    for nic in networks.values():
        if not isinstance(nic, dict): continue
        counters = nic.get("counters") or {}
        if not isinstance(counters, dict): continue
        rx = _counter(counters.get("bytes_received"))
        tx = _counter(counters.get("bytes_sent"))
        if rx is not None: received.append(rx)
        if tx is not None: sent.append(tx)
    uptime = None
    started = state.get("started_at")
    if state.get("status") == "Running" and isinstance(started, str) and started:
        try:
            timestamp = datetime.fromisoformat(started.replace("Z", "+00:00"))
            if timestamp.tzinfo is not None:
                uptime = max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds()))
        except ValueError:
            pass
    return MetricsSnapshot(_counter(cpu.get("usage")), _counter(memory.get("usage")),
                           _counter(memory.get("total")), _counter(root.get("usage")),
                           _counter(root.get("total")), sum(received) if received else None,
                           sum(sent) if sent else None, uptime)
