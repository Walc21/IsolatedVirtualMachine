"""Read-only GPU inventory from PCI sysfs for explicit Incus passthrough."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


PCI = re.compile(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\Z")
HEX = re.compile(r"0x([0-9a-f]{4})\Z")


@dataclass(frozen=True)
class GpuDevice:
    pci: str
    vendor_id: str
    product_id: str
    description: str


def _read(path: Path) -> str:
    try: return path.read_text(encoding="utf-8").strip().lower()
    except OSError: return ""


def host_gpu_devices(root: Path = Path("/sys/bus/pci/devices")) -> list[GpuDevice]:
    try: entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError: return []
    result: list[GpuDevice] = []
    for item in entries:
        if not PCI.fullmatch(item.name.lower()): continue
        class_code, vendor, product = _read(item / "class"), _read(item / "vendor"), _read(item / "device")
        vendor_match, product_match = HEX.fullmatch(vendor), HEX.fullmatch(product)
        if not class_code.startswith("0x03") or not vendor_match or not product_match: continue
        driver = item / "driver"
        try: driver_name = driver.resolve().name
        except OSError: driver_name = "sem driver"
        result.append(GpuDevice(item.name.lower(), vendor_match.group(1), product_match.group(1), f"GPU PCI {item.name} · driver {driver_name}"))
    return result
