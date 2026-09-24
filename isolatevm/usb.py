"""Read-only USB inventory with identifiers safe to pass to Incus as arguments."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


HEX_ID = re.compile(r"[0-9a-f]{4}\Z")


@dataclass(frozen=True)
class UsbDevice:
    path: str
    vendor_id: str
    product_id: str
    description: str
    busnum: int | None = None
    devnum: int | None = None
    serial: str = ""


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def host_usb_devices(root: Path = Path("/sys/bus/usb/devices")) -> list[UsbDevice]:
    """Return physical USB devices only; interfaces and root hubs are excluded."""
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return []
    result: list[UsbDevice] = []
    for item in entries:
        if ":" in item.name or item.name.startswith("usb"):
            continue
        vendor, product = _read(item / "idVendor").lower(), _read(item / "idProduct").lower()
        if not HEX_ID.fullmatch(vendor) or not HEX_ID.fullmatch(product):
            continue
        try:
            busnum = int(_read(item / "busnum"), 10)
            devnum = int(_read(item / "devnum"), 10)
        except ValueError:
            continue
        if not 1 <= busnum <= 255 or not 1 <= devnum <= 127:
            continue
        words = [_read(item / "manufacturer"), _read(item / "product")]
        description = " ".join(word for word in words if word) or "Dispositivo USB sem descrição"
        serial = _read(item / "serial")
        if len(serial) > 128 or any(ord(char) < 32 or ord(char) == 127 for char in serial):
            serial = ""
        result.append(UsbDevice(item.name, vendor, product, description, busnum, devnum, serial))
    return result
