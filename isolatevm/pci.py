"""Read-only inventory of PCI functions eligible for explicit VM passthrough."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


PCI_ADDRESS = re.compile(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}[.][0-7]\Z")
HEX_ID = re.compile(r"0x([0-9a-f]{4})\Z")
PCI_CLASS = re.compile(r"0x([0-9a-f]{6})\Z")
DRIVER = re.compile(r"[A-Za-z0-9_.+-]{1,64}\Z")
# GPU and network devices have dedicated controls; bridges can affect the host
# bus and are never offered as individual passthrough candidates.
EXCLUDED_CLASSES = {"02", "03", "06"}


@dataclass(frozen=True)
class PciDevice:
    address: str
    vendor_id: str
    product_id: str
    class_code: str
    driver: str
    description: str


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip().lower()
    except OSError:
        return ""


def host_pci_devices(root: Path = Path("/sys/bus/pci/devices")) -> list[PciDevice]:
    """List non-GPU, non-network PCI functions without changing driver state."""
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return []
    entries_by_address: list[tuple[Path, str, str, str, str]] = []
    excluded_slots: set[str] = set()
    for item in entries:
        address = item.name.lower()
        if not PCI_ADDRESS.fullmatch(address):
            continue
        raw_class = _read(item / "class")
        raw_vendor = _read(item / "vendor")
        raw_product = _read(item / "device")
        pci_class = PCI_CLASS.fullmatch(raw_class)
        vendor = HEX_ID.fullmatch(raw_vendor)
        product = HEX_ID.fullmatch(raw_product)
        if not pci_class or not vendor or not product:
            continue
        if pci_class.group(1)[:2] in EXCLUDED_CLASSES:
            # Exclude sibling functions too (for example, HDMI audio on the
            # same PCI slot as a GPU) to avoid offering half of a host device.
            excluded_slots.add(address.rsplit(".", 1)[0])
            continue
        entries_by_address.append((item, address, pci_class.group(1),
                                   vendor.group(1), product.group(1)))
    result: list[PciDevice] = []
    for item, address, class_code, vendor_id, product_id in entries_by_address:
        if address.rsplit(".", 1)[0] in excluded_slots:
            continue
        try:
            driver = (item / "driver").resolve(strict=True).name
        except OSError:
            driver = "sem driver"
        if driver != "sem driver" and not DRIVER.fullmatch(driver):
            driver = "driver desconhecido"
        description = (f"PCI {address} · {vendor_id}:{product_id} · classe {class_code} · "
                       f"driver {driver}")
        result.append(PciDevice(address, vendor_id, product_id, class_code,
                                driver, description))
    return result
