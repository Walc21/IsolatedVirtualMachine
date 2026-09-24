from pathlib import Path

from isolatevm.usb import UsbDevice, host_usb_devices


def write_device(root: Path, name: str, vendor: str, product: str, manufacturer: str = "Acme", label: str = "Camera") -> None:
    folder = root / name; folder.mkdir()
    (folder / "idVendor").write_text(vendor)
    (folder / "idProduct").write_text(product)
    (folder / "manufacturer").write_text(manufacturer)
    (folder / "product").write_text(label)


def test_usb_inventory_uses_sysfs_ids_and_ignores_interfaces_hubs_and_invalid_entries(tmp_path):
    write_device(tmp_path, "1-2", "1234", "aBcD")
    write_device(tmp_path, "1-2:1.0", "9999", "0001")
    write_device(tmp_path, "usb1", "9999", "0001")
    write_device(tmp_path, "1-3", "invalid", "0001")
    assert host_usb_devices(tmp_path) == [UsbDevice("1-2", "1234", "abcd", "Acme Camera")]


def test_usb_inventory_returns_empty_when_sysfs_is_unavailable(tmp_path):
    assert host_usb_devices(tmp_path / "missing") == []
