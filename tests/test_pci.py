from isolatevm.pci import PciDevice, host_pci_devices


def write_pci(root, name, class_code, vendor="0x1234", product="0x5678", driver=None):
    item = root / name
    item.mkdir()
    (item / "class").write_text(class_code)
    (item / "vendor").write_text(vendor)
    (item / "device").write_text(product)
    if driver:
        target = root.parent / "drivers" / driver
        target.mkdir(parents=True, exist_ok=True)
        (item / "driver").symlink_to(target)


def test_pci_inventory_lists_supported_non_network_non_gpu_functions(tmp_path):
    write_pci(tmp_path, "0000:02:00.0", "0x040300", driver="snd_hda_intel")
    write_pci(tmp_path, "0000:03:00.0", "0x030000")
    write_pci(tmp_path, "0000:03:00.1", "0x040300")
    write_pci(tmp_path, "0000:04:00.0", "0x030000")
    write_pci(tmp_path, "0000:05:00.0", "0x060400")
    write_pci(tmp_path, "0000:06:00.0", "0x020000")
    write_pci(tmp_path, "malformed", "0x040300")
    devices = host_pci_devices(tmp_path)
    assert devices == [PciDevice(
        "0000:02:00.0", "1234", "5678", "040300", "snd_hda_intel",
        "PCI 0000:02:00.0 · 1234:5678 · classe 040300 · driver snd_hda_intel",
    )]


def test_pci_inventory_handles_missing_sysfs_and_invalid_metadata(tmp_path):
    assert host_pci_devices(tmp_path / "missing") == []
    write_pci(tmp_path, "0000:02:00.0", "broken")
    assert host_pci_devices(tmp_path) == []
