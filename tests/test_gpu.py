from isolatevm.gpu import GpuDevice, host_gpu_devices


def write_pci(root, name, class_code, vendor="0x10de", product="0x1f91"):
    item = root / name; item.mkdir()
    (item / "class").write_text(class_code)
    (item / "vendor").write_text(vendor)
    (item / "device").write_text(product)


def test_gpu_inventory_accepts_only_display_class_and_valid_pci_ids(tmp_path):
    write_pci(tmp_path, "0000:01:00.0", "0x030000")
    write_pci(tmp_path, "0000:00:14.3", "0x028000")
    write_pci(tmp_path, "broken", "0x030000")
    devices = host_gpu_devices(tmp_path)
    assert len(devices) == 1
    assert devices[0].pci == "0000:01:00.0"
    assert devices[0].vendor_id == "10de"


def test_gpu_inventory_is_empty_for_missing_sysfs(tmp_path):
    assert host_gpu_devices(tmp_path / "missing") == []
