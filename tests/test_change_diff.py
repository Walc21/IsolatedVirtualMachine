import pytest

from isolatevm import change_diff as diff
from isolatevm.model import Mount, ValidationError


def effective():
    return {
        "config": {"config": {"limits.cpu": "2", "limits.memory": "2048MiB"},
                   "devices": {"root": {"type": "disk", "path": "/"},
                               "isovm0": {"type": "disk"}, "eth0": {"type": "nic"},
                               "isousb0": {"type": "usb"}}},
        "mounts": [{"device": "isovm0", "managed": True, "source": "/home/user/project",
                    "path": "/workspace", "mode": "RO"}],
        "volumes": [],
        "nics": [{"device": "eth0", "network": "incusbr0", "nictype": "bridged"}],
        "can_block_network": True,
        "security_profile": "normal-development",
        "other_devices": [{"device": "isousb0", "managed": True, "type": "usb"}],
    }


def test_resources_show_before_after_from_effective_state():
    current = effective()
    preview = diff.resources(current, 4, 4096)
    assert "- CPU: 2; RAM: 2048MiB" in preview.text()
    assert "+ CPU: 4; RAM: 4096MiB" in preview.text()
    assert "incus config set '<VM>' limits.cpu=4 limits.memory=4096MiB" in preview.text()
    with pytest.raises(ValidationError, match="já possuem"):
        diff.resources(current, 2, 2048)
    with pytest.raises(ValidationError, match="indisponíveis"):
        diff.resources({"config": {}}, 4, 4096)


def test_cpu_pin_preview_uses_range_syntax_for_a_single_host_thread():
    current = effective()
    preview = diff.cpu_pin(current, "6", "vm-name")
    assert "+ limits.cpu: 6-6 · threads lógicas do host selecionadas" in preview.text()
    assert "incus config set vm-name limits.cpu=6-6" in preview.text()


def test_root_disk_preview_only_allows_increase_of_a_verified_gib_disk():
    current = effective()
    current["config"]["devices"] = {"root": {"type": "disk", "path": "/", "size": "20GiB"}}
    preview = diff.root_disk_grow(current, 40)
    assert "- root: 20 GiB" in preview.text()
    assert "+ root: 40 GiB" in preview.text()
    assert "não pode ser desfeita" in preview.text()
    for requested in (20, 10, 2049, True):
        with pytest.raises(ValidationError):
            diff.root_disk_grow(current, requested)


def test_data_volume_previews_are_explicit_and_deletion_lists_both_mutations():
    current = effective()
    added = diff.data_volume_add(current, "default", "project-data", 12,
                                 "/data", True, "vm-name")
    assert "+ project-data · 12 GiB · default → /data · RO" in added.text()
    assert "storage volume create default project-data" in added.text()
    assert "readonly=true" in added.text()
    assert "backups" in added.text()
    current["config"]["devices"]["isodata0"] = {
        "type": "disk", "pool": "default", "source": "project-data", "path": "/data"}
    current["volumes"] = [{"device": "isodata0", "source": "project-data", "path": "/data"}]
    removed = diff.data_volume_remove(current, "isodata0", "vm-name")
    assert "removido definitivamente" in removed.text()
    assert "incus storage volume delete default project-data" in removed.text()
    with pytest.raises(ValidationError, match="se sobrepõe"):
        diff.data_volume_add(current, "default", "another-data", 4, "/data/nested", False)


def test_data_volume_previews_are_explicit_and_deletion_lists_both_mutations():
    current = effective()
    added = diff.data_volume_add(current, "default", "project-data", 12,
                                 "/data", True, "vm-name")
    assert "+ project-data · 12 GiB · default → /data · RO" in added.text()
    assert "storage volume create default project-data" in added.text()
    assert "readonly=true" in added.text()
    assert "backups" in added.text()
    current["config"]["devices"]["isodata0"] = {
        "type": "disk", "pool": "default", "source": "project-data", "path": "/data"}
    current["volumes"] = [{"device": "isodata0", "source": "project-data", "path": "/data"}]
    removed = diff.data_volume_remove(current, "isodata0", "vm-name")
    assert "removido definitivamente" in removed.text()
    assert "incus storage volume delete default project-data" in removed.text()
    with pytest.raises(ValidationError, match="se sobrepõe"):
        diff.data_volume_add(current, "default", "another-data", 4, "/data/nested", False)


def test_mount_diff_refuses_overlap_and_missing_managed_device():
    current = effective()
    mount = Mount("/home/user/data", "/data", "rw")
    preview = diff.mount_add(current, mount, "vm-name")
    assert "+ /home/user/data → /data [RW]" in preview.text()
    spaced = diff.mount_add(current, Mount("/home/user/Project Name", "/scratch", "ro"), "vm-name")
    assert "'source=/home/user/Project Name'" in spaced.text()
    assert "incus config device add vm-name isovm1 disk" in spaced.text()
    with pytest.raises(ValidationError, match="sobrepõe"):
        diff.mount_add(current, Mount("/home/user/data", "/workspace/nested", "ro"))
    assert "- /home/user/project → /workspace [RO]" in diff.mount_remove(current, "isovm0").text()
    with pytest.raises(ValidationError, match="não está mais presente"):
        diff.mount_remove(current, "isovm9")


def test_network_diff_distinguishes_restricted_and_normal():
    current = effective()
    assert "- eth0: incusbr0" in diff.network_block(current).text()
    assert "incus config device remove '<VM>' eth0" in diff.network_block(current).text()
    current["nics"] = []
    current["security_profile"] = "restricted-development"
    assert "allowlist/proxy" in diff.network_restore(current, "incusbr0").text()
    current["security_profile"] = "normal-development"
    assert "não filtra domínios" in diff.network_restore(current, "incusbr0").text()
    current["security_profile"] = "maximum-isolation"
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        diff.network_restore(current, "incusbr0")


def test_device_diff_identifies_managed_removal():
    current = effective()
    assert "+ USB 1234:5678" in diff.device_add(current, "USB", "Synthetic USB", "1234:5678").text()
    pci_preview = diff.device_add(current, "PCI", "Audio controller", "0000:02:00.0")
    assert "+ PCI 0000:02:00.0" in pci_preview.text()
    assert "IOMMU" in pci_preview.text()
    pci_command = diff.device_add(current, "PCI", "Audio controller", "0000:02:00.0",
                                  "vm-name", ("address=0000:02:00.0", "firmware=false"))
    assert "incus config device add vm-name isopci0 pci address=0000:02:00.0 firmware=false" in pci_command.text()
    assert "- isousb0: usb ?:? anexado" in diff.device_remove(current, "isousb0").text()
    current["config"]["devices"] = {"isousb0": {"type": "usb", "vendorid": "1234", "productid": "5678",
                                                   "busnum": "1", "devnum": "7"}}
    assert "bus 1 device 7" in diff.device_remove(current, "isousb0").text()
    current["config"]["devices"]["isousb0"]["serial"] = "camera-serial"
    assert "serial camera-serial" in diff.device_remove(current, "isousb0").text()
    current["other_devices"][0]["managed"] = False
    with pytest.raises(ValidationError, match="não está mais presente"):
        diff.device_remove(current, "isousb0")
