import pytest

from isolatevm import change_diff as diff
from isolatevm.model import Mount, ValidationError


def effective():
    return {
        "config": {"config": {"limits.cpu": "2", "limits.memory": "2048MiB"}},
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
    with pytest.raises(ValidationError, match="já possuem"):
        diff.resources(current, 2, 2048)
    with pytest.raises(ValidationError, match="indisponíveis"):
        diff.resources({"config": {}}, 4, 4096)


def test_mount_diff_refuses_overlap_and_missing_managed_device():
    current = effective()
    mount = Mount("/home/user/data", "/data", "rw")
    assert "+ /home/user/data → /data [RW]" in diff.mount_add(current, mount).text()
    with pytest.raises(ValidationError, match="sobrepõe"):
        diff.mount_add(current, Mount("/home/user/data", "/workspace/nested", "ro"))
    assert "- /home/user/project → /workspace [RO]" in diff.mount_remove(current, "isovm0").text()
    with pytest.raises(ValidationError, match="não está mais presente"):
        diff.mount_remove(current, "isovm9")


def test_network_diff_distinguishes_restricted_and_normal():
    current = effective()
    assert "- eth0: incusbr0" in diff.network_block(current).text()
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
    assert "- isousb0: usb anexado" in diff.device_remove(current, "isousb0").text()
    current["config"]["devices"] = {"isousb0": {"type": "usb", "vendorid": "1234", "productid": "5678",
                                                   "busnum": "1", "devnum": "7"}}
    assert "bus 1 device 7" in diff.device_remove(current, "isousb0").text()
    current["config"]["devices"]["isousb0"]["serial"] = "camera-serial"
    assert "serial camera-serial" in diff.device_remove(current, "isousb0").text()
    current["other_devices"][0]["managed"] = False
    with pytest.raises(ValidationError, match="não está mais presente"):
        diff.device_remove(current, "isousb0")
