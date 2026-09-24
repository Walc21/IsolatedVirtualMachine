from isolatevm.permissions import describe_effective


def test_effective_separates_host_paths_volumes_nics_and_proxy():
    config = {"profiles": ["lab"], "config": {"raw.qemu": "redacted elsewhere"},
              "devices": {
                  "root": {"type": "disk", "path": "/", "pool": "default"},
                  "workspace": {"type": "disk", "source": "/home/alice/project", "path": "/workspace", "readonly": "true"},
                  "data": {"type": "disk", "source": "dataset-volume", "path": "/data"},
                  "eth0": {"type": "nic", "network": "incusbr0"},
                  "forward": {"type": "proxy", "listen": "tcp:127.0.0.1:8080"}}}
    summary = describe_effective(config, {"devices": config["devices"], "config": {}})
    assert [x["source"] for x in summary["mounts"]] == ["/home/alice/project"]
    assert summary["mounts"][0]["mode"] == "RO"
    assert not summary["mounts"][0]["managed"]
    assert [x["source"] for x in summary["volumes"]] == ["dataset-volume"]
    assert summary["nics"][0]["network"] == "incusbr0"
    assert summary["other_devices"] == [{"device": "forward", "type": "proxy", "managed": False}]
    assert summary["profiles"] == ["lab"]
    assert summary["can_block_network"] is False
    assert any("rede" in x for x in summary["warnings"])


def test_proxy_without_nic_never_claims_offline():
    config = {"devices": {"forward": {"type": "proxy"}}, "config": {}, "profiles": []}
    summary = describe_effective(config, config)
    assert "podem fornecer rede" in summary["network"]
    assert summary["can_block_network"] is False


def test_usb_effective_identity_prefers_serial_then_live_address():
    config = {"devices": {
        "isousb0": {"type": "usb", "vendorid": "1234", "productid": "abcd", "serial": "camera-serial"},
        "isousb1": {"type": "usb", "vendorid": "1234", "productid": "abcd", "busnum": "1", "devnum": "7"}},
        "config": {"user.isolatevm.managed": "true"}, "profiles": []}
    summary = describe_effective(config, config)
    assert summary["other_devices"] == [
        {"device": "isousb0", "type": "usb", "managed": True, "identity": "1234:abcd · serial camera-serial"},
        {"device": "isousb1", "type": "usb", "managed": True, "identity": "1234:abcd · bus 1 device 7"},
    ]


def test_managed_mount_and_nic_require_marker_and_no_profiles():
    config = {"devices": {"isovm0": {"type": "disk", "source": "/home/alice/project", "path": "/workspace"},
                          "eth0": {"type": "nic", "network": "incusbr0"}},
              "config": {"user.isolatevm.managed": "true"}, "profiles": []}
    summary = describe_effective(config, config)
    assert summary["mounts"][0]["managed"] is True
    assert summary["can_block_network"] is True
    config["profiles"] = ["default"]
    summary = describe_effective(config, config)
    assert summary["mounts"][0]["managed"] is False
    assert summary["can_block_network"] is False


def test_maximum_isolation_flags_external_device_drift():
    config = {"devices": {"eth0": {"type": "nic", "network": "incusbr0"}},
              "config": {"user.isolatevm.security-profile": "maximum-isolation"}, "profiles": []}
    summary = describe_effective(config, config)
    assert any("diverge" in finding for finding in summary["warnings"])


def test_maximum_isolation_allows_only_marked_managed_workspace_volume():
    volume = "isolatevm-ws-0123456789abcdef01234567"
    config = {"devices": {
                  "root": {"type": "disk", "path": "/", "pool": "default"},
                  "isovm-workspace": {"type": "disk", "pool": "default",
                                      "source": volume, "path": "/workspace"}},
              "config": {"user.isolatevm.managed": "true",
                         "user.isolatevm.security-profile": "maximum-isolation",
                         "user.isolatevm.lifecycle-disposition": "persist-workspace",
                         "user.isolatevm.workspace-volume": volume}, "profiles": []}
    summary = describe_effective(config, config)
    assert summary["volumes"] == [{"device": "isovm-workspace", "source": volume, "path": "/workspace"}]
    assert not any("Máximo isolamento diverge" in finding for finding in summary["warnings"])
    config["devices"]["isovm-workspace"]["source"] = "/home/alice/project"
    summary = describe_effective(config, config)
    assert summary["mounts"] and any("Máximo isolamento diverge" in finding for finding in summary["warnings"])
