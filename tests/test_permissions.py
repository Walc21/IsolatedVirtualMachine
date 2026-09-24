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
