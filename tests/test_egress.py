import pytest

from isolatevm.egress import EgressError, _runtime, request_for
from isolatevm.model import Manifest, ValidationError


def restricted():
    return Manifest.parse({"schemaVersion": 1, "name": "locked-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
        "network": {"mode": "restricted", "bridge": "incusbr0", "egress": [
            {"kind": "domain", "value": "github.com", "port": 443, "protocol": "tcp"}]},
        "security": {"profile": "restricted-development"}, "mounts": [], "software": {"apt": []}})


def test_helper_request_has_only_typed_fields():
    assert request_for(restricted()) == {"version": 1, "name": "locked-vm", "bridge": "incusbr0",
                                         "network_mode": "restricted",
                                         "rules": [{"kind": "domain", "value": "github.com", "port": 443}]}


def test_runtime_response_is_closed():
    assert _runtime({"address": "198.51.100.200", "gateway": "198.51.100.1", "port": 20200,
                     "mac": "02:00:00:00:00:01"}).proxy_url.endswith(":20200")
    with pytest.raises(EgressError): _runtime({"address": "10.0.0.2", "gateway": "10.0.0.1", "port": 1,
                                                "mac": "broken"})
    with pytest.raises(ValidationError): request_for(Manifest.parse({**restricted().to_dict(), "network": {"mode": "offline"}}))


def lan_only(network):
    return Manifest.parse({"schemaVersion": 1, "name": "locked-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
        "network": {"mode": "lan-only", "bridge": "incusbr0", "egress": network},
        "security": {"profile": "restricted-development"}, "mounts": [],
        "software": {"apt": []}})


def test_lan_only_manifest_uses_private_ipv4_cidrs_and_proxy():
    manifest = lan_only([{"kind": "cidr", "value": "192.168.1.0/24", "port": 5432}])
    assert request_for(manifest)["network_mode"] == "lan-only"
    assert request_for(manifest)["rules"] == [{"kind": "cidr", "value": "192.168.1.0/24", "port": 5432}]
    with pytest.raises(ValidationError, match="CIDRs dentro"):
        lan_only([{"kind": "cidr", "value": "8.8.8.0/24", "port": 5432}])
    with pytest.raises(ValidationError, match="CIDRs IPv4 privados"):
        lan_only([{"kind": "domain", "value": "printer.local", "port": 443}])


def test_privileged_helper_revalidates_lan_only_cidr_restriction():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).parents[1] / "packaging" / "isolatevm-egress-helper.py"
    spec = importlib.util.spec_from_file_location("isolatevm_egress_helper_test", path)
    assert spec and spec.loader
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    private = [{"kind": "cidr", "value": "10.20.0.0/16", "port": 443}]
    assert helper.rules(private, "lan-only") == private
    with pytest.raises(helper.Error, match="RFC1918"):
        helper.rules([{"kind": "cidr", "value": "0.0.0.0/0", "port": 443}], "lan-only")
    with pytest.raises(helper.Error, match="RFC1918"):
        helper.rules([{"kind": "domain", "value": "example.com", "port": 443}], "lan-only")
