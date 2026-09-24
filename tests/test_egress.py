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
                                         "rules": [{"kind": "domain", "value": "github.com", "port": 443}]}


def test_runtime_response_is_closed():
    assert _runtime({"address": "198.51.100.200", "gateway": "198.51.100.1", "port": 20200,
                     "mac": "02:00:00:00:00:01"}).proxy_url.endswith(":20200")
    with pytest.raises(EgressError): _runtime({"address": "10.0.0.2", "gateway": "10.0.0.1", "port": 1,
                                                "mac": "broken"})
    with pytest.raises(ValidationError): request_for(Manifest.parse({**restricted().to_dict(), "network": {"mode": "offline"}}))
