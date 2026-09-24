import os

from isolatevm.model import Manifest
from isolatevm.mock import MockIncus
from isolatevm.planning import CreationPlan, plan_creation


def manifest():
    return Manifest.parse({"schemaVersion": 1, "name": "planned-vm",
        "os": {"distribution": "ubuntu", "release": "24.04", "desktop": "xfce"},
        "resources": {"cpu": 2, "memoryMiB": 4096, "diskGiB": 30, "pool": "default"},
        "network": {"mode": "offline"}, "mounts": [],
        "software": {"apt": ["git"], "pip": ["requests==2.32.3"], "npm": [],
                     "cargo": ["ripgrep@14.1.1"], "go": ["golang.org/x/tools/gopls@v0.20.0"]},
        "environment": {"NODE_ENV": "development"}})


def test_plan_explains_operations_without_creating_vm(monkeypatch):
    monkeypatch.setattr("isolatevm.planning.host_capacity", lambda: (8, 8192))
    service = MockIncus()
    plan = plan_creation(service, manifest())
    lines = "\n".join(plan.lines())
    assert not service.items
    assert "images:ubuntu/24.04/cloud" in lines
    assert "limite lógico 30 GiB" in lines
    assert "nenhuma NIC" in lines
    assert "xubuntu-desktop" in lines
    assert "requests==2.32.3" in lines
    assert "ripgrep@14.1.1" in lines
    assert "golang.org/x/tools/gopls@v0.20.0" in lines
    assert "NODE_ENV" in lines
    assert "development" not in lines
    assert "Sem rede" in lines


def test_plan_distinguishes_low_capacity_from_allocation():
    m = manifest()
    plan = CreationPlan(m, {"alias": "images:ubuntu/24.04/cloud"},
                        (10 * 1024**3, 100 * 1024**3), 2, 1024, ())
    lines = "\n".join(plan.lines())
    assert "10.0 GiB livres" in lines
    assert "supera o espaço livre" in lines
    assert "RAM solicitada supera" in lines
    assert "limite lógico não é espaço já consumido" in lines


def test_plan_explains_lan_only_proxy_and_private_ranges():
    m = Manifest.parse({"schemaVersion": 1, "name": "lan-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
        "network": {"mode": "lan-only", "bridge": f"incusbr-{os.getuid()}", "egress": [
            {"kind": "cidr", "value": "192.168.1.0/24", "port": 5432}]},
        "security": {"profile": "restricted-development"}, "mounts": [], "software": {"apt": []}})
    service = MockIncus()
    plan = plan_creation(service, m)
    lines = "\n".join(plan.lines())
    assert "Modo LAN-only" in lines
    assert "192.168.1.0/24:5432/tcp" in lines
    assert "alcançáveis pelo host" in lines
