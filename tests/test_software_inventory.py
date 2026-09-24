import json

from isolatevm.incus import IncusError, LocalIncus
from isolatevm.model import Manifest
from isolatevm.provision import apt_packages
from isolatevm.software_inventory import (entries_for, normalize_name, parse_cargo,
                                          parse_dpkg, parse_go, parse_npm, parse_pip,
                                          parse_go_modules, parse_pipx, parse_rustc,
                                          SoftwareInventoryEntry)
from isolatevm.storage import save_instance_manifest


def test_dpkg_parser_uses_only_installed_rows_and_ignores_architecture():
    rows = parse_dpkg("git:amd64\t2.43.0\tinstalled\n"
                      "broken\t1.0\tconfig-files\n"
                      "missing\t\tnot-installed\n")
    assert rows == {"git": "2.43.0"}


def test_python_pipx_and_npm_parsers_read_declared_packages():
    pip = parse_pip(json.dumps([{"name": "Requests", "version": "2.32.3"}]))
    pipx = parse_pipx(json.dumps({"pipx_spec_version": "0.1", "venvs": {
        "uv": {"metadata": {"main_package": {"package": "uv", "package_version": "0.12.18"}}}}}))
    npm = parse_npm(json.dumps({"dependencies": {"@scope/tool": {"version": "1.2.3"}}}))
    assert entries_for("pip", ["requests==2.32.3", "pytest"], pip) == [
        SoftwareInventoryEntry("pip", "requests==2.32.3", "installed", "2.32.3"),
        SoftwareInventoryEntry("pip", "pytest", "missing", None),
    ]
    assert entries_for("pip", ["requests==2.31.0"], pip)[0].status == "version-mismatch"
    assert "uv" in pipx and normalize_name("uv", "pipx") in pipx
    assert entries_for("npm", ["@scope/tool@1.2.3"], npm)[0] == SoftwareInventoryEntry(
        "npm", "@scope/tool@1.2.3", "installed", "1.2.3")


def test_cargo_and_go_parsers_extract_resolved_versions():
    cargo = parse_cargo("ripgrep v14.1.1:\n    rg\nother-tool v2.0.0:\n    other\n")
    go = """/usr/local/bin/gopls: go1.24.4
    path golang.org/x/tools/gopls
    mod golang.org/x/tools/gopls v0.20.0 h1:ignored
"""
    assert cargo == {"ripgrep": "14.1.1", "other-tool": "2.0.0"}
    assert parse_go(go, "golang.org/x/tools/gopls") == "v0.20.0"
    assert parse_go(go, "example.com/other/tool") is None
    assert parse_go_modules(go + "mod example.com/cli/tool v1.2.0 h1:ignored\n",
                            ["golang.org/x/tools/gopls", "example.com/cli/tool"]) == {
                                "golang.org/x/tools/gopls": "v0.20.0",
                                "example.com/cli/tool": "v1.2.0",
                            }
    assert parse_rustc("rustc 1.87.0 (17067e9ac 2025-05-09)\n") == "1.87.0"


def _manifest() -> Manifest:
    return Manifest.parse({
        "schemaVersion": 1,
        "name": "inventory-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
        "network": {"mode": "offline"},
        "mounts": [],
        "software": {
            "apt": ["git"], "pip": ["requests==2.32.3"],
            "pipx": ["uv==0.12.18"], "npm": ["@scope/tool@1.2.3"],
            "cargo": ["ripgrep@14.1.1"],
            "go": ["golang.org/x/tools/gopls@v0.20.0"],
            "external": ["terraform@hashicorp"],
        },
        "security": {"profile": "maximum-isolation"},
    })


def test_local_inventory_queries_fixed_guest_commands_and_returns_versions(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    manifest = _manifest()
    save_instance_manifest(manifest)
    service = LocalIncus.__new__(LocalIncus)
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        command = args[3:]
        if command[:2] == ("dpkg-query", "-W"):
            names = apt_packages(manifest) + ("terraform",)
            return "".join(f"{name}\t1.2.3\tinstalled\n" for name in dict.fromkeys(names))
        if command[:4] == ("/opt/isolatevm/python/bin/python", "-m", "pip", "list"):
            return json.dumps([{"name": "requests", "version": "2.32.3"}])
        if command[:5] == ("/usr/sbin/runuser", "--user", "ubuntu", "--", "pipx"):
            return json.dumps({"venvs": {"uv": {"metadata": {
                "main_package": {"package": "uv", "package_version": "0.12.18"}}}}})
        if command[:8] == ("/usr/sbin/runuser", "--user", "ubuntu", "--", "/usr/bin/env",
                           "npm_config_prefix=/home/ubuntu/.local", "/usr/bin/npm", "list"):
            return json.dumps({"dependencies": {"@scope/tool": {"version": "1.2.3"}}})
        if command[:5] == ("/usr/bin/cargo", "install", "--root", "/usr/local", "--list"):
            return "ripgrep v14.1.1:\n    rg\n"
        if command[:3] == ("go", "version", "-m"):
            return "mod golang.org/x/tools/gopls v0.20.0 h1:ignored\n"
        raise AssertionError(f"unexpected guest command: {args}")

    service._run = run
    entries = service.software_inventory(manifest.name)
    by_package = {item.package: item for item in entries}
    assert len(entries) == len(apt_packages(manifest)) + 1 + 1 + 1 + 1 + 1 + 1
    assert by_package["git"].status == "installed"
    assert by_package["git"].version == "1.2.3"
    assert by_package["requests==2.32.3"].version == "2.32.3"
    assert by_package["uv==0.12.18"].version == "0.12.18"
    assert by_package["@scope/tool@1.2.3"].version == "1.2.3"
    assert by_package["ripgrep@14.1.1"].version == "14.1.1"
    assert by_package["golang.org/x/tools/gopls@v0.20.0"].version == "v0.20.0"
    assert all(call[3] != "sh" and "-c" not in call for call in calls)


def test_local_inventory_marks_failed_queries_unavailable(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    manifest = _manifest()
    save_instance_manifest(manifest)
    service = LocalIncus.__new__(LocalIncus)
    service._run = lambda *_args, **_kwargs: (_ for _ in ()).throw(IncusError("guest offline"))
    entries = service.software_inventory(manifest.name)
    assert entries
    assert all(item.status == "unavailable" for item in entries)


def test_local_inventory_checks_rustup_toolchain_at_users_fixed_path(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    raw = _manifest().to_dict()
    raw["software"]["apt"].append("rustup")
    manifest = Manifest.parse(raw)
    save_instance_manifest(manifest)
    service = LocalIncus.__new__(LocalIncus)
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        command = args[3:]
        if command[:2] == ("dpkg-query", "-W"):
            names = apt_packages(manifest) + ("terraform",)
            return "".join(f"{name}\t1.2.3\tinstalled\n" for name in dict.fromkeys(names))
        if command[:4] == ("/opt/isolatevm/python/bin/python", "-m", "pip", "list"):
            return json.dumps([{"name": "requests", "version": "2.32.3"}])
        if command[:8] == ("/usr/sbin/runuser", "--user", "ubuntu", "--", "/usr/bin/env",
                           "npm_config_prefix=/home/ubuntu/.local", "/usr/bin/npm", "list"):
            return json.dumps({"dependencies": {"@scope/tool": {"version": "1.2.3"}}})
        if command[:4] == ("/usr/sbin/runuser", "--user", "ubuntu", "--"):
            if command[-2:] == ("/home/ubuntu/.cargo/bin/rustc", "--version"):
                return "rustc 1.87.0 (17067e9ac 2025-05-09)\n"
            if command[4:5] == ("pipx",):
                return json.dumps({"venvs": {"uv": {"metadata": {
                    "main_package": {"package": "uv", "package_version": "0.12.18"}}}}})
        if command[:3] == ("/usr/bin/cargo", "install", "--root"):
            return "ripgrep v14.1.1:\n    rg\n"
        if command[:3] == ("go", "version", "-m"):
            return "mod golang.org/x/tools/gopls v0.20.0 h1:ignored\n"
        raise AssertionError(f"unexpected guest command: {args}")

    service._run = run
    entries = service.software_inventory(manifest.name)
    rust = next(item for item in entries if item.manager == "rustup")
    assert rust.status == "installed" and rust.version == "1.87.0"
    assert any(call[-2:] == ("/home/ubuntu/.cargo/bin/rustc", "--version") for call in calls)


def test_mock_inventory_never_claims_real_guest_versions():
    from isolatevm.mock import MockIncus

    manifest = _manifest()
    service = MockIncus()
    service.create(manifest)
    entries = service.software_inventory(manifest.name)
    assert entries
    assert all(item.status == "simulated" and item.version is None for item in entries)
