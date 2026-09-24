from pathlib import Path

import pytest

from isolatevm.model import Manifest, ValidationError
from isolatevm.storage import (complete_onboarding, first_run, load_instance_manifest, load_template,
                               load_theme, save_instance_manifest, save_template, save_theme,
                               save_template_versioned, export_manifest, export_manifest_versioned, import_manifest,
                               saved_network_bridge)


def sample(**updates):
    raw = {"schemaVersion": 1, "name": "dev-vm",
           "os": {"distribution": "ubuntu", "release": "24.04"},
           "resources": {"cpu": 2, "memoryMiB": 4096, "diskGiB": 30, "pool": "default"},
           "network": {"mode": "offline"}, "mounts": [], "software": {"apt": ["git", "curl"]}}
    raw.update(updates)
    return raw


def test_round_trip_and_defaults():
    manifest = Manifest.parse(sample())
    assert manifest.networkMode == "offline"
    assert manifest.securityProfile == "custom"
    assert manifest.mounts == ()
    assert manifest.desktop is None
    assert "pipx" not in manifest.to_dict()["software"]
    assert Manifest.from_yaml(manifest.to_yaml()) == manifest


def test_pipx_applications_round_trip_with_pins():
    manifest = Manifest.parse(sample(software={"apt": [], "pipx": ["uv==0.12.18", "poetry==2.5.1"]}))
    assert manifest.pipx == ("uv==0.12.18", "poetry==2.5.1")
    assert manifest.to_dict()["software"]["pipx"] == ["uv==0.12.18", "poetry==2.5.1"]
    assert Manifest.from_yaml(manifest.to_yaml()) == manifest
    assert any("uv==0.12.18" in line for line in manifest.review())
    for bad in (["--index-url=https://example.test"], ["uv;touch /tmp/pwn"]):
        with pytest.raises(ValidationError, match="pipx"):
            Manifest.parse(sample(software={"apt": [], "pipx": bad}))


def test_devops_upstream_choices_round_trip_and_reject_unknown_sources():
    selected = ["terraform@hashicorp", "kubectl@1.37", "helm@community"]
    manifest = Manifest.parse(sample(software={"apt": [], "external": selected}))
    assert manifest.externalTools == tuple(selected)
    assert Manifest.from_yaml(manifest.to_yaml()) == manifest
    assert manifest.to_dict()["software"]["external"] == selected
    assert any("Helm comunitário Buildkite" in line for line in manifest.review())
    for invalid in (["kubectl"], ["helm@unknown"], ["terraform;echo pwn"]):
        with pytest.raises(ValidationError, match="DevOps externas"):
            Manifest.parse(sample(software={"apt": [], "external": invalid}))


def test_rustup_and_distro_rust_toolchains_are_mutually_exclusive():
    with pytest.raises(ValidationError, match="Escolha rustup"):
        Manifest.parse(sample(software={"apt": ["rustup", "rustc", "cargo"]}))


@pytest.mark.parametrize(("release", "package"), [("26.04", "dotnet-sdk-8.0"),
                                                    ("22.04", "dotnet-sdk-10.0")])
def test_dotnet_sdk_must_exist_in_the_selected_ubuntu_default_feed(release, package):
    with pytest.raises(ValidationError, match="feed Ubuntu padrão"):
        Manifest.parse(sample(os={"distribution": "ubuntu", "release": release},
                              software={"apt": [package]}))


@pytest.mark.parametrize("disposition", ["persistent", "manual-delete", "delete-on-close",
                                          "restore-initial-on-close", "persist-workspace"])
def test_lifecycle_disposition_round_trips(disposition):
    raw = sample(lifecycle={"disposition": disposition, **(
        {"workspaceSizeGiB": 40} if disposition == "persist-workspace" else {})})
    manifest = Manifest.parse(raw)
    assert manifest.lifecycleDisposition == disposition
    assert Manifest.from_yaml(manifest.to_yaml()) == manifest
    assert any("Ciclo de vida" in line and disposition in line for line in manifest.review())
    if disposition == "persist-workspace":
        assert manifest.workspaceSizeGiB == 40
        assert any("Volume persistente" in line and "40 GiB" in line for line in manifest.review())


@pytest.mark.parametrize("lifecycle", [None, "delete", {"disposition": "delete"},
                                        {"disposition": "delete-on-close", "unexpected": True}])
def test_invalid_lifecycle_disposition_rejected(lifecycle):
    with pytest.raises(ValidationError, match="Ciclo de vida"):
        Manifest.parse(sample(lifecycle=lifecycle))


def test_persistent_workspace_rejects_overlapping_host_mounts(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    project = tmp_path / "project"; project.mkdir()
    for guest in ("/workspace", "/workspace/nested"):
        with pytest.raises(ValidationError, match="mounts host sobrepostos"):
            Manifest.parse(sample(lifecycle={"disposition": "persist-workspace"},
                                  mounts=[{"host": str(project), "guest": guest, "mode": "ro"}]))
    assert Manifest.parse(sample(lifecycle={"disposition": "persist-workspace", "workspaceSizeGiB": 2048})).workspaceSizeGiB == 2048
    for size in (0, 2049, True, "20"):
        with pytest.raises(ValidationError, match="Tamanho persistente"):
            Manifest.parse(sample(lifecycle={"disposition": "persist-workspace", "workspaceSizeGiB": size}))
    with pytest.raises(ValidationError, match="só pode"):
        Manifest.parse(sample(lifecycle={"disposition": "persistent", "workspaceSizeGiB": 20}))


@pytest.mark.parametrize("desktop", ["gnome", "kde", "xfce"])
def test_desktop_is_explicit_and_round_trips(desktop):
    raw = sample(os={"distribution": "ubuntu", "release": "24.04", "desktop": desktop})
    manifest = Manifest.parse(raw)
    assert manifest.desktop == desktop
    assert Manifest.from_yaml(manifest.to_yaml()) == manifest


def test_unknown_desktop_is_rejected():
    with pytest.raises(ValidationError, match="Desktop"):
        Manifest.parse(sample(os={"distribution": "ubuntu", "release": "24.04", "desktop": "custom-command"}))


def test_maximum_isolation_is_enforced_by_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    folder = tmp_path / "project"; folder.mkdir()
    manifest = Manifest.parse(sample(security={"profile": "maximum-isolation"}))
    assert Manifest.from_yaml(manifest.to_yaml()).securityProfile == "maximum-isolation"
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        Manifest.parse(sample(security={"profile": "maximum-isolation"},
                              network={"mode": "normal", "bridge": "incusbr0"}))
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        Manifest.parse(sample(security={"profile": "maximum-isolation"},
                              mounts=[{"host": str(folder), "guest": "/workspace", "mode": "ro"}]))
    with pytest.raises(ValidationError, match="rede restricted"):
        Manifest.parse(sample(security={"profile": "restricted-development"}))


def test_restricted_egress_is_explicit_and_round_trips():
    raw = sample(network={"mode": "restricted", "bridge": "incusbr0", "egress": [
        {"kind": "domain", "value": "API.GitHub.COM.", "port": 443, "protocol": "tcp"},
        {"kind": "cidr", "value": "198.51.100.9/24", "port": 8443, "protocol": "tcp"}]},
        security={"profile": "restricted-development"})
    manifest = Manifest.parse(raw)
    assert [(rule.kind, rule.value, rule.port) for rule in manifest.egress] == [
        ("domain", "api.github.com", 443), ("cidr", "198.51.100.0/24", 8443)]
    assert Manifest.from_yaml(manifest.to_yaml()) == manifest
    raw["network"]["egress"] = []
    with pytest.raises(ValidationError, match="ao menos"):
        Manifest.parse(raw)


def test_environment_is_reproducible_and_rejects_secrets():
    manifest = Manifest.parse(sample(environment={"NODE_ENV": "development", "APP_URL": "https://example.test"}))
    assert manifest.environment == (("APP_URL", "https://example.test"), ("NODE_ENV", "development"))
    assert Manifest.from_yaml(manifest.to_yaml()) == manifest
    for environment in ({"OPENAI_API_KEY": "sk-test"}, {"PATH": "/tmp"},
                        {"SAFE": "$(touch /tmp/unsafe)"}, {"SAFE": "sk-example"}):
        with pytest.raises(ValidationError): Manifest.parse(sample(environment=environment))


def test_secret_references_round_trip_without_values_and_respect_isolation():
    raw = sample(secrets=["OPENAI_API_KEY", "GITHUB_TOKEN"],
                 security={"profile": "normal-development"})
    manifest = Manifest.parse(raw)
    exported = manifest.to_yaml()
    assert manifest.secrets == ("OPENAI_API_KEY", "GITHUB_TOKEN")
    assert "OPENAI_API_KEY" in exported
    assert "synthetic-secret-value" not in exported
    assert Manifest.from_yaml(exported) == manifest
    assert any("Secrets referenciados" in line for line in manifest.review())
    with pytest.raises(ValidationError, match="Máximo isolamento"):
        Manifest.parse(sample(secrets=["OPENAI_API_KEY"],
                              security={"profile": "maximum-isolation"}))
    for refs in (["PATH"], ["LD_PRELOAD"], "OPENAI_API_KEY", [{"OPENAI_API_KEY": "value"}]):
        with pytest.raises(ValidationError):
            Manifest.parse(sample(secrets=refs, security={"profile": "normal-development"}))


def test_import_rejects_ambiguous_yaml():
    text = Manifest.parse(sample()).to_yaml()
    with pytest.raises(ValidationError, match="duplicado"):
        Manifest.from_yaml(text + "name: shadow-vm\n")
    with pytest.raises(ValidationError, match="Aliases"):
        Manifest.from_yaml(text.replace("name: dev-vm", "name: &name dev-vm").replace("pool: default", "pool: *name"))


@pytest.mark.parametrize("raw", [
    sample(name="bad;name"), sample(name="bad-"),
    sample(network={"mode": "restricted", "bridge": "incusbr0"}),
    sample(network={"mode": "normal"}),
    sample(software={"apt": ["git;touch /tmp/pwn"]}),
    sample(resources={"cpu": True, "memoryMiB": 4096, "diskGiB": 30, "pool": "default"}),
    sample(extra="unknown"),
])
def test_rejects_invalid_manifest(raw):
    with pytest.raises(ValidationError): Manifest.parse(raw)


def test_mount_paths_are_explicit_and_sensitive_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    project = tmp_path / "project"; project.mkdir()
    raw = sample(mounts=[{"host": str(project), "guest": "/workspace", "mode": "ro"}])
    assert Manifest.parse(raw).mounts[0].host == str(project)
    secret = tmp_path / ".ssh"; secret.mkdir()
    raw["mounts"][0]["host"] = str(secret)
    with pytest.raises(ValidationError): Manifest.parse(raw)
    link = tmp_path / "linked"; link.symlink_to(project)
    raw["mounts"][0]["host"] = str(link)
    with pytest.raises(ValidationError): Manifest.parse(raw)
    raw["mounts"][0]["host"] = str(tmp_path)
    with pytest.raises(ValidationError): Manifest.parse(raw)


def test_mounts_reject_overlapping_host_or_guest_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    first = tmp_path / "project"; first.mkdir()
    child = first / "child"; child.mkdir()
    second = tmp_path / "dataset"; second.mkdir()
    with pytest.raises(ValidationError, match="host duplicadas ou sobrepostas"):
        Manifest.parse(sample(mounts=[{"host": str(first), "guest": "/workspace", "mode": "ro"},
                                      {"host": str(child), "guest": "/other", "mode": "rw"}]))
    with pytest.raises(ValidationError, match="Destinos de mount"):
        Manifest.parse(sample(mounts=[{"host": str(first), "guest": "/workspace", "mode": "ro"},
                                      {"host": str(second), "guest": "/workspace/data", "mode": "ro"}]))


def test_template_drops_personal_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    project = tmp_path / "project"; project.mkdir()
    manifest = Manifest.parse(sample(mounts=[{"host": str(project), "guest": "/workspace", "mode": "rw"}]))
    path = save_template("safe-dev", manifest)
    assert path.stat().st_mode & 0o777 == 0o600
    assert str(project) not in path.read_text()
    assert not load_template("safe-dev").mounts
    with pytest.raises(ValidationError, match="já existe"):
        save_template("safe-dev", manifest)
    first = save_template_versioned("safe-dev", manifest)
    second = save_template_versioned("safe-dev", manifest)
    assert first.name == "safe-dev-v0001.yaml"
    assert second.name == "safe-dev-v0002.yaml"
    assert not load_template("safe-dev-v0002").mounts


def test_instance_manifest_preserves_declared_access(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    project = tmp_path / "project"; project.mkdir()
    manifest = Manifest.parse(sample(mounts=[{"host": str(project), "guest": "/workspace", "mode": "ro"}]))
    path = save_instance_manifest(manifest)
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_instance_manifest("dev-vm") == manifest


def test_saved_network_bridge_reads_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    manifest = Manifest.parse(sample(network={"mode": "normal", "bridge": "incusbr0"}))
    save_instance_manifest(manifest)
    assert saved_network_bridge("dev-vm") == "incusbr0"
    assert saved_network_bridge("unknown-vm") is None


def test_export_never_overwrites_and_versioned_exports_round_trip(tmp_path):
    manifest = Manifest.parse(sample(secrets=["OPENAI_API_KEY"],
                                     security={"profile": "normal-development"}))
    existing = tmp_path / "dev-vm.yaml"
    existing.write_text("valuable existing data", encoding="utf-8")
    with pytest.raises(ValidationError, match="já existe"):
        export_manifest(manifest, existing)
    assert existing.read_text(encoding="utf-8") == "valuable existing data"
    first = export_manifest_versioned(manifest, tmp_path)
    second = export_manifest_versioned(manifest, tmp_path)
    assert first.name == "dev-vm-v0001.yaml"
    assert second.name == "dev-vm-v0002.yaml"
    assert first.read_bytes() == second.read_bytes()
    assert first.stat().st_mode & 0o777 == 0o600
    assert import_manifest(first) == manifest
    assert "OPENAI_API_KEY" in first.read_text()
    with pytest.raises(ValidationError):
        export_manifest_versioned(manifest, tmp_path / "missing")


def test_theme_preference_is_closed_and_private(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert load_theme() == "system"
    save_theme("dark")
    assert load_theme() == "dark"
    assert (tmp_path / "isolatevm/settings.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValidationError): save_theme("custom-css")


def test_first_run_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert first_run()
    complete_onboarding()
    assert not first_run()
