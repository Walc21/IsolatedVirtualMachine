import yaml
import pytest

from isolatevm.model import Manifest, ValidationError
from isolatevm.provision import GO_INSTALL_RETRY, cloud_config


def manifest(software):
    return Manifest.parse({"schemaVersion": 1, "name": "package-vm",
        "os": {"distribution": "ubuntu", "release": "24.04"},
        "resources": {"cpu": 2, "memoryMiB": 2048, "diskGiB": 20, "pool": "default"},
        "network": {"mode": "offline"}, "mounts": [], "software": software})


def test_cloud_init_uses_argv_lists_inside_guest():
    config = cloud_config(manifest({"apt": ["git"], "pip": ["requests==2.32.3"],
                                    "npm": ["typescript@5.0.0"]}))
    assert config.startswith("#cloud-config\n")
    data = yaml.safe_load(config[len("#cloud-config\n"):])
    assert data["packages"] == ["git", "python3", "python3-venv", "nodejs", "npm"]
    assert data["runcmd"][1] == ["/opt/isolatevm/python/bin/pip", "install", "requests==2.32.3"]
    assert data["runcmd"][2] == ["npm", "install", "--global", "typescript@5.0.0"]


def test_package_specs_reject_options_and_shell_text():
    with pytest.raises(ValidationError): manifest({"apt": [], "pip": ["--index-url=https://evil"], "npm": []})
    with pytest.raises(ValidationError): manifest({"apt": [], "pip": [], "npm": ["pkg;touch /tmp/x"]})


def test_no_packages_means_no_cloud_init():
    assert cloud_config(manifest({"apt": [], "pip": [], "npm": []})) is None


def test_restricted_proxy_is_written_for_apt_and_interactive_tools():
    config = cloud_config(manifest({"apt": []}), "http://198.51.100.1:20200")
    data = yaml.safe_load(config[len("#cloud-config\n"):])
    files = {item["path"]: item for item in data["write_files"]}
    assert 'Acquire::https::Proxy "http://198.51.100.1:20200";' in files["/etc/apt/apt.conf.d/90isolatevm-proxy"]["content"]
    assert "HTTPS_PROXY=http://198.51.100.1:20200" in files["/etc/profile.d/isolatevm-proxy.sh"]["content"]


@pytest.mark.parametrize("desktop, package", [
    ("gnome", "ubuntu-desktop-minimal"), ("kde", "kubuntu-desktop"), ("xfce", "xubuntu-desktop")])
def test_desktop_adds_only_selected_guest_metapackage(desktop, package):
    raw = manifest({"apt": [], "pip": [], "npm": []}).to_dict()
    raw["os"]["desktop"] = desktop
    config = cloud_config(Manifest.parse(raw))
    data = yaml.safe_load(config[len("#cloud-config\n"):])
    assert data["packages"] == [package]
    assert data["package_update"] is True
    assert "runcmd" not in data


def test_non_secret_environment_uses_structured_cloud_init_file():
    raw = manifest({"apt": [], "pip": [], "npm": []}).to_dict()
    raw["environment"] = {"NODE_ENV": "development"}
    config = cloud_config(Manifest.parse(raw))
    data = yaml.safe_load(config[len("#cloud-config\n"):])
    assert data["write_files"] == [{"path": "/etc/environment", "content": "\nNODE_ENV=development\n",
                                   "append": True, "owner": "root:root", "permissions": "0644"}]
    assert "runcmd" not in data


def test_codex_cli_is_guest_package_without_secret():
    m = manifest({"apt": [], "pip": [], "npm": ["@openai/codex@latest"]})
    config = cloud_config(m)
    assert "@openai/codex@latest" in config
    assert "OPENAI_API_KEY" not in config


def test_pinned_cargo_and_go_tools_use_structured_guest_commands():
    m = manifest({"apt": [], "cargo": ["ripgrep@14.1.1"],
                  "go": ["golang.org/x/tools/gopls@v0.20.0"]})
    assert Manifest.from_yaml(m.to_yaml()) == m
    config = cloud_config(m)
    data = yaml.safe_load(config[len("#cloud-config\n"):])
    assert data["packages"] == ["cargo", "build-essential", "golang-go"]
    assert data["runcmd"] == [
        ["cargo", "install", "--locked", "--root", "/usr/local", "--version", "14.1.1", "ripgrep"],
        ["/usr/local/lib/isolatevm/go-install", "golang.org/x/tools/gopls@v0.20.0"]]
    assert data["write_files"] == [{"path": "/usr/local/lib/isolatevm/go-install",
        "content": GO_INSTALL_RETRY, "owner": "root:root", "permissions": "0755"}]


@pytest.mark.parametrize("software", [
    {"cargo": ["ripgrep@latest"]}, {"cargo": ["--root=/host@1.0.0"]},
    {"go": ["example.com/tool@latest"]}, {"go": ["example.com/../tool@v1.2.3"]},
    {"go": ["example.com/tool@v1.2.3;touch /tmp/unsafe"]},
])
def test_cargo_and_go_reject_unpinned_or_unsafe_specs(software):
    with pytest.raises(ValidationError):
        manifest(software)
