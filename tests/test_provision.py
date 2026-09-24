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
    assert data["runcmd"][2] == ["/usr/sbin/runuser", "--user", "ubuntu", "--", "/usr/bin/env",
                                 "npm_config_prefix=/home/ubuntu/.local", "/usr/bin/npm",
                                 "install", "--global", "typescript@5.0.0"]


def test_package_specs_reject_options_and_shell_text():
    with pytest.raises(ValidationError): manifest({"apt": [], "pip": ["--index-url=https://evil"], "npm": []})
    with pytest.raises(ValidationError): manifest({"apt": [], "pip": [], "npm": ["pkg;touch /tmp/x"]})


def test_no_packages_means_no_cloud_init():
    assert cloud_config(manifest({"apt": [], "pip": [], "npm": []})) is None


def test_persistent_workspace_cloud_init_sets_guest_user_ownership():
    raw = manifest({"apt": [], "pip": [], "npm": []}).to_dict()
    raw["lifecycle"] = {"disposition": "persist-workspace", "workspaceSizeGiB": 12}
    data = yaml.safe_load(cloud_config(Manifest.parse(raw))[len("#cloud-config\n"):])
    assert data["runcmd"] == [
        ["/usr/bin/chown", "1000:1000", "/workspace"],
        ["/usr/bin/chmod", "0750", "/workspace"],
    ]


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


def test_secret_references_install_only_helpers_never_values_in_cloud_init():
    raw = manifest({"apt": []}).to_dict()
    raw["security"] = {"profile": "normal-development"}
    raw["secrets"] = ["OPENAI_API_KEY"]
    config = cloud_config(Manifest.parse(raw))
    data = yaml.safe_load(config[len("#cloud-config\n"):])
    files = {item["path"]: item for item in data["write_files"]}
    injector = files["/usr/local/lib/isolatevm/inject-secrets"]
    runner = files["/usr/local/bin/isolatevm-run"]
    assert injector["permissions"] == "0750"
    assert runner["permissions"] == "0755"
    assert "OPENAI_API_KEY" not in injector["content"]
    assert "OPENAI_API_KEY" not in runner["content"]
    assert "synthetic-secret-value" not in config
    assert "packages" not in data


def test_codex_cli_is_guest_package_without_secret():
    m = manifest({"apt": [], "pip": [], "npm": ["@openai/codex@0.154.0"]})
    config = cloud_config(m)
    assert "@openai/codex@0.154.0" in config
    assert "OPENAI_API_KEY" not in config


def test_ai_coding_packages_use_guest_user_and_keep_authentication_out_of_cloud_init():
    m = manifest({"apt": [], "pip": [],
                  "pipx": ["aider-chat==0.86.2"],
                  "npm": ["@openai/codex@0.154.0", "@anthropic-ai/claude-code@2.1.276",
                          "opencode-ai@1.18.31"]})
    data = yaml.safe_load(cloud_config(m)[len("#cloud-config\n"):])
    npm_install = next(command for command in data["runcmd"] if "/usr/bin/npm" in command)
    assert npm_install[:4] == ["/usr/sbin/runuser", "--user", "ubuntu", "--"]
    assert "npm_config_prefix=/home/ubuntu/.local" in npm_install
    assert npm_install[-3:] == ["@openai/codex@0.154.0", "@anthropic-ai/claude-code@2.1.276",
                                "opencode-ai@1.18.31"]
    assert ["/usr/sbin/runuser", "--user", "ubuntu", "--", "pipx", "install",
            "aider-chat==0.86.2"] in data["runcmd"]
    profile = next(item for item in data["write_files"]
                   if item["path"] == "/etc/profile.d/isolatevm-user-tools.sh")
    assert "/home/ubuntu/.local/bin" in profile["content"]
    assert "OPENAI_API_KEY" not in yaml.safe_dump(data)


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


def test_python_cli_tools_use_pipx_as_the_guest_user_and_pinned_versions():
    m = manifest({"apt": [], "pipx": ["uv==0.12.18", "poetry==2.5.1"]})
    data = yaml.safe_load(cloud_config(m)[len("#cloud-config\n"):])
    assert data["packages"] == ["pipx", "python3-venv"]
    assert data["runcmd"] == [
        ["/usr/sbin/runuser", "--user", "ubuntu", "--", "pipx", "install", "uv==0.12.18"],
        ["/usr/sbin/runuser", "--user", "ubuntu", "--", "pipx", "install", "poetry==2.5.1"],
    ]
    path_file = next(item for item in data["write_files"]
                     if item["path"] == "/etc/profile.d/isolatevm-user-tools.sh")
    assert "/home/ubuntu/.local/bin" in path_file["content"]
    assert path_file["owner"] == "root:root" and path_file["permissions"] == "0644"


def test_rustup_installs_stable_toolchain_as_guest_user():
    m = manifest({"apt": ["rustup"]})
    data = yaml.safe_load(cloud_config(m)[len("#cloud-config\n"):])
    assert data["packages"] == ["rustup"]
    assert data["runcmd"] == [["/usr/sbin/runuser", "--user", "ubuntu", "--",
                               "rustup", "default", "stable"]]


def test_devops_tools_use_whitelisted_signed_repositories_inside_guest():
    tools = ["kubectl@1.37", "helm@community", "terraform@hashicorp"]
    m = manifest({"apt": [], "external": tools})
    data = yaml.safe_load(cloud_config(m)[len("#cloud-config\n"):])
    assert data["packages"] == ["ca-certificates", "curl", "gnupg"]
    assert data["runcmd"] == [["/usr/local/lib/isolatevm/setup-devops-packages", *tools]]
    helper = next(item for item in data["write_files"]
                  if item["path"] == "/usr/local/lib/isolatevm/setup-devops-packages")
    assert helper["owner"] == "root:root" and helper["permissions"] == "0750"
    assert "DDF78C3E6EBB2D2CC223C95C62BA89D07698DBC6" in helper["content"]
    assert "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560" in helper["content"]
    assert "stable:/v1.37/deb" in helper["content"]
    assert "eval " not in helper["content"]


@pytest.mark.parametrize("software", [
    {"cargo": ["ripgrep@latest"]}, {"cargo": ["--root=/host@1.0.0"]},
    {"go": ["example.com/tool@latest"]}, {"go": ["example.com/../tool@v1.2.3"]},
    {"go": ["example.com/tool@v1.2.3;touch /tmp/unsafe"]},
])
def test_cargo_and_go_reject_unpinned_or_unsafe_specs(software):
    with pytest.raises(ValidationError):
        manifest(software)
