"""Structured cloud-init generation for guest-only package installation."""
from __future__ import annotations

import yaml
from pathlib import Path

from .model import DESKTOP_PACKAGES, Manifest
from .workspace_volume import (WORKSPACE_GUEST_GID, WORKSPACE_GUEST_MODE,
                               WORKSPACE_GUEST_UID)


GO_INSTALL_RETRY = """#!/bin/sh
set -eu
[ \"$#\" -eq 1 ]
attempt=1
until env GOBIN=/usr/local/bin GOPATH=/opt/isolatevm/go GOCACHE=/opt/isolatevm/go-cache GOTOOLCHAIN=local go install \"$1\"; do
    if [ \"$attempt\" -ge 3 ]; then
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 5
done
"""


def apt_packages(manifest: Manifest) -> tuple[str, ...]:
    apt = list(manifest.apt)
    if manifest.desktop:
        apt.append(DESKTOP_PACKAGES[manifest.desktop])
    if manifest.pip:
        apt.extend(["python3", "python3-venv"])
    if manifest.npm:
        apt.extend(["nodejs", "npm"])
    if manifest.cargo:
        apt.extend(["cargo", "build-essential"])
    if manifest.go:
        apt.append("golang-go")
    if manifest.pipx:
        apt.extend(["pipx", "python3-venv"])
    if manifest.externalTools:
        apt.extend(["ca-certificates", "curl", "gnupg"])
    return tuple(dict.fromkeys(apt))


def _guest_helper(filename: str) -> str:
    candidates = (Path("/usr/lib/isolatevm/guest") / filename,
                  Path(__file__).resolve().parents[1] / "packaging" / "guest" / filename)
    for path in candidates:
        if path.is_file():
            return path.read_text(encoding="utf-8")
    raise FileNotFoundError(f"Guest helper ausente: {filename}")


def cloud_config(manifest: Manifest, proxy_url: str | None = None) -> str | None:
    apt = apt_packages(manifest)
    commands: list[list[str]] = []
    files: list[dict[str, object]] = []
    if manifest.pip:
        commands.append(["python3", "-m", "venv", "/opt/isolatevm/python"])
        commands.append(["/opt/isolatevm/python/bin/pip", "install", *manifest.pip])
    if manifest.npm:
        commands.append(["npm", "install", "--global", *manifest.npm])
    for spec in manifest.cargo:
        crate, version = spec.rsplit("@", 1)
        commands.append(["cargo", "install", "--locked", "--root", "/usr/local",
                         "--version", version, crate])
    for spec in manifest.go:
        commands.append(["/usr/local/lib/isolatevm/go-install", spec])
    if manifest.externalTools:
        commands.append(["/usr/local/lib/isolatevm/setup-devops-packages", *manifest.externalTools])
    for spec in manifest.pipx:
        commands.append(["/usr/sbin/runuser", "--user", "ubuntu", "--", "pipx", "install", spec])
    if "rustup" in manifest.apt:
        commands.append(["/usr/sbin/runuser", "--user", "ubuntu", "--", "rustup",
                         "default", "stable"])
    if manifest.lifecycleDisposition == "persist-workspace":
        commands.extend([
            ["/usr/bin/chown", f"{WORKSPACE_GUEST_UID}:{WORKSPACE_GUEST_GID}", "/workspace"],
            ["/usr/bin/chmod", WORKSPACE_GUEST_MODE, "/workspace"],
        ])
    if manifest.go:
        files.append({"path": "/usr/local/lib/isolatevm/go-install", "content": GO_INSTALL_RETRY,
                      "owner": "root:root", "permissions": "0755"})
    if manifest.externalTools:
        files.append({"path": "/usr/local/lib/isolatevm/setup-devops-packages",
                      "content": _guest_helper("isolatevm-setup-devops"),
                      "owner": "root:root", "permissions": "0750"})
    if manifest.pipx:
        files.append({"path": "/etc/profile.d/isolatevm-pipx.sh",
                      "content": 'case ":$PATH:" in *:/home/ubuntu/.local/bin:*) ;; *) PATH="$PATH:/home/ubuntu/.local/bin" ;; esac\nexport PATH\n',
                      "owner": "root:root", "permissions": "0644"})
    if not apt and not commands and not manifest.environment and not proxy_url and not manifest.secrets and not manifest.copies: return None
    data: dict[str, object] = {}
    if apt:
        data["package_update"] = True
        data["packages"] = apt
    if commands: data["runcmd"] = commands
    if manifest.environment:
        content = "\n" + "".join(f"{key}={value}\n" for key, value in manifest.environment)
        files.append({"path": "/etc/environment", "content": content,
                      "append": True, "owner": "root:root", "permissions": "0644"})
    if manifest.secrets:
        files.extend([
            {"path": "/usr/local/lib/isolatevm/inject-secrets",
             "content": _guest_helper("isolatevm-inject-secrets.py"),
             "owner": "root:root", "permissions": "0750"},
            {"path": "/usr/local/bin/isolatevm-run",
             "content": _guest_helper("isolatevm-run"),
             "owner": "root:root", "permissions": "0755"},
        ])
    if manifest.copies:
        files.append({"path": "/usr/local/lib/isolatevm/copy-files",
                      "content": _guest_helper("isolatevm-copy-files.py"),
                      "owner": "root:root", "permissions": "0750"})
    if proxy_url:
        files.append({"path": "/etc/apt/apt.conf.d/90isolatevm-proxy",
                      "content": (f'Acquire::http::Proxy "{proxy_url}";\n'
                                  f'Acquire::https::Proxy "{proxy_url}";\n'),
                      "owner": "root:root", "permissions": "0644"})
        proxy_environment = "\n" + "".join(f"{key}={proxy_url}\n" for key in
                                               ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"))
        files.append({"path": "/etc/profile.d/isolatevm-proxy.sh", "content": proxy_environment,
                      "owner": "root:root", "permissions": "0644"})
    if files: data["write_files"] = files
    return "#cloud-config\n" + yaml.safe_dump(data, sort_keys=False)
