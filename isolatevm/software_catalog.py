"""Curated guest-only software choices shown by the creation wizard."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogItem:
    label: str
    package: str
    manager: str = "apt"


CATALOG_GROUPS: tuple[tuple[str, tuple[CatalogItem, ...]], ...] = (
    ("Básico", tuple(CatalogItem(name, name) for name in (
        "curl", "wget", "git", "vim", "nano", "htop", "jq", "zip", "unzip", "build-essential"))),
    ("Linguagens adicionais", (
        CatalogItem("Go", "golang-go"), CatalogItem("Java JDK", "default-jdk"),
        CatalogItem("Ruby", "ruby-full"), CatalogItem("PHP CLI", "php-cli"))),
    ("Ferramentas Python", (
        CatalogItem("pipx", "pipx"), CatalogItem("virtualenv", "python3-virtualenv"),
        CatalogItem("uv", "uv==0.12.18", "pipx"),
        CatalogItem("Poetry", "poetry==2.5.1", "pipx"))),
    ("JavaScript", (
        CatalogItem("pnpm standalone", "@pnpm/exe@12.5.1", "npm"),
        CatalogItem("Yarn Classic", "yarn@1.22.22", "npm"),
        CatalogItem("Bun", "bun@1.4.2", "npm"))),
    ("Ferramentas Rust", (
        CatalogItem("rustup + toolchain stable", "rustup"),)),
    ("DevOps dentro da VM", (
        CatalogItem("Podman", "podman"), CatalogItem("Ansible", "ansible"),
        CatalogItem("Docker Engine", "docker.io"),
        CatalogItem("kubectl · canal 1.37", "kubectl@1.37", "external"),
        CatalogItem("Helm · repositório comunitário", "helm@community", "external"),
        CatalogItem("Terraform · repositório HashiCorp", "terraform@hashicorp", "external"))),
)

LANGUAGE_PRESETS: dict[str, tuple[str, ...]] = {
    "python": ("python3", "python3-pip"),
    "node": ("nodejs", "npm"),
    "rust": ("rustc", "cargo"),
}

APT_CATALOG_PACKAGES = frozenset(item.package for _, group in CATALOG_GROUPS
                                 for item in group if item.manager == "apt")
PIPX_CATALOG_PACKAGES = frozenset(item.package for _, group in CATALOG_GROUPS
                                  for item in group if item.manager == "pipx")
NPM_CATALOG_PACKAGES = frozenset(item.package for _, group in CATALOG_GROUPS
                                 for item in group if item.manager == "npm")
DOTNET_SDK_PACKAGES = frozenset({"dotnet-sdk-8.0", "dotnet-sdk-10.0"})
EXTERNAL_TOOL_PACKAGES = frozenset({"kubectl@1.37", "helm@community", "terraform@hashicorp"})
