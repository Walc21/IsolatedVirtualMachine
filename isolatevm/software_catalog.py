"""Ubuntu APT choices exposed by the wizard; the manifest stores package names."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogItem:
    label: str
    package: str


CATALOG_GROUPS: tuple[tuple[str, tuple[CatalogItem, ...]], ...] = (
    ("Básico", tuple(CatalogItem(name, name) for name in (
        "curl", "wget", "git", "vim", "nano", "htop", "jq", "zip", "unzip", "build-essential"))),
    ("Linguagens adicionais", (
        CatalogItem("Go", "golang-go"), CatalogItem("Java JDK", "default-jdk"),
        CatalogItem("Ruby", "ruby-full"), CatalogItem("PHP CLI", "php-cli"))),
    ("Ferramentas Python", (
        CatalogItem("pipx", "pipx"), CatalogItem("virtualenv", "python3-virtualenv"))),
    ("DevOps dentro da VM", (
        CatalogItem("Podman", "podman"), CatalogItem("Ansible", "ansible"),
        CatalogItem("Docker Engine", "docker.io"))),
)

LANGUAGE_PRESETS: dict[str, tuple[str, ...]] = {
    "python": ("python3", "python3-pip"),
    "node": ("nodejs", "npm"),
    "rust": ("rustc", "cargo"),
}

CATALOG_PACKAGES = frozenset(item.package for _, group in CATALOG_GROUPS for item in group)
