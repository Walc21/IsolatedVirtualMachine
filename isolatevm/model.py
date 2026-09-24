"""Versioned manifest and deny-by-default validation."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress
from pathlib import Path
import re
import stat
from typing import Any

import yaml

from .copy_source import (CopySourceError, MAX_COPY_BYTES, MAX_COPY_FILES,
                          canonical_source, scan_source, source_reference)
from .cpu import CPUSelectionError, format_cpu_set, parse_cpu_set
from .software_catalog import (AIDER_SUPPORTED_RELEASES, EXTERNAL_TOOL_PACKAGES)

NAME = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
PIP_PACKAGE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}(?:==[a-zA-Z0-9][a-zA-Z0-9_.+!-]{0,63})?\Z")
NPM_PACKAGE = re.compile(r"(?:@[a-z0-9][a-z0-9_.-]*/)?[a-z0-9][a-z0-9_.-]*(?:@[a-z0-9][a-z0-9_.-]*)?\Z")
CARGO_PACKAGE = re.compile(r"[a-z][a-z0-9_-]{0,63}@[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?\Z")
GO_PACKAGE = re.compile(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/[a-zA-Z0-9][a-zA-Z0-9_./-]*@v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?\Z")
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
GUEST = re.compile(r"/(?:[a-zA-Z0-9_.-]+/?)+\Z")
RELEASES = {"22.04", "24.04", "26.04"}
BRIDGED_NETWORK_MODES = {"normal", "restricted", "lan-only"}
PROXIED_NETWORK_MODES = {"restricted", "lan-only"}
LAN_IPV4_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                          ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
DESKTOP_PACKAGES = {"gnome": "ubuntu-desktop-minimal", "kde": "kubuntu-desktop", "xfce": "xubuntu-desktop"}
SENSITIVE = {".ssh", ".gnupg", ".aws", ".config", ".local", ".docker", ".kube"}
SECURITY_PROFILES = {"maximum-isolation", "normal-development", "restricted-development", "custom"}
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
ENV_VALUE = re.compile(r"[A-Za-z0-9_./:@+-]{0,256}\Z")
SECRET_REF = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
LIFECYCLE_DISPOSITIONS = {"persistent", "manual-delete", "delete-on-close",
                          "restore-initial-on-close", "persist-workspace"}
INITIAL_SNAPSHOT = "isolatevm-initial"
RESERVED_ENV = {"PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "IFS", "ENV", "BASH_ENV", "PYTHONPATH", "PYTHONHOME"}
SECRET_NAME_PARTS = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY", "PRIVATE_KEY", "ACCESS_KEY", "BEARER", "AUTH")


class ValidationError(ValueError):
    pass


class _ManifestLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValidationError("Aliases YAML não são aceitos em manifestos")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValidationError(f"Campo YAML duplicado: {key}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _keys(value: Any, expected: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - expected:
        raise ValidationError(f"{where}: estrutura ou campos desconhecidos")
    return value


def _name(value: Any, where: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValidationError(f"{where}: use letras minúsculas, dígitos e hífen; comece por letra")
    return value


def _integer(value: Any, low: int, high: int, where: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValidationError(f"{where}: esperado inteiro entre {low} e {high}")
    return value


def _host_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValidationError("Mount: caminho do host deve ser absoluto")
    raw = Path(value)
    if ".." in raw.parts or not raw.exists():
        raise ValidationError("Mount: caminho inexistente ou contém '..'")
    # Disallow symlinks in every component so the displayed path is meaningful.
    for part in (raw, *raw.parents):
        if part.is_symlink():
            raise ValidationError("Mount: symlinks não são aceitos")
    resolved = raw.resolve(strict=True)
    home = Path.home().resolve()
    if resolved == home or not resolved.is_relative_to(home):
        raise ValidationError("Mount: escolha uma pasta específica dentro do seu HOME")
    if any(p in SENSITIVE for p in resolved.relative_to(home).parts):
        raise ValidationError("Mount: pasta sensível bloqueada")
    mode = resolved.stat().st_mode
    if not stat.S_ISDIR(mode):
        raise ValidationError("Mount: apenas diretórios regulares são aceitos")
    return str(resolved)


@dataclass(frozen=True)
class Mount:
    host: str
    guest: str
    mode: str = "ro"

    @classmethod
    def parse(cls, raw: Any) -> "Mount":
        item = _keys(raw, {"host", "guest", "mode"}, "Mount")
        host = _host_path(item.get("host"))
        guest = item.get("guest")
        if not isinstance(guest, str) or not GUEST.fullmatch(guest) or ".." in Path(guest).parts or guest == "/":
            raise ValidationError("Mount: destino inválido na VM")
        mode = item.get("mode", "ro")
        if mode not in ("ro", "rw"):
            raise ValidationError("Mount: acesso deve ser ro ou rw")
        return cls(host, guest.rstrip("/"), mode)


def _copy_guest_path(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048 or not value.startswith("/home/ubuntu/"):
        raise ValidationError("Cópia: destino precisa ficar dentro de /home/ubuntu")
    parts = value.split("/")
    try:
        invalid = (len(parts) < 4 or parts[:3] != ["", "home", "ubuntu"] or
                   any(not part or part in {".", ".."} or
                       any(ord(char) < 32 or ord(char) == 127 for char in part) or
                       len(part.encode("utf-8")) > 255 for part in parts[3:]))
    except UnicodeEncodeError:
        invalid = True
    if invalid:
        raise ValidationError("Cópia: destino inválido ou contém caminho ambíguo")
    if parts[3].startswith(".") or parts[3] in SENSITIVE:
        raise ValidationError("Cópia: escolha uma pasta de trabalho dentro de /home/ubuntu")
    return value


@dataclass(frozen=True)
class CopySpec:
    host: str
    guest: str
    kind: str
    include_hidden: bool = False

    @classmethod
    def parse(cls, raw: Any, *, check_source: bool = True) -> "CopySpec":
        item = _keys(raw, {"host", "guest", "kind", "includeHidden"}, "Cópia")
        kind = item.get("kind")
        include_hidden = item.get("includeHidden", False)
        try:
            host = (canonical_source(item.get("host"), kind, include_hidden)
                    if check_source else source_reference(item.get("host"), kind, include_hidden))
        except CopySourceError as exc:
            raise ValidationError(str(exc)) from None
        return cls(str(host), _copy_guest_path(item.get("guest")),
                   kind, include_hidden)

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "guest": self.guest, "kind": self.kind,
                "includeHidden": self.include_hidden}


@dataclass(frozen=True)
class EgressRule:
    """One explicit TCP destination admitted by the restricted proxy."""
    kind: str
    value: str
    port: int

    @classmethod
    def parse(cls, raw: Any) -> "EgressRule":
        item = _keys(raw, {"kind", "value", "port", "protocol"}, "Regra de saída")
        kind, value, port = item.get("kind"), item.get("value"), item.get("port")
        if not isinstance(kind, str) or kind not in {"domain", "ip", "cidr"} or not isinstance(value, str):
            raise ValidationError("Regra de saída: tipo deve ser domain, ip ou cidr")
        if item.get("protocol", "tcp") != "tcp":
            raise ValidationError("Regra de saída: somente TCP é suportado pelo proxy HTTPS")
        port = _integer(port, 1, 65535, "Porta de saída")
        if kind == "domain":
            value = value.lower().rstrip(".")
            if not DOMAIN.fullmatch(value):
                raise ValidationError("Regra de saída: domínio inválido")
        else:
            try:
                parsed = ipaddress.ip_network(value, strict=True) if kind == "cidr" else ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValidationError("Regra de saída: IP ou CIDR inválido") from exc
            if parsed.version != 4:
                raise ValidationError("Regra de saída: somente IPv4 é suportado nesta versão")
            if kind == "ip": value = str(parsed)
            else: value = str(parsed)
        return cls(kind, value, port)


@dataclass(frozen=True)
class Manifest:
    schemaVersion: int
    name: str
    release: str
    cpu: int
    memoryMiB: int
    diskGiB: int
    pool: str
    networkMode: str = "offline"
    bridge: str | None = None
    egress: tuple[EgressRule, ...] = ()
    mounts: tuple[Mount, ...] = ()
    apt: tuple[str, ...] = ()
    pip: tuple[str, ...] = ()
    npm: tuple[str, ...] = ()
    template: str | None = None
    securityProfile: str = "custom"
    environment: tuple[tuple[str, str], ...] = ()
    desktop: str | None = None
    cargo: tuple[str, ...] = ()
    go: tuple[str, ...] = ()
    secrets: tuple[str, ...] = ()
    copies: tuple[CopySpec, ...] = ()
    lifecycleDisposition: str = "persistent"
    workspaceSizeGiB: int | None = None
    pipx: tuple[str, ...] = ()
    externalTools: tuple[str, ...] = ()
    cpuPinning: str | None = None

    @classmethod
    def parse(cls, raw: Any, *, check_copy_sources: bool = True) -> "Manifest":
        item = _keys(raw, {"schemaVersion", "name", "os", "resources", "network", "mounts", "copies", "software", "metadata", "security", "environment", "secrets", "lifecycle"}, "Manifesto")
        if item.get("schemaVersion") != 1 or type(item.get("schemaVersion")) is not int:
            raise ValidationError("Versão de manifesto não suportada")
        os_data = _keys(item.get("os"), {"distribution", "release", "desktop"}, "Sistema")
        if os_data.get("distribution") != "ubuntu" or not isinstance(os_data.get("release"), str) or os_data.get("release") not in RELEASES:
            raise ValidationError("Somente imagens Ubuntu cloud 22.04, 24.04 e 26.04 são aceitas nesta versão")
        desktop = os_data.get("desktop")
        if desktop is not None and (not isinstance(desktop, str) or desktop not in DESKTOP_PACKAGES):
            raise ValidationError("Desktop: escolha GNOME, KDE Plasma ou XFCE")
        resources = _keys(item.get("resources"), {"cpu", "memoryMiB", "diskGiB", "pool"}, "Recursos")
        network = _keys(item.get("network", {"mode": "offline"}), {"mode", "bridge", "egress"}, "Rede")
        mode = network.get("mode")
        if mode not in ("offline", "normal", "restricted", "lan-only"):
            raise ValidationError("Rede: escolha offline, normal, restricted ou lan-only")
        bridge = network.get("bridge")
        if mode in BRIDGED_NETWORK_MODES:
            bridge = _name(bridge, "Bridge")
        elif bridge is not None:
            raise ValidationError("Rede offline não aceita bridge")
        rules_raw = network.get("egress", [])
        if not isinstance(rules_raw, list) or len(rules_raw) > 32:
            raise ValidationError("Rede: máximo de 32 regras de saída")
        egress = tuple(EgressRule.parse(rule) for rule in rules_raw)
        if len(set(egress)) != len(egress):
            raise ValidationError("Rede: regras de saída duplicadas")
        if mode in PROXIED_NETWORK_MODES and not egress:
            raise ValidationError("Rede restrita exige ao menos uma regra de saída")
        if mode not in PROXIED_NETWORK_MODES and egress:
            raise ValidationError("Regras de saída são exclusivas da rede restrita")
        if mode == "lan-only":
            for rule in egress:
                if rule.kind != "cidr":
                    raise ValidationError("LAN somente aceita CIDRs IPv4 privados e portas TCP explícitas")
                network = ipaddress.ip_network(rule.value, strict=True)
                if not any(network.subnet_of(private) for private in LAN_IPV4_NETWORKS):
                    raise ValidationError("LAN somente aceita apenas CIDRs dentro de 10/8, 172.16/12 ou 192.168/16")
        mounts_raw = item.get("mounts", [])
        if not isinstance(mounts_raw, list) or len(mounts_raw) > 16:
            raise ValidationError("Máximo de 16 mounts")
        mounts = tuple(Mount.parse(x) for x in mounts_raw)
        for index, mount in enumerate(mounts):
            for earlier in mounts[:index]:
                guest = Path(mount.guest); prior_guest = Path(earlier.guest)
                host = Path(mount.host); prior_host = Path(earlier.host)
                if guest == prior_guest or guest in prior_guest.parents or prior_guest in guest.parents:
                    raise ValidationError("Destinos de mount duplicados ou sobrepostos")
                if host == prior_host or host in prior_host.parents or prior_host in host.parents:
                    raise ValidationError("Pastas do host duplicadas ou sobrepostas")
        copies_raw = item.get("copies", [])
        if not isinstance(copies_raw, list) or len(copies_raw) > 16:
            raise ValidationError("Cópia: máximo de 16 origens")
        copies = tuple(CopySpec.parse(x, check_source=check_copy_sources) for x in copies_raw)
        total_files = 0
        total_bytes = 0
        for index, copy in enumerate(copies):
            destination = Path(copy.guest)
            if any(destination == Path(mount.guest) or destination in Path(mount.guest).parents or
                   Path(mount.guest) in destination.parents for mount in mounts):
                raise ValidationError("Cópia: destino se sobrepõe a um compartilhamento permanente")
            if any(destination == Path(earlier.guest) or destination in Path(earlier.guest).parents or
                   Path(earlier.guest) in destination.parents for earlier in copies[:index]):
                raise ValidationError("Cópia: destinos duplicados ou sobrepostos")
            if check_copy_sources:
                try:
                    entries = scan_source(copy.host, copy.kind, copy.include_hidden)
                except CopySourceError as exc:
                    raise ValidationError(str(exc)) from None
                total_files += sum(not entry.directory for entry in entries)
                total_bytes += sum(entry.size for entry in entries)
                if total_files > MAX_COPY_FILES or total_bytes > MAX_COPY_BYTES:
                    raise ValidationError("Cópia: limite total de 2048 arquivos ou 1 GiB excedido")
        security = _keys(item.get("security", {"profile": "custom"}), {"profile"}, "Segurança")
        profile = security.get("profile")
        if not isinstance(profile, str) or profile not in SECURITY_PROFILES:
            raise ValidationError("Perfil de segurança desconhecido")
        if profile == "restricted-development" and mode not in PROXIED_NETWORK_MODES:
            raise ValidationError("Desenvolvimento restrito exige proxy de saída restricted ou LAN-only")
        if mode in PROXIED_NETWORK_MODES and profile != "restricted-development":
            raise ValidationError("Rede proxied exige o perfil restricted-development")
        if profile == "maximum-isolation" and (mode != "offline" or mounts):
            raise ValidationError("Máximo isolamento exige rede offline e nenhum compartilhamento do host")
        if profile == "maximum-isolation" and copies:
            raise ValidationError("Máximo isolamento impede copiar arquivos do host para a VM")
        secrets_raw = item.get("secrets", [])
        if (not isinstance(secrets_raw, list) or len(secrets_raw) > 32 or
                any(not isinstance(name, str) or not SECRET_REF.fullmatch(name) or name in RESERVED_ENV or
                    name.startswith("LD_") for name in secrets_raw)):
            raise ValidationError("Secrets: use até 32 nomes de variável válidos; valores não podem constar no manifesto")
        secrets = tuple(dict.fromkeys(secrets_raw))
        if profile == "maximum-isolation" and secrets:
            raise ValidationError("Máximo isolamento impede disponibilizar secrets ao guest")
        lifecycle = _keys(item.get("lifecycle", {}), {"disposition", "workspaceSizeGiB"}, "Ciclo de vida")
        disposition = lifecycle.get("disposition", "persistent")
        if not isinstance(disposition, str) or disposition not in LIFECYCLE_DISPOSITIONS:
            raise ValidationError("Ciclo de vida: escolha persistent, manual-delete, delete-on-close, restore-initial-on-close ou persist-workspace")
        workspace_size = None
        if disposition == "persist-workspace":
            workspace_size = _integer(lifecycle.get("workspaceSizeGiB", 20), 1, 2048,
                                      "Tamanho persistente de /workspace")
            workspace_path = Path("/workspace")
            if any(Path(mount.guest) == workspace_path or Path(mount.guest) in workspace_path.parents or
                   workspace_path in Path(mount.guest).parents for mount in mounts):
                raise ValidationError("Persistir /workspace exige um volume Incus próprio; remova mounts host sobrepostos")
        elif "workspaceSizeGiB" in lifecycle:
            raise ValidationError("workspaceSizeGiB só pode ser definido com persist-workspace")
        environment = item.get("environment", {})
        if not isinstance(environment, dict) or len(environment) > 32:
            raise ValidationError("Variáveis de ambiente: máximo de 32 pares NOME=VALOR")
        for key, value in environment.items():
            if not isinstance(key, str) or not ENV_NAME.fullmatch(key) or key in RESERVED_ENV or key.startswith("LD_"):
                raise ValidationError("Nome de variável de ambiente inválido ou reservado")
            if any(part in key for part in SECRET_NAME_PARTS) or key.endswith("_KEY"):
                raise ValidationError("Variável parece conter segredo; use armazenamento seguro, não o manifesto")
            if not isinstance(value, str) or not ENV_VALUE.fullmatch(value):
                raise ValidationError("Valor de variável de ambiente inválido; use texto simples sem espaços ou caracteres de shell")
            if value.startswith(("sk-", "ghp_", "github_pat_", "xoxb-", "AKIA")):
                raise ValidationError("Valor parece ser uma credencial; não coloque secrets no manifesto")
        software = _keys(item.get("software", {"apt": []}), {"apt", "pip", "pipx", "npm", "cargo", "go", "external"}, "Software")
        packages = software.get("apt", [])
        if not isinstance(packages, list) or len(packages) > 100 or any(not isinstance(p, str) or not PACKAGE.fullmatch(p) for p in packages):
            raise ValidationError("Lista APT inválida")
        pip = software.get("pip", [])
        if not isinstance(pip, list) or len(pip) > 50 or any(not isinstance(p, str) or not PIP_PACKAGE.fullmatch(p) for p in pip):
            raise ValidationError("Lista Python inválida")
        pipx = software.get("pipx", [])
        if not isinstance(pipx, list) or len(pipx) > 50 or any(not isinstance(p, str) or not PIP_PACKAGE.fullmatch(p) for p in pipx):
            raise ValidationError("Lista pipx inválida; use pacote ou pacote==versão exata")
        if (any(package.partition("==")[0] == "aider-chat" for package in pipx) and
                os_data["release"] not in AIDER_SUPPORTED_RELEASES):
            raise ValidationError("Aider 0.86.2 requer Python 3.10 a 3.12; selecione Ubuntu 22.04 ou 24.04")
        external = software.get("external", [])
        if not isinstance(external, list) or len(external) > 16 or any(
                not isinstance(tool, str) or tool not in EXTERNAL_TOOL_PACKAGES for tool in external):
            raise ValidationError("Lista de ferramentas DevOps externas inválida")
        npm = software.get("npm", [])
        if not isinstance(npm, list) or len(npm) > 50 or any(not isinstance(p, str) or not NPM_PACKAGE.fullmatch(p) for p in npm):
            raise ValidationError("Lista npm inválida")
        cargo = software.get("cargo", [])
        if not isinstance(cargo, list) or len(cargo) > 32 or any(not isinstance(p, str) or not CARGO_PACKAGE.fullmatch(p) for p in cargo):
            raise ValidationError("Lista Cargo inválida; use crate@versão exata, como ripgrep@14.1.1")
        go = software.get("go", [])
        if not isinstance(go, list) or len(go) > 32 or any(not isinstance(p, str) or not GO_PACKAGE.fullmatch(p) or ".." in p for p in go):
            raise ValidationError("Lista Go inválida; use módulo/comando@vX.Y.Z")
        if "rustup" in packages and {"rustc", "cargo"}.issubset(packages):
            raise ValidationError("Escolha rustup ou o toolchain Rust dos repositórios Ubuntu, não ambos")
        if "dotnet-sdk-8.0" in packages and os_data["release"] == "26.04":
            raise ValidationError(".NET 8.0 não está na feed Ubuntu padrão de 26.04; configure uma fonte compatível explicitamente")
        if "dotnet-sdk-10.0" in packages and os_data["release"] == "22.04":
            raise ValidationError(".NET 10.0 não está na feed Ubuntu padrão de 22.04; configure uma fonte compatível explicitamente")
        cpu_count = _integer(resources.get("cpu"), 1, 64, "CPU")
        metadata = _keys(item.get("metadata", {}), {"template", "cpuPinning"}, "Metadados")
        template = metadata.get("template")
        if template is not None:
            template = _name(template, "Template")
        cpu_pinning = metadata.get("cpuPinning")
        if cpu_pinning is not None:
            if not isinstance(cpu_pinning, str):
                raise ValidationError("CPU pinning: esperado texto com IDs do host")
            try:
                selected_cpus = parse_cpu_set(cpu_pinning)
            except CPUSelectionError as exc:
                raise ValidationError(str(exc)) from None
            if len(selected_cpus) != cpu_count:
                raise ValidationError("CPU pinning: a quantidade de IDs deve corresponder ao número de vCPUs")
            cpu_pinning = format_cpu_set(selected_cpus)
        return cls(1, _name(item.get("name"), "Nome"), os_data["release"],
                   cpu_count,
                   _integer(resources.get("memoryMiB"), 512, 262144, "RAM"),
                   _integer(resources.get("diskGiB"), 8, 2048, "Disco"),
                   _name(resources.get("pool"), "Pool"), mode, bridge, egress,
                   mounts, tuple(dict.fromkeys(packages)), tuple(dict.fromkeys(pip)),
                   tuple(dict.fromkeys(npm)), template, profile,
                   tuple(sorted(environment.items())), desktop,
                   tuple(dict.fromkeys(cargo)), tuple(dict.fromkeys(go)), secrets, copies, disposition,
                   workspace_size, tuple(dict.fromkeys(pipx)), tuple(dict.fromkeys(external)),
                   cpu_pinning)

    def to_dict(self) -> dict[str, Any]:
        software = {"apt": list(self.apt), "pip": list(self.pip), "npm": list(self.npm),
                    "cargo": list(self.cargo), "go": list(self.go)}
        if self.pipx:
            software["pipx"] = list(self.pipx)
        if self.externalTools:
            software["external"] = list(self.externalTools)
        result = {"schemaVersion": 1, "name": self.name,
                "os": {"distribution": "ubuntu", "release": self.release,
                       **({"desktop": self.desktop} if self.desktop else {})},
                "resources": {"cpu": self.cpu, "memoryMiB": self.memoryMiB,
                              "diskGiB": self.diskGiB, "pool": self.pool},
                "network": {"mode": self.networkMode, **({"bridge": self.bridge} if self.bridge else {}),
                            **({"egress": [{"kind": rule.kind, "value": rule.value, "port": rule.port,
                                           "protocol": "tcp"} for rule in self.egress]} if self.egress else {})},
                "mounts": [asdict(x) for x in self.mounts],
                "security": {"profile": self.securityProfile},
                "environment": dict(self.environment),
                "software": software,
                "metadata": {key: value for key, value in
                             (("template", self.template), ("cpuPinning", self.cpuPinning))
                             if value is not None}}
        if self.secrets:
            result["secrets"] = list(self.secrets)
        if self.copies:
            result["copies"] = [copy.to_dict() for copy in self.copies]
        if self.lifecycleDisposition != "persistent":
            lifecycle = {"disposition": self.lifecycleDisposition}
            if self.lifecycleDisposition == "persist-workspace":
                lifecycle["workspaceSizeGiB"] = self.workspaceSizeGiB
            result["lifecycle"] = lifecycle
        return result

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), allow_unicode=True, sort_keys=False)

    @classmethod
    def from_yaml(cls, text: str, *, check_copy_sources: bool = True) -> "Manifest":
        if not isinstance(text, str):
            raise ValidationError("Manifesto precisa ser texto YAML")
        try:
            input_bytes = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise ValidationError("Manifesto não é texto UTF-8 válido") from None
        if input_bytes > 64_000:
            raise ValidationError("Manifesto muito grande")
        try:
            return cls.parse(yaml.load(text, Loader=_ManifestLoader),
                             check_copy_sources=check_copy_sources)
        except (yaml.YAMLError, TypeError, RecursionError) as exc:
            raise ValidationError("YAML inválido") from exc

    def review(self) -> list[str]:
        lines = [f"VM: {self.name}", f"Imagem: images:ubuntu/{self.release}/cloud",
                 f"Tipo: {self.desktop.upper() if self.desktop else 'Headless'}"
                 + (f" · pacote {DESKTOP_PACKAGES[self.desktop]}" if self.desktop else ""),
                 f"CPU: {self.cpu} · RAM: {self.memoryMiB} MiB · Disco: {self.diskGiB} GiB ({self.pool})",
                 *( [f"CPUs do host fixadas: {self.cpuPinning}"] if self.cpuPinning else [] ),
                 f"Rede: {self.networkMode}" + (f" via {self.bridge}" if self.bridge else ""),
                 f"Perfil de segurança: {self.securityProfile}",
                 f"Ciclo de vida: {self.lifecycleDisposition}",
                 *( [f"Volume persistente: /workspace · {self.workspaceSizeGiB} GiB" ]
                    if self.lifecycleDisposition == "persist-workspace" else [] ),
                 f"Pacotes APT: {', '.join(self.apt) if self.apt else 'nenhum'}",
                 f"Pacotes Python: {', '.join(self.pip) if self.pip else 'nenhum'}",
                 f"Aplicativos Python pipx: {', '.join(self.pipx) if self.pipx else 'nenhum'}",
                 f"Pacotes npm globais: {', '.join(self.npm) if self.npm else 'nenhum'}",
                 f"Crates Cargo: {', '.join(self.cargo) if self.cargo else 'nenhum'}",
                 f"Ferramentas Go: {', '.join(self.go) if self.go else 'nenhum'}",
                 f"Ferramentas DevOps externas: {', '.join(self.externalTools) if self.externalTools else 'nenhuma'}",
                 *( ["APT externo do guest: canal kubectl 1.37, Helm comunitário Buildkite e/ou Terraform HashiCorp; pacote efetivo acompanha o feed selecionado." ]
                    if self.externalTools else [] ),
                 "Saída restrita: " + (", ".join(f"{rule.value}:{rule.port}" for rule in self.egress) if self.egress else "não aplicável"),
                 f"Variáveis não secretas: {', '.join(key for key, _ in self.environment) if self.environment else 'nenhuma'}",
                 f"Secrets referenciados: {', '.join(self.secrets) if self.secrets else 'nenhum'} (valores fora do manifesto)",
                 f"Diretórios do host: {len(self.mounts)}",
                 f"Cópias únicas para o disco da VM: {len(self.copies)}"]
        lines.extend(f"  {x.host} → {x.guest} [{x.mode.upper()}]" for x in self.mounts)
        lines.extend(f"  COPIAR {x.host} → {x.guest} ({'pasta' if x.kind == 'directory' else 'arquivo'})"
                     for x in self.copies)
        lines.append("Alterações no host: nenhuma configuração global; Incus armazenará VM/disco.")
        lines.append("Download: imagem e pacotes, se ausentes. Tamanho depende do servidor remoto.")
        return lines
