"""Explainable warnings for validated manifests. Validation still blocks unsafe inputs."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .model import Manifest


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str


def assess(manifest: Manifest) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    if manifest.networkMode == "normal":
        findings.append(Finding("NETWORK_UNRESTRICTED", "warning",
                                "Rede normal não filtra domínio, IP nem porta."))
    if manifest.networkMode == "restricted":
        findings.append(Finding("NETWORK_RESTRICTED_PROXY", "info",
                                "Saída restrita usa proxy HTTPS local; DNS e conexões diretas da VM serão bloqueados."))
    if manifest.networkMode == "offline" and (manifest.apt or manifest.pip or manifest.npm or manifest.cargo or manifest.go or manifest.desktop):
        findings.append(Finding("OFFLINE_PROVISION", "warning",
                                "Sem rede, pacotes ausentes da imagem/cache podem não ser instalados no primeiro boot."))
    if manifest.desktop:
        findings.append(Finding("DESKTOP_LOGIN", "warning",
                                "A imagem cloud não configura uma senha de login gráfico; defina uma senha dentro da VM após o primeiro boot, sem guardá-la no manifesto."))
    if "@openai/codex@latest" in manifest.npm:
        findings.append(Finding("UNPINNED_CODEX", "warning",
                                "Codex CLI usa @latest; fixe uma versão npm no manifesto para reprodução exata."))
    if set(manifest.apt) & {"docker.io", "podman"}:
        findings.append(Finding("GUEST_CONTAINER_ENGINE", "warning",
                                "Docker/Podman serão instalados dentro da VM. O aplicativo não repassa sockets do host; execução de contêineres depende dos recursos disponíveis no guest."))
    for mount in manifest.mounts:
        relative = Path(mount.host).relative_to(Path.home())
        if mount.mode == "rw":
            findings.append(Finding("HOST_WRITE", "high",
                                    f"A VM poderá modificar {mount.host}."))
        if relative.parts and relative.parts[0] in {"Downloads", "Documents", "Documentos"}:
            findings.append(Finding("BROAD_PERSONAL_FOLDER", "warning",
                                    f"Revise os arquivos expostos por {mount.host}."))
    return tuple(findings)
