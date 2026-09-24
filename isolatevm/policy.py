"""Explainable warnings for validated manifests. Validation still blocks unsafe inputs."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .model import Manifest, PROXIED_NETWORK_MODES


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
    if manifest.networkMode == "lan-only":
        findings.append(Finding("NETWORK_LAN_PROXY", "warning",
                                "Apenas os CIDRs RFC1918 declarados por TCP são encaminhados pelo proxy local; destinos precisam ser alcançáveis pelo host. DNS e conexões diretas da VM são bloqueados."))
    if manifest.secrets:
        findings.append(Finding("GUEST_SECRETS", "high",
                                "Secrets do cofre só são entregues após confirmação; processos do usuário ubuntu na VM poderão lê-los até ela desligar ou os arquivos temporários serem removidos."))
    if manifest.copies:
        findings.append(Finding("HOST_COPY", "warning",
                                "Os arquivos escolhidos serão transferidos uma vez ao disco da VM após iniciá-la; poderão permanecer em snapshots e exports."))
        if any(copy.include_hidden for copy in manifest.copies):
            findings.append(Finding("HIDDEN_HOST_COPY", "high",
                                    "A inclusão explícita de arquivos ocultos pode transferir dados privados; revise toda a pasta escolhida."))
    if manifest.lifecycleDisposition == "delete-on-close":
        findings.append(Finding("DISPOSABLE_DELETE", "high",
                                "Ao fechar o IsolateVM, será solicitada confirmação para excluir esta VM e seus snapshots. A exclusão é destrutiva e não pode ser desfeita."))
    if manifest.lifecycleDisposition == "restore-initial-on-close":
        findings.append(Finding("DISPOSABLE_RESTORE", "high",
                                "Ao fechar o IsolateVM, será solicitada confirmação para parar a VM e restaurar o snapshot inicial; mudanças posteriores no disco serão perdidas."))
    if manifest.lifecycleDisposition == "persist-workspace":
        findings.append(Finding("PERSISTENT_WORKSPACE", "warning",
                                f"/workspace fica em um volume Incus separado de {manifest.workspaceSizeGiB} GiB. O snapshot da VM e o backup completo da VM não incluem esse volume; exporte os dados separadamente."))
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
