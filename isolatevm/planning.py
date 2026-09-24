"""Read-only creation plan shown before any Incus mutation."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from .incus import IncusService
from .copy_source import CopySourceError, scan_source
from .model import Manifest, PROXIED_NETWORK_MODES, ValidationError
from .policy import Finding, assess
from .provision import apt_packages


def host_capacity() -> tuple[int | None, int | None]:
    cpus = os.cpu_count()
    try:
        meminfo = Path("/proc/meminfo").read_text()
        available = next(int(line.split()[1]) // 1024 for line in meminfo.splitlines()
                         if line.startswith("MemAvailable:"))
    except (OSError, StopIteration, ValueError, IndexError):
        available = None
    return cpus, available


@dataclass(frozen=True)
class CreationPlan:
    manifest: Manifest
    image: dict[str, str]
    pool_space: tuple[int, int] | None
    host_cpus: int | None
    host_available_mib: int | None
    findings: tuple[Finding, ...]

    def lines(self) -> list[str]:
        manifest = self.manifest
        image = self.image
        lines = [
            f"AMBIENTE · {manifest.name}",
            "Validações: manifesto, nome livre, pool, bridge quando usada, mounts e alias da imagem.",
            "",
            "IMAGEM E DOWNLOADS",
            f"Origem: {image['alias']}",
            f"Arquitetura: {image.get('architecture', 'indisponível')}",
            f"Fingerprint: {image.get('fingerprint', 'indisponível')}",
            f"Tamanho anunciado: {image.get('size', 'indisponível')}",
            f"Data anunciada: {image.get('uploaded_at', 'indisponível')}",
            "Download da imagem: poderá ocorrer se não estiver em cache.",
            "",
            "RECURSOS E ARMAZENAMENTO",
            f"CPU: {manifest.cpu} vCPU" + (f"; host com {self.host_cpus} CPUs lógicas" if self.host_cpus else ""),
            f"RAM: {manifest.memoryMiB} MiB" +
            (f"; host disponível agora: {self.host_available_mib} MiB; diferença aritmética: "
             f"{self.host_available_mib - manifest.memoryMiB} MiB" if self.host_available_mib is not None else ""),
            f"Disco raiz: limite lógico {manifest.diskGiB} GiB no pool {manifest.pool}.",
        ]
        logical_capacity = manifest.diskGiB
        if manifest.lifecycleDisposition == "persist-workspace":
            logical_capacity += manifest.workspaceSizeGiB or 0
            lines.append(f"/workspace: volume Incus separado com limite de {manifest.workspaceSizeGiB} GiB; não é caminho do host e não entra em snapshots/backups da VM.")
            lines.append(f"Limite lógico combinado no pool: {logical_capacity} GiB.")
        if self.pool_space:
            free, total = self.pool_space
            lines.append(f"Pool informado pelo Incus: {free / 1024**3:.1f} GiB livres de {total / 1024**3:.1f} GiB.")
        else:
            lines.append("Capacidade livre do pool: indisponível nesta conexão Incus.")
        lines.append("Uso físico inicial depende do driver, da imagem e do cache; limite lógico não é espaço já consumido.")
        lines.extend(["", "REDE E ACESSO AO HOST"])
        if manifest.networkMode == "offline":
            lines.append("Rede: nenhuma NIC; nenhuma rede Incus será criada.")
        elif manifest.networkMode in PROXIED_NETWORK_MODES:
            lines.append(f"Rede: NIC eth0 com IPv4 fixo e filtro antispoof na bridge {manifest.bridge}.")
            lines.append("Saída: somente proxy HTTPS local por VM; DNS e conexões diretas da VM serão bloqueados.")
            lines.extend(f"  permitir {rule.kind} {rule.value}:{rule.port}/tcp" for rule in manifest.egress)
            if manifest.networkMode == "lan-only":
                lines.append("Modo LAN-only: CIDRs RFC1918 explícitos; somente serviços TCP alcançáveis pelo host, sem DNS do guest.")
            lines.append("O helper Polkit validará Squid e nftables antes de criar a VM; haverá uma autorização administrativa.")
        else:
            lines.append(f"Rede: NIC eth0 na bridge existente {manifest.bridge}; sem filtro de domínio/IP/porta.")
            lines.append("Nenhuma rede Incus será criada; a bridge existente será apenas usada.")
        lines.append(f"Mounts persistentes: {len(manifest.mounts)}")
        lines.extend(f"  {mount.host} → {mount.guest} [{mount.mode.upper()}]" for mount in manifest.mounts)
        lines.append(f"Cópias únicas para o disco da VM: {len(manifest.copies)}")
        for copy in manifest.copies:
            try:
                entries = scan_source(copy.host, copy.kind, copy.include_hidden)
            except CopySourceError as exc:
                raise ValidationError(str(exc)) from None
            files = sum(not entry.directory for entry in entries)
            size = sum(entry.size for entry in entries)
            lines.append(f"  {copy.host} → {copy.guest}: {files} arquivo(s), {size} byte(s); ocultos: {'sim' if copy.include_hidden else 'não'}")
        if manifest.copies:
            lines.append("A cópia ocorre após a primeira inicialização, pelo agente Incus, sem mount permanente. Mudanças posteriores no host não são sincronizadas.")
        lines.extend(["", "PROVISIONAMENTO NO PRIMEIRO BOOT"])
        apt = apt_packages(manifest)
        lines.append("APT: " + (", ".join(apt) if apt else "nenhum"))
        lines.append("Python no venv: " + (", ".join(manifest.pip) if manifest.pip else "nenhum"))
        lines.append("npm global no guest: " + (", ".join(manifest.npm) if manifest.npm else "nenhum"))
        lines.append("Cargo no guest: " + (", ".join(manifest.cargo) if manifest.cargo else "nenhum"))
        lines.append("Go no guest: " + (", ".join(manifest.go) if manifest.go else "nenhum"))
        lines.append("Variáveis não secretas: " +
                     (", ".join(key for key, _ in manifest.environment) if manifest.environment else "nenhuma"))
        lines.append("Secrets referenciados: " +
                     (", ".join(manifest.secrets) + "; valores ficam no Secret Service e não entram no cloud-init" if manifest.secrets else "nenhum"))
        if manifest.secrets:
            lines.append("Entrega ao guest: ação manual posterior, via stdin local do agente Incus, em arquivos temporários de /run.")
        lines.append("Pacotes podem ser baixados no primeiro boot; versões e tamanhos dependem dos repositórios.")
        lines.extend(["", "OPERAÇÕES E RISCOS",
                      "Incus criará uma VM parada e um disco raiz; acrescentará somente NIC e mounts declarados.",
                      "Configuração global do host: nenhuma alteração planejada."])
        if manifest.copies:
            lines.append("No primeiro start, IsolateVM lerá as origens e gravará somente destinos novos no disco do guest; falhas mantêm o estado pendente para retomada.")
        if self.findings:
            lines.extend(f"{finding.severity.upper()}: {finding.message}" for finding in self.findings)
        else:
            lines.append("Nenhum alerta de política do manifesto.")
        if self.host_available_mib is not None and manifest.memoryMiB > self.host_available_mib:
            lines.append("ATENÇÃO: RAM solicitada supera MemAvailable observado; isso não é uma reserva nem uma previsão de OOM.")
        if self.pool_space and logical_capacity * 1024**3 > self.pool_space[0]:
            lines.append("ATENÇÃO: limite lógico combinado dos volumes supera o espaço livre informado; o comportamento depende do driver e de quotas.")
        return lines


def plan_creation(service: IncusService, manifest: Manifest) -> CreationPlan:
    image = service.preflight(manifest)
    pool_space = service.pool_space(manifest.pool)
    cpus, available_mib = host_capacity()
    return CreationPlan(manifest, image, pool_space, cpus, available_mib, assess(manifest))
