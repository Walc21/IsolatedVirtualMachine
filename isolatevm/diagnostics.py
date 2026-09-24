"""Read-only Ubuntu/virtualization checks."""
from __future__ import annotations

import os
import grp
import pwd
from pathlib import Path
import platform
import shutil
import subprocess

from .access import local_socket
from .storage import data_dir


CLIENT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _incus_client_environment() -> dict[str, str]:
    client_config_dir = data_dir() / "incus-client"
    client_config_dir.mkdir(mode=0o700, exist_ok=True)
    return {
        "HOME": str(Path.home()),
        "PATH": CLIENT_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C",
        "INCUS_CONF": str(client_config_dir),
    }


def diagnose() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    os_release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1); os_release[key] = value.strip('"')
    rows.append(("ok" if os_release.get("ID") == "ubuntu" else "warn", "Ubuntu", os_release.get("PRETTY_NAME", "Desconhecido")))
    rows.append(("ok", "Arquitetura", platform.machine()))
    flags = Path("/proc/cpuinfo").read_text(errors="replace")
    rows.append(("ok" if " vmx " in f" {flags} " or " svm " in f" {flags} " else "error",
                 "Virtualização CPU", "vmx/svm detectado" if "vmx" in flags or "svm" in flags else "Não detectada"))
    kvm = Path("/dev/kvm")
    rows.append(("ok" if kvm.exists() and os.access(kvm, os.R_OK | os.W_OK) else "error",
                 "KVM", "Acessível" if kvm.exists() and os.access(kvm, os.R_OK | os.W_OK) else "Indisponível ou sem permissão"))
    rows.append(("ok" if shutil.which("qemu-system-x86_64") else "error", "QEMU",
                 shutil.which("qemu-system-x86_64") or "Não instalado"))
    incus = shutil.which("incus", path=CLIENT_PATH)
    rows.append(("ok" if incus else "error", "Incus", incus or "Não instalado"))
    viewer = shutil.which("remote-viewer") or shutil.which("spicy")
    rows.append(("ok" if viewer else "warn", "Console VGA/SPICE",
                 viewer or "Cliente SPICE ausente; a console VGA ficará indisponível"))
    groups = {grp.getgrgid(gid).gr_name for gid in os.getgroups()}
    access = ", ".join(sorted(groups & {"incus", "incus-admin"})) or "nenhum grupo Incus"
    if not groups & {"incus", "incus-admin"}:
        user = pwd.getpwuid(os.getuid()).pw_name
        try:
            if user in grp.getgrnam("incus").gr_mem:
                access = "Grupo incus atribuído, mas ainda inativo nesta sessão. Entre novamente no Ubuntu."
        except KeyError:
            pass
    rows.append(("ok" if groups & {"incus", "incus-admin"} else "warn", "Grupo Incus", access))
    socket_path, socket_mode = local_socket()
    if socket_path is None:
        rows.append(("error", "Socket Incus", "Sem acesso ao socket local. O operador deve configurar o acesso e abrir uma nova sessão."))
    else:
        description = "administrativo (acesso amplo)" if socket_mode == "admin" else "de usuário (projeto restrito)"
        rows.append(("ok", "Socket Incus", f"{socket_path} · {description}"))
    if incus and socket_path is None:
        rows.append(("error", "Serviço Incus", "Não verificável nesta sessão sem acesso ao socket"))
    if incus and socket_mode == "confined":
        rows.append(("warn", "Serviço Incus", "Socket de usuário disponível; conexão adiada até confirmação na interface"))
    if incus and socket_mode == "admin":
        env = _incus_client_environment()
        try:
            proc = subprocess.run([incus, "--force-local", "info"], capture_output=True, text=True, timeout=8, env=env)
            rows.append(("ok" if proc.returncode == 0 else "error", "Serviço Incus",
                         "Acessível" if proc.returncode == 0 else (proc.stderr.strip()[:180] or "Sem acesso")))
            if proc.returncode == 0:
                pools = subprocess.run([incus, "--force-local", "storage", "list", "--format", "json"],
                                       capture_output=True, text=True, timeout=8, env=env)
                rows.append(("ok" if pools.returncode == 0 and pools.stdout.strip() not in ("", "[]") else "warn",
                             "Pool Incus", "Disponível" if pools.returncode == 0 and pools.stdout.strip() not in ("", "[]") else "Nenhum pool disponível"))
        except subprocess.TimeoutExpired:
            rows.append(("error", "Serviço Incus", "Tempo esgotado"))
    mem = Path("/proc/meminfo").read_text()
    available = next((int(line.split()[1]) // 1024 for line in mem.splitlines() if line.startswith("MemAvailable:")), 0)
    free = shutil.disk_usage(Path.home()).free // (1024 ** 3)
    rows.append(("ok", "Recursos", f"{os.cpu_count()} CPUs · {available} MiB RAM disponível · {free} GiB disco livre"))
    return rows
