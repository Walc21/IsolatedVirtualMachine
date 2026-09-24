"""Creation wizard and template flow for IsolateVM."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk

from .model import CopySpec, Manifest, Mount, PROXIED_NETWORK_MODES, ValidationError
from .policy import assess
from .planning import CreationPlan, plan_creation
from .provision import cloud_config
from .software_catalog import (AI_CODING_ITEMS, AI_CODING_PACKAGES,
                               AIDER_SUPPORTED_RELEASES, APT_CATALOG_PACKAGES,
                               CATALOG_GROUPS, DOTNET_SDK_PACKAGES,
                               LANGUAGE_PRESETS, NPM_CATALOG_PACKAGES,
                               PIPX_CATALOG_PACKAGES)
from .storage import audit, export_manifest, import_manifest, load_template, save_instance_manifest, save_template, save_template_versioned, templates
from .ui_widgets import label, button, row, entry, combo


@dataclass
class MountEditor:
    frame: Gtk.Frame
    host: Gtk.Entry
    guest: Gtk.Entry
    rw: Gtk.CheckButton


@dataclass
class CopyEditor:
    frame: Gtk.Frame
    host: Gtk.Entry
    guest: Gtk.Entry
    kind: str
    include_hidden: Gtk.CheckButton


class WizardMixin:
    def _build_wizard(self) -> None:
        self._clear(self.wizard)
        self.wizard.append(label("Novo Ambiente", "page-title"))
        self.wizard.append(label("Criação declarativa. A VM nasce parada; cópias únicas são aplicadas depois do primeiro start.", "muted"))
        self.step_title = label("", "section-title")
        self.wizard.append(self.step_title)
        self.step_body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.wizard.append(self.step_body)
        nav = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.back_btn = button("Voltar", self._back)
        self.next_btn = button("Próximo", self._next, "suggested-action")
        nav.append(self.back_btn); nav.append(self.next_btn)
        self.wizard.append(nav)

        self.name_input = entry("novo-ambiente")
        self.release_input = combo(["24.04", "26.04", "22.04"])
        self.headless_check = Gtk.CheckButton(label="Headless (padrão)")
        self.desktop_check = Gtk.CheckButton(label="Desktop")
        self.desktop_check.set_group(self.headless_check)
        self.headless_check.set_active(True)
        self.desktop_input = combo(["GNOME", "KDE Plasma", "XFCE"])
        self.desktop_input.set_sensitive(False)
        self.desktop_check.connect("toggled", lambda widget: self.desktop_input.set_sensitive(widget.get_active()))
        self.cpu_input = Gtk.SpinButton.new_with_range(1, 64, 1); self.cpu_input.set_value(2)
        self.cpu_pinning_input = entry()
        self.cpu_pinning_input.set_placeholder_text("Opcional · ex.: 0-3,6-7")
        self.ram_input = Gtk.SpinButton.new_with_range(512, 262144, 512); self.ram_input.set_value(4096)
        self.ram_status = label("", "muted")
        self.ram_input.connect("value-changed", lambda *_: self._update_ram_capacity())
        self.disk_input = Gtk.SpinButton.new_with_range(8, 2048, 1); self.disk_input.set_value(30)
        self.pool_input = entry("default")
        self.network_input = combo(["offline", "normal", "restricted", "lan-only"])
        self.bridge_input = entry("incusbr0")
        self.network_input.connect("changed", self._network_mode_changed)
        self.egress_input = entry("github.com:443, api.github.com:443")
        self.security_profile_input = combo(["maximum-isolation", "normal-development", "restricted-development", "custom"])
        self.lifecycle_input = combo(["Persistente", "Excluir manualmente", "Excluir ao fechar o IsolateVM",
                                      "Restaurar snapshot inicial ao fechar",
                                      "Persistir somente /workspace"])
        self.workspace_size_input = Gtk.SpinButton.new_with_range(1, 2048, 1)
        self.workspace_size_input.set_value(20)
        self.workspace_size_input.set_sensitive(False)
        self.lifecycle_input.connect("changed", lambda combo: self.workspace_size_input.set_sensitive(
            combo.get_active() == 4))
        self.mount_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.mount_empty_label = label("Nenhuma pasta do host compartilhada", "muted")
        self.mount_list.append(self.mount_empty_label)
        self.mount_rows: list[MountEditor] = []
        self.add_mount_button = button("+ Compartilhar pasta…", self._add_mount_row)
        self.copy_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.copy_empty_label = label("Nenhum arquivo ou pasta marcado para cópia única", "muted")
        self.copy_list.append(self.copy_empty_label)
        self.copy_rows: list[CopyEditor] = []
        self.add_copy_file_button = button("+ Copiar arquivo uma vez…", lambda: self._add_copy_row("file"))
        self.add_copy_folder_button = button("+ Copiar pasta uma vez…", lambda: self._add_copy_row("directory"))
        self.apt_input = entry()
        self.pip_input = entry()
        self.pipx_input = entry()
        self.npm_input = entry()
        self.cargo_input = entry()
        self.go_input = entry()
        self._original_apt_order: tuple[str, ...] = ()
        self._original_pipx_order: tuple[str, ...] = ()
        self._original_npm_order: tuple[str, ...] = ()
        self._original_external_order: tuple[str, ...] = ()
        self.catalog_checks: dict[str, Gtk.CheckButton] = {}
        self.catalog_sections: list[Gtk.Expander] = []
        for title, items in CATALOG_GROUPS:
            section = Gtk.Expander(label=title)
            section.set_expanded(title == "Básico")
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            body.set_margin_start(12); body.set_margin_top(6); body.set_margin_bottom(6)
            for item in items:
                manager_label = {"apt": "APT", "pipx": "PyPI / pipx", "npm": "npm global",
                                 "external": "APT upstream assinado"}[item.manager]
                check = Gtk.CheckButton(label=f"{item.label} · {item.package} · {manager_label}")
                if item.package in {"docker.io", "podman"}:
                    check.set_tooltip_text("Instala dentro da VM; recursos de contêiner podem exigir suporte adicional do guest")
                if item.package == "rustup":
                    check.set_tooltip_text("Instala e define a toolchain stable para ubuntu no primeiro boot; o alias stable acompanha novas versões.")
                key = item.package if item.manager == "apt" else f"{item.manager}:{item.package}"
                self.catalog_checks[key] = check
                body.append(check)
            section.set_child(body)
            self.catalog_sections.append(section)
        self.ai_coding_checks: dict[str, Gtk.CheckButton] = {}
        for item in AI_CODING_ITEMS:
            method = "npm · latest" if item.manager == "npm" else "PyPI / pipx · 0.86.2"
            check = Gtk.CheckButton(label=f"{item.label} · {method}")
            if item.package == "opencode-ai@latest":
                check.set_tooltip_text("O pacote npm baixa o binário nativo da plataforma durante a instalação.")
            elif item.package == "aider-chat==0.86.2":
                check.set_tooltip_text("Versão fixada; requer Python 3.10–3.12 (Ubuntu 22.04 ou 24.04).")
            else:
                check.set_tooltip_text("Instala somente dentro da VM. Nenhuma autenticação do host é copiada.")
            self.ai_coding_checks[item.package] = check
        self.aider_status = label("", "muted")
        self.release_input.connect("changed", lambda *_: self._update_aider_status())
        self.python_check = Gtk.CheckButton(label="Python (python3, python3-pip)")
        self.node_check = Gtk.CheckButton(label="Node.js (nodejs, npm)")
        self.rust_check = Gtk.CheckButton(label="Rust (rustc, cargo)")
        self.dotnet8_check = Gtk.CheckButton(label="SDK .NET 8.0 · feeds Ubuntu 22.04/24.04")
        self.dotnet10_check = Gtk.CheckButton(label="SDK .NET 10.0 · feeds Ubuntu 24.04/26.04")
        self.environment_view = Gtk.TextView()
        self.environment_view.set_monospace(True)
        self.environment_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.environment_view.set_size_request(-1, 120)
        self.secret_ref_names: set[str] = set()
        self.save_template_check = Gtk.CheckButton(label="Salvar como template sem caminhos pessoais de mounts e cópias")
        self._update_aider_status()
        self._render_step()

    def _update_aider_status(self) -> None:
        release = self.release_input.get_active_text()
        if release in AIDER_SUPPORTED_RELEASES:
            self.aider_status.set_text("Aider 0.86.2 está disponível nas imagens Ubuntu 22.04 e 24.04. Ferramentas de coding não recebem credenciais do host; faça login na VM ou referencie secrets explicitamente.")
        else:
            self.aider_status.set_text("Aider 0.86.2 requer Python 3.10–3.12 e não está disponível para Ubuntu 26.04. Escolha outra versão Ubuntu ou deixe Aider desmarcado.")

    def _render_step(self) -> None:
        self._clear(self.step_body)
        titles = ["1. Nome", "2. Sistema operacional", "3. Hardware", "4. Disco",
                  "5. Rede", "6. Acesso ao host", "7. Software", "8. Ferramentas de desenvolvimento",
                  "9. Variáveis de ambiente", "10. Provisionamento", "11. Segurança",
                  "12. Revisão", "13. Criar"]
        self.step_title.set_text(titles[self.wizard_step])
        self.back_btn.set_sensitive(self.wizard_step > 0)
        self.next_btn.set_label("Criar ambiente" if self.wizard_step == 12 else "Próximo")
        self.next_btn.set_sensitive(True)
        if self.wizard_step == 0:
            self.step_body.append(row("Nome", self.name_input))
            self.step_body.append(label("Use letras minúsculas, números e hífen. A criação começa após a confirmação final.", "muted"))
        elif self.wizard_step == 1:
            self.step_body.append(row("Ubuntu cloud · versão", self.release_input))
            self.step_body.append(label("Tipo de ambiente", "section-title"))
            self.step_body.append(self.headless_check)
            self.step_body.append(self.desktop_check)
            self.step_body.append(row("Ambiente gráfico (somente Desktop)", self.desktop_input))
            self.step_body.append(label("Desktop instala pacotes no primeiro boot; precisa de repositórios acessíveis. A imagem cloud não define senha de login gráfico: configure-a dentro da VM antes de usar a console VGA.", "risk"))
            self.step_body.append(label("Origem: images.linuxcontainers.org. Consulte os metadados antes do download.", "muted"))
            self.step_body.append(button("Consultar imagem", self._show_image_info))
        elif self.wizard_step == 2:
            for title, item in [("vCPU", self.cpu_input), ("RAM (MiB)", self.ram_input)]:
                self.step_body.append(row(title, item))
            self.step_body.append(self.ram_status)
            self._update_ram_capacity()
            self.step_body.append(row("Pinning de CPUs lógicas do host (opcional)", self.cpu_pinning_input))
            self.step_body.append(label("IDs do host Incus separados por vírgula; exemplos: 0-3,6-7 ou 2-2 para fixar um único ID. A quantidade de IDs define a quantidade de vCPUs. Consulte os IDs em Hardware após criar a VM. Pinning exige VM parada e não reserva as CPUs exclusivamente.", "muted"))
            self.step_body.append(button("Mostrar CPUs disponíveis no Incus", self._show_host_cpu_ids))
            self.step_body.append(label("Limite percentual e prioridade de CPU são opções de containers Incus, não VMs. A arquitetura vem da imagem Ubuntu compatível com o host.", "risk"))
        elif self.wizard_step == 3:
            self.step_body.append(row("Disco (GiB)", self.disk_input))
            self.step_body.append(row("Pool Incus", self.pool_input))
        elif self.wizard_step == 4:
            self.step_body.append(row("Modo de rede · offline por padrão", self.network_input))
            self.step_body.append(row("Bridge Incus existente", self.bridge_input))
            self.step_body.append(button("Escolher bridge Incus existente…", self._choose_bridge))
            self.step_body.append(row("Saída permitida (destino:porta; separados por vírgula)", self.egress_input))
            self.step_body.append(label("Bridge customizada: escolha uma bridge Incus gerenciada existente; nenhuma rede do host será criada. Internet normal não filtra destinos. Restricted aceita domínio, IPv4 ou CIDR. LAN-only aceita apenas CIDR IPv4 privado em 10/8, 172.16/12 ou 192.168/16. Os dois modos proxied bloqueiam DNS e conexões diretas da VM; o proxy permite somente TCP nas portas declaradas e o host precisa ter rota aos destinos LAN.", "risk"))
        elif self.wizard_step == 5:
            self.step_body.append(label("Acessos ao Host", "section-title"))
            self.step_body.append(label("COMPARTILHAR PERMANENTEMENTE · a pasta continua ligada ao host", "section-title"))
            self.step_body.append(self.mount_list)
            self.step_body.append(self.add_mount_button)
            self.add_mount_button.set_sensitive(len(self.mount_rows) < 16)
            self.step_body.append(label("Escolha RO ou RW. A VM mantém acesso à pasta enquanto o dispositivo Incus estiver anexado.", "muted"))
            self.step_body.append(label("COPIAR UMA VEZ · arquivos entram no disco da VM", "section-title"))
            self.step_body.append(self.copy_list)
            controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            controls.append(self.add_copy_file_button)
            controls.append(self.add_copy_folder_button)
            self.step_body.append(controls)
            for widget in (self.add_copy_file_button, self.add_copy_folder_button):
                widget.set_sensitive(len(self.copy_rows) < 16)
            self.step_body.append(label("Cópias são enviadas pelo agente Incus após o primeiro start, sem mount permanente. Os arquivos ficam no disco e em backups da VM; alteração posterior no host não os atualiza.", "risk"))
        elif self.wizard_step == 6:
            self.step_body.append(label("Selecione software por categoria. O manifesto registra o pacote, gerenciador e versão escolhidos.", "muted"))
            for section in self.catalog_sections:
                self.step_body.append(section)
            self.step_body.append(row("Outros pacotes APT (separados por vírgula)", self.apt_input))
            self.step_body.append(row("Pacotes Python no venv da VM (nome ou nome==versão)", self.pip_input))
            self.step_body.append(row("Aplicativos CLI via pipx (nome ou nome==versão)", self.pipx_input))
            self.step_body.append(row("Pacotes npm globais na VM (nome ou nome@versão)", self.npm_input))
            self.step_body.append(row("Crates Cargo (crate@X.Y.Z)", self.cargo_input))
            self.step_body.append(row("Ferramentas Go (módulo/comando@vX.Y.Z)", self.go_input))
            self.step_body.append(label("Instalação via cloud-init no primeiro boot. Os presets Python e npm têm versões fixas; transitive dependencies e pacotes APT seguem os repositórios do guest. No modo offline, downloads podem falhar.", "muted"))
            self.step_body.append(label("Rustup instala e define o canal stable, que pode avançar entre execuções; ele conflita com o preset Rust dos repositórios Ubuntu. Docker/Podman rodam no guest e podem exigir suporte adicional. kubectl segue o canal Kubernetes 1.37; Helm usa um repositório APT comunitário mantido pela Buildkite, não pelo projeto Helm; Terraform usa o repositório assinado pela HashiCorp. Esses repositórios acompanham as versões disponíveis e exigem rede no guest.", "risk"))
        elif self.wizard_step == 7:
            for widget in (self.python_check, self.node_check, self.rust_check):
                self.step_body.append(widget)
            self.step_body.append(self.dotnet8_check)
            self.step_body.append(self.dotnet10_check)
            self.step_body.append(label(".NET 8.0 não está na feed padrão Ubuntu 26.04; .NET 10.0 não está na feed padrão 22.04. O wizard rejeita essas combinações sem uma fonte explícita.", "muted"))
            self.step_body.append(label("AI Coding", "section-title"))
            for check in self.ai_coding_checks.values():
                self.step_body.append(check)
            self.step_body.append(self.aider_status)
            self.step_body.append(label("OpenAI Codex, Claude Code e OpenCode são instalados pela versão npm atual; Aider usa o release 0.86.2 via pipx. Faça login dentro da VM ou referencie um secret guardado nesta sessão. O host nunca fornece credenciais ou arquivos de autenticação automaticamente.", "muted"))
        elif self.wizard_step == 8:
            self.step_body.append(label("Somente valores não secretos. Uma linha NOME=VALOR por variável.", "risk"))
            self.step_body.append(self.environment_view)
            self.step_body.append(label("Os valores serão incluídos no manifesto exportado, na configuração Incus e em /etc/environment da VM.", "muted"))
            self.step_body.append(label("Secrets para o guest", "section-title"))
            self.step_body.append(label("O manifesto guarda apenas nomes. Valores ficam no cofre do usuário e só são enviados à VM por ação separada após a criação.", "muted"))
            if not self.secret_ref_names:
                self.step_body.append(label("Nenhuma referência de secret selecionada", "muted"))
            for name in sorted(self.secret_ref_names):
                strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                strip.append(label(name))
                strip.append(button("Remover referência", lambda n=name: self._remove_secret_reference(n)))
                self.step_body.append(strip)
            self.step_body.append(button("Referenciar um secret existente…", self._choose_secret_reference))
            self.step_body.append(button("Salvar/atualizar um secret…", lambda: self._secret_value_dialog(self._add_secret_reference)))
        elif self.wizard_step == 9:
            try:
                manifest = self._form_manifest()
                config = cloud_config(manifest)
                self.step_body.append(label("Configuração cloud-init aplicada ao primeiro boot da VM:", "muted"))
                preview = Gtk.TextView()
                preview.set_editable(False)
                preview.set_cursor_visible(False)
                preview.set_monospace(True)
                preview.get_buffer().set_text(config or "Nenhum provisionamento adicional.")
                preview.set_size_request(-1, 220)
                self.step_body.append(preview)
            except Exception as exc:
                self.step_body.append(label(f"Preview pendente: {exc}", "risk"))
                self.step_body.append(label("Ajuste os dados nas etapas anteriores ou selecione o perfil apropriado na próxima etapa.", "muted"))
        elif self.wizard_step == 10:
            self.step_body.append(row("Perfil de segurança", self.security_profile_input))
            self.step_body.append(label("Máximo isolamento: sem NIC, mounts, dispositivos repassados ou secrets. Outros perfis permitem somente concessões explícitas; secrets exigem entrega separada ao guest.", "muted"))
            self.step_body.append(label("Desenvolvimento restrito usa o proxy de saída por VM e a allowlist TCP revisada na etapa Rede.", "muted"))
            self.step_body.append(row("Ciclo de vida", self.lifecycle_input))
            self.step_body.append(row("Tamanho persistente de /workspace (GiB)", self.workspace_size_input))
            self.workspace_size_input.set_sensitive(self.lifecycle_input.get_active() == 4)
            self.step_body.append(label("Persistir somente /workspace usa um volume Incus separado, sem caminho do host; no primeiro boot, o cloud-init prepara o diretório para ubuntu. Ao fechar, a VM volta ao snapshot inicial e mantém esse volume. Excluir ao fechar apaga a VM; restaurar snapshot inicial apaga mudanças no disco. Nenhuma ação ocorre após encerramento forçado. O backup completo da VM não inclui o volume /workspace; exporte-o separadamente.", "risk"))
        elif self.wizard_step in (11, 12):
            try:
                self.current_manifest = self._form_manifest()
                for line in self.current_manifest.review(): self.step_body.append(label(line))
                for finding in assess(self.current_manifest):
                    self.step_body.append(label(f"{finding.severity.upper()}: {finding.message}", "risk"))
                if self.wizard_step == 11:
                    self.step_body.append(self.save_template_check)
                    self.step_body.append(button("Simular criação", self._dry_run))
                    self.step_body.append(button("Salvar template", self._save_current_template))
                    self.step_body.append(button("Salvar nova versão do template", self._save_current_template_versioned))
                    self.step_body.append(button("Exportar manifesto…", self._export_current))
                    self.step_body.append(button("Exportar nova versão no HOME", lambda: self._export_versioned(self.current_manifest)))
                else:
                    self.step_body.append(label("A VM será criada parada. Confirme a operação no próximo diálogo.", "risk"))
            except Exception as exc:
                self.current_manifest = None
                self.step_body.append(label(str(exc), "error"))
            self.next_btn.set_sensitive(self.current_manifest is not None)

    def _environment(self) -> dict[str, str]:
        buffer = self.environment_view.get_buffer()
        raw = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
        result: dict[str, str] = {}
        for number, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            if "=" not in line:
                raise ValidationError(f"Variável de ambiente, linha {number}: use NOME=VALOR")
            name, value = line.split("=", 1)
            if name in result:
                raise ValidationError(f"Variável de ambiente duplicada: {name}")
            result[name] = value
        return result

    def _update_ram_capacity(self) -> None:
        try:
            values = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                key, separator, value = line.partition(":")
                if separator and key in {"MemTotal", "MemAvailable"}:
                    values[key] = int(value.strip().split()[0])
            total_mib = values["MemTotal"] // 1024
            available_mib = values["MemAvailable"] // 1024
        except (OSError, KeyError, ValueError, IndexError):
            self.ram_status.set_text("Host: memória total e disponível não puderam ser consultadas.")
            return
        selected_mib = self.ram_input.get_value_as_int()
        after_mib = available_mib - selected_mib
        self.ram_status.set_text(
            f"Host: {total_mib} MiB no total · {available_mib} MiB disponíveis agora\n"
            f"VM selecionada: {selected_mib} MiB · estimativa disponível após alocar: {after_mib} MiB. "
            "Estimativa simples baseada na memória disponível atual; o uso real varia. "
            "VMs usam RAM fixa e podem pressionar o host quando a memória estiver baixa."
        )
        if after_mib < 0:
            self.ram_status.add_css_class("risk")
        else:
            self.ram_status.remove_css_class("risk")

    def _show_host_cpu_ids(self) -> None:
        def show(values: object) -> None:
            ids = ", ".join(str(value) for value in values)
            self._toast("IDs de CPU lógicas online segundo o Incus: " + (ids or "nenhum"))
        self._work(self.service.host_cpu_ids, show)

    def _network_mode_changed(self, _widget: Gtk.ComboBoxText) -> None:
        current = self.bridge_input.get_text().strip()
        if self.network_input.get_active_text() in PROXIED_NETWORK_MODES and current == "incusbr0":
            self.bridge_input.set_text(f"incusbr-{os.getuid()}")
        elif self.network_input.get_active_text() not in PROXIED_NETWORK_MODES and current == f"incusbr-{os.getuid()}":
            self.bridge_input.set_text("incusbr0")

    def _choose_bridge(self) -> None:
        dialog = Gtk.Dialog(title="Escolher bridge Incus", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        choose = dialog.add_button("Usar bridge", Gtk.ResponseType.OK)
        choose.set_sensitive(False)
        content = dialog.get_content_area()
        content.set_spacing(8); content.set_margin_start(16); content.set_margin_end(16)
        content.set_margin_top(12); content.set_margin_bottom(12)
        content.append(label("Somente bridges gerenciadas retornadas pelo Incus aparecem aqui. A seleção não cria nem altera a bridge.", "muted"))
        status = label("Consultando bridges…", "muted")
        content.append(status)
        chooser = Gtk.ComboBoxText()
        content.append(chooser)
        choices: list[str] = []

        def loaded(values: object) -> None:
            all_bridges = [str(value) for value in values if isinstance(value, str)]
            mode = self.network_input.get_active_text()
            choices.extend(value for value in all_bridges
                           if mode not in PROXIED_NETWORK_MODES or value == f"incusbr-{os.getuid()}")
            for value in choices:
                chooser.append_text(value)
            current = self.bridge_input.get_text().strip()
            chooser.set_active(choices.index(current) if current in choices else (0 if choices else -1))
            choose.set_sensitive(bool(choices))
            status.set_text("Escolha uma bridge disponível." if choices else
                            ("Proxy restrito exige a bridge incusbr-<UID>, que não foi encontrada."
                             if mode in PROXIED_NETWORK_MODES else
                             "Nenhuma bridge Incus gerenciada foi encontrada."))

        self._work(self.service.bridges, loaded,
                   lambda exc: status.set_text("Não foi possível consultar bridges: " + str(exc)))

        def response(window: Gtk.Dialog, response_id: int) -> None:
            selected = chooser.get_active_text()
            window.destroy()
            if response_id == Gtk.ResponseType.OK and selected:
                self.bridge_input.set_text(selected)

        dialog.connect("response", response)
        dialog.present()

    def _add_secret_reference(self, name: str) -> None:
        self.secret_ref_names.add(name)
        if self.wizard_step == 8:
            self._render_step()

    def _remove_secret_reference(self, name: str) -> None:
        self.secret_ref_names.discard(name)
        self._render_step()

    def _choose_secret_reference(self) -> None:
        dialog = Gtk.Dialog(title="Referenciar um secret do cofre", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        use_button = dialog.add_button("Adicionar referência", Gtk.ResponseType.OK)
        use_button.set_sensitive(False)
        content = dialog.get_content_area()
        content.set_spacing(8); content.set_margin_start(16); content.set_margin_end(16)
        content.set_margin_top(12); content.set_margin_bottom(12)
        content.append(label("São exibidos somente nomes; valores nunca aparecem nesta lista.", "muted"))
        status = label("Lendo nomes do cofre…", "muted")
        content.append(status)
        chooser = Gtk.ComboBoxText()
        content.append(chooser)
        names: list[str] = []

        def loaded(values: object) -> None:
            names.extend(str(value) for value in values if isinstance(value, str))
            for name in names:
                chooser.append_text(name)
            chooser.set_active(0 if names else -1)
            use_button.set_sensitive(bool(names))
            status.set_text("Escolha um nome para referenciar." if names else "Cofre vazio; salve um secret primeiro.")

        self._work(self.secret_vault.names, loaded,
                   lambda exc: status.set_text("Cofre indisponível: " + str(exc)))

        def response(d: Gtk.Dialog, response_id: int) -> None:
            selected = chooser.get_active()
            d.destroy()
            if response_id == Gtk.ResponseType.OK and 0 <= selected < len(names):
                self._add_secret_reference(names[selected])

        dialog.connect("response", response)
        dialog.present()

    def _form_manifest(self) -> Manifest:
        requested_apt = [x.strip() for x in self.apt_input.get_text().split(",") if x.strip()]
        requested_pipx = [x.strip() for x in self.pipx_input.get_text().split(",") if x.strip()]
        requested_npm = [x.strip() for x in self.npm_input.get_text().split(",") if x.strip()]
        requested_external: list[str] = []
        for key, check in self.catalog_checks.items():
            if not check.get_active():
                continue
            manager, package = (("apt", key) if ":" not in key else key.split(":", 1))
            {"apt": requested_apt, "pipx": requested_pipx, "npm": requested_npm,
             "external": requested_external}[manager].append(package)
        for item in AI_CODING_ITEMS:
            if self.ai_coding_checks[item.package].get_active():
                {"npm": requested_npm, "pipx": requested_pipx}[item.manager].append(item.package)
        if self.python_check.get_active(): requested_apt.extend(LANGUAGE_PRESETS["python"])
        if self.node_check.get_active(): requested_apt.extend(LANGUAGE_PRESETS["node"])
        if self.rust_check.get_active(): requested_apt.extend(LANGUAGE_PRESETS["rust"])
        if self.dotnet8_check.get_active(): requested_apt.append("dotnet-sdk-8.0")
        if self.dotnet10_check.get_active(): requested_apt.append("dotnet-sdk-10.0")
        requested_apt = list(dict.fromkeys(requested_apt))
        packages = [package for package in self._original_apt_order if package in requested_apt]
        packages.extend(package for package in requested_apt if package not in packages)
        pip_packages = [x.strip() for x in self.pip_input.get_text().split(",") if x.strip()]
        pipx_packages = list(dict.fromkeys(requested_pipx))
        ordered_pipx = [package for package in self._original_pipx_order if package in pipx_packages]
        ordered_pipx.extend(package for package in pipx_packages if package not in ordered_pipx)
        npm_packages = list(dict.fromkeys(requested_npm))
        ordered_npm = [package for package in self._original_npm_order if package in npm_packages]
        ordered_npm.extend(package for package in npm_packages if package not in ordered_npm)
        external_tools = list(dict.fromkeys(requested_external))
        ordered_external = [package for package in self._original_external_order if package in external_tools]
        ordered_external.extend(package for package in external_tools if package not in ordered_external)
        cargo_packages = [x.strip() for x in self.cargo_input.get_text().split(",") if x.strip()]
        go_packages = [x.strip() for x in self.go_input.get_text().split(",") if x.strip()]
        mounts = []
        for index, editor in enumerate(self.mount_rows, start=1):
            host = editor.host.get_text().strip()
            if not host:
                raise ValidationError(f"Pasta {index}: escolha um diretório do host ou remova a linha")
            mounts.append({"host": host, "guest": editor.guest.get_text().strip(),
                           "mode": "rw" if editor.rw.get_active() else "ro"})
        mode = self.network_input.get_active_text()
        egress = []
        if mode in PROXIED_NETWORK_MODES:
            for value in self.egress_input.get_text().split(","):
                destination = value.strip()
                if not destination or destination.count(":") != 1:
                    raise ValidationError("Saída restrita: use destino:porta, separado por vírgula")
                target, port = destination.rsplit(":", 1)
                if mode == "lan-only" and "/" not in target:
                    raise ValidationError("LAN-only: use somente CIDR IPv4 privado:porta")
                kind = "cidr" if "/" in target else ("ip" if target.replace(".", "").isdigit() else "domain")
                if not port.isdigit(): raise ValidationError("Saída restrita: porta inválida")
                egress.append({"kind": kind, "value": target, "port": int(port), "protocol": "tcp"})
        lifecycle_disposition = ("persistent", "manual-delete", "delete-on-close",
                                 "restore-initial-on-close", "persist-workspace")[self.lifecycle_input.get_active()]
        lifecycle = {"disposition": lifecycle_disposition}
        if lifecycle_disposition == "persist-workspace":
            lifecycle["workspaceSizeGiB"] = self.workspace_size_input.get_value_as_int()
        raw = {"schemaVersion": 1, "name": self.name_input.get_text().strip(),
               "os": {"distribution": "ubuntu", "release": self.release_input.get_active_text(),
                      **({"desktop": ("gnome", "kde", "xfce")[self.desktop_input.get_active()]}
                         if self.desktop_check.get_active() else {})},
               "resources": {"cpu": self.cpu_input.get_value_as_int(),
                             "memoryMiB": self.ram_input.get_value_as_int(),
                             "diskGiB": self.disk_input.get_value_as_int(), "pool": self.pool_input.get_text().strip()},
               "network": {"mode": mode, **({"bridge": self.bridge_input.get_text().strip()} if mode in {"normal", "restricted", "lan-only"} else {}),
                           **({"egress": egress} if egress else {})},
               "security": {"profile": "restricted-development" if mode in PROXIED_NETWORK_MODES else self.security_profile_input.get_active_text()},
               "lifecycle": lifecycle,
               "mounts": mounts,
               "copies": [{"host": editor.host.get_text().strip(), "guest": editor.guest.get_text().strip(),
                           "kind": editor.kind, "includeHidden": editor.include_hidden.get_active()}
                          for editor in self.copy_rows],
               "software": {"apt": packages, "pip": pip_packages, "pipx": ordered_pipx,
                            "npm": ordered_npm, "external": ordered_external,
                                              "cargo": cargo_packages, "go": go_packages},
               "secrets": sorted(self.secret_ref_names),
               "environment": self._environment(),
               "metadata": ({"cpuPinning": self.cpu_pinning_input.get_text().strip()}
                            if self.cpu_pinning_input.get_text().strip() else {})}
        return Manifest.parse(raw)

    def _add_mount_row(self, mount: Mount | None = None) -> None:
        if len(self.mount_rows) >= 16:
            self._toast("Máximo de 16 pastas compartilhadas")
            return
        if not self.mount_rows:
            self.mount_list.remove(self.mount_empty_label)
        frame = Gtk.Frame()
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        body.set_margin_start(10); body.set_margin_end(10)
        body.set_margin_top(10); body.set_margin_bottom(10)
        frame.set_child(body)
        host = entry(mount.host if mount else "")
        guest = entry(mount.guest if mount else "/workspace")
        rw = Gtk.CheckButton(label="Leitura e escrita (RW)")
        rw.set_active(bool(mount and mount.mode == "rw"))
        editor = MountEditor(frame, host, guest, rw)
        body.append(row("Pasta do host", host))
        body.append(button("Escolher pasta…", lambda: self._choose_mount_folder(host)))
        body.append(row("Destino na VM", guest))
        body.append(rw)
        body.append(button("Remover esta pasta", lambda: self._remove_mount_row(editor), "destructive-action"))
        self.mount_rows.append(editor)
        self.mount_list.append(frame)
        self.add_mount_button.set_sensitive(len(self.mount_rows) < 16)

    def _remove_mount_row(self, editor: MountEditor) -> None:
        self.mount_list.remove(editor.frame)
        self.mount_rows.remove(editor)
        if not self.mount_rows:
            self.mount_list.append(self.mount_empty_label)
        self.add_mount_button.set_sensitive(True)

    def _choose_mount_folder(self, target: Gtk.Entry) -> None:
        chooser = Gtk.FileDialog(title="Escolher pasta do host")
        def selected(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                folder = dialog.select_folder_finish(result)
                if folder.get_path(): target.set_text(folder.get_path())
            except GLib.Error:
                pass
        chooser.select_folder(self, None, selected)

    def _add_copy_row(self, kind: str, copy: CopySpec | None = None) -> None:
        if len(self.copy_rows) >= 16:
            self._toast("Máximo de 16 origens para cópia única")
            return
        if not self.copy_rows:
            self.copy_list.remove(self.copy_empty_label)
        frame = Gtk.Frame()
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        body.set_margin_start(10); body.set_margin_end(10)
        body.set_margin_top(10); body.set_margin_bottom(10)
        frame.set_child(body)
        host = entry(copy.host if copy else "")
        default_target = "/home/ubuntu/imports/" + ("new-file" if kind == "file" else "new-folder")
        guest = entry(copy.guest if copy else default_target)
        include_hidden = Gtk.CheckButton(label="Incluir arquivos ocultos desta origem")
        include_hidden.set_active(bool(copy and copy.include_hidden))
        editor = CopyEditor(frame, host, guest, kind, include_hidden)
        body.append(label("CÓPIA ÚNICA · ARQUIVO" if kind == "file" else "CÓPIA ÚNICA · PASTA", "section-title"))
        body.append(row("Origem no host", host))
        body.append(button("Escolher arquivo…" if kind == "file" else "Escolher pasta…",
                           lambda: self._choose_copy_source(editor)))
        body.append(row("Destino dentro de /home/ubuntu", guest))
        body.append(include_hidden)
        body.append(label("Ocultos podem conter credenciais. Caminhos sensíveis conhecidos, symlinks e dispositivos são bloqueados.", "risk"))
        body.append(button("Remover esta cópia", lambda: self._remove_copy_row(editor), "destructive-action"))
        self.copy_rows.append(editor)
        self.copy_list.append(frame)
        for widget in (self.add_copy_file_button, self.add_copy_folder_button):
            widget.set_sensitive(len(self.copy_rows) < 16)

    def _remove_copy_row(self, editor: CopyEditor) -> None:
        self.copy_list.remove(editor.frame)
        self.copy_rows.remove(editor)
        if not self.copy_rows:
            self.copy_list.append(self.copy_empty_label)
        for widget in (self.add_copy_file_button, self.add_copy_folder_button):
            widget.set_sensitive(True)

    def _choose_copy_source(self, editor: CopyEditor) -> None:
        chooser = Gtk.FileDialog(title="Escolher origem para cópia única")
        def selected(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                chosen = (dialog.open_finish(result) if editor.kind == "file" else
                          dialog.select_folder_finish(result))
                path = chosen.get_path()
                if path:
                    editor.host.set_text(path)
                    if editor.guest.get_text().endswith("/new-file") or editor.guest.get_text().endswith("/new-folder"):
                        editor.guest.set_text("/home/ubuntu/imports/" + Path(path).name)
            except GLib.Error:
                pass
        if editor.kind == "file": chooser.open(self, None, selected)
        else: chooser.select_folder(self, None, selected)

    def _back(self) -> None:
        self.wizard_step -= 1; self._render_step()

    def _next(self) -> None:
        if self.wizard_step < 12:
            if (self.wizard_step == 7 and self.ai_coding_checks["aider-chat==0.86.2"].get_active()
                    and self.release_input.get_active_text() not in AIDER_SUPPORTED_RELEASES):
                self._error_dialog(ValidationError(
                    "Aider 0.86.2 requer Python 3.10 a 3.12; selecione Ubuntu 22.04 ou 24.04 ou desmarque Aider"))
                return
            self.wizard_step += 1; self._render_step(); return
        manifest = self.current_manifest
        if not manifest: return
        copy_note = (f" {len(manifest.copies)} cópia(s) serão enviadas ao disco da VM após o primeiro start."
                     if manifest.copies else "")
        self._confirm("Criar VM Incus?", "A imagem poderá ser baixada e um disco criado. Nenhuma configuração global do host será alterada." + copy_note,
                      lambda: self._create(manifest))

    def _create(self, manifest: Manifest) -> None:
        self.next_btn.set_sensitive(False)
        progress_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        progress_box.append(label("Criando VM… A operação pode levar vários minutos.", "risk"))
        self.step_body.append(progress_box)
        def progress(message: str) -> None:
            GLib.idle_add(progress_box.append, label("• " + message))
        save_template_requested = self.save_template_check.get_active()
        def run() -> None:
            try:
                try:
                    self.service.create(manifest, progress)
                except Exception:
                    try: audit("create", manifest.name, "erro")
                    except OSError: pass
                    raise
                try:
                    audit("create", manifest.name, "ok")
                    save_instance_manifest(manifest)
                    if save_template_requested:
                        save_template_versioned(manifest.name, manifest); audit("template", manifest.name, "ok")
                except (OSError, ValidationError) as exc:
                    GLib.idle_add(self._toast, f"VM criada; registro local incompleto: {exc}")
            finally:
                GLib.idle_add(self.next_btn.set_sensitive, True)
        def done(_: object) -> None:
            self.next_btn.set_sensitive(True)
            self._toast(f"VM {manifest.name} criada e parada. Inicie pelo dashboard." +
                        (" Cópias aguardam o primeiro start." if manifest.copies else ""))
            self.show_dashboard()
        self._work(run, done)

    def _dry_run(self) -> None:
        manifest = self.current_manifest
        if not manifest: return
        self._work(lambda: plan_creation(self.service, manifest), self._show_creation_plan)

    def _show_creation_plan(self, plan: CreationPlan) -> None:
        dialog = Gtk.Dialog(title="Simulação de criação · somente leitura", transient_for=self, modal=True)
        dialog.add_button("Fechar", Gtk.ResponseType.CLOSE)
        scroller = Gtk.ScrolledWindow()
        scroller.set_size_request(720, 520)
        preview = Gtk.TextView(editable=False, cursor_visible=False,
                               monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        preview.set_margin_start(14); preview.set_margin_end(14)
        preview.set_margin_top(14); preview.set_margin_bottom(14)
        preview.get_buffer().set_text("\n".join(plan.lines()))
        scroller.set_child(preview)
        dialog.get_content_area().append(scroller)
        dialog.connect("response", lambda d, *_: d.destroy())
        dialog.present()

    def _show_image_info(self) -> None:
        release = self.release_input.get_active_text()
        def render(data: object) -> None:
            self._toast("\n".join(f"{key}: {value}" for key, value in data.items()))
        self._work(lambda: self.service.image_info(release), render)

    def _save_current_template(self) -> None:
        manifest = self.current_manifest
        if not manifest: return
        self._ask("Nome do template", manifest.name, lambda name: self._save_template(name, manifest))

    def _save_current_template_versioned(self) -> None:
        manifest = self.current_manifest
        if not manifest: return
        self._ask("Nome-base do template", manifest.name,
                  lambda name: self._save_template_versioned(name, manifest))

    def _save_template(self, name: str, manifest: Manifest) -> None:
        try:
            path = save_template(name, manifest)
            audit("template", manifest.name, "ok")
            self._toast(f"Template salvo em {path}; mounts e fontes de cópia pessoais foram removidos.")
        except Exception as exc: self._toast(str(exc))

    def _save_template_versioned(self, name: str, manifest: Manifest) -> None:
        try:
            path = save_template_versioned(name, manifest)
            audit("template", manifest.name, "ok")
            self._toast(f"Nova versão de template salva em {path}; caminhos pessoais foram removidos.")
        except Exception as exc: self._toast(str(exc))

    def _export_current(self) -> None:
        manifest = self.current_manifest
        if not manifest: return
        self._ask("Salvar manifesto em .yaml", str(Path.home() / f"{manifest.name}.yaml"),
                  lambda value: self._export_to(manifest, value))

    def _export_to(self, manifest: Manifest, path: str) -> None:
        try:
            export_manifest(manifest, Path(path)); audit("export", manifest.name, "ok")
            self._toast(f"Manifesto salvo em {path}")
        except Exception as exc: self._toast(str(exc))

    def show_templates(self) -> None:
        self._clear(self.templates_page)
        self.templates_page.append(label("Templates", "page-title"))
        self.templates_page.append(label("Templates locais removem mounts e fontes pessoais de cópia; guardam apenas referências de secrets, nunca valores.", "muted"))
        self.templates_page.append(label("A importação valida o schema e abre a revisão do wizard antes de qualquer criação Incus.", "muted"))
        self.templates_page.append(button("Importar manifesto…", lambda: self._ask("Caminho do arquivo YAML", "", self._import_from)))
        for name in templates():
            self.templates_page.append(button(name, lambda n=name: self._use_template(n)))

    def _use_template(self, name: str) -> None:
        try:
            manifest = load_template(name)
            self._fill_form(manifest)
            self.stack.set_visible_child_name("wizard")
        except Exception as exc: self._toast(str(exc))

    def _import_from(self, path: str) -> None:
        try:
            manifest = import_manifest(Path(path))
            self._fill_form(manifest)
            self.stack.set_visible_child_name("wizard")
        except Exception as exc: self._toast(str(exc))

    def _fill_form(self, manifest: Manifest) -> None:
        self.name_input.set_text(manifest.name)
        releases = ["24.04", "26.04", "22.04"]
        self.release_input.set_active(releases.index(manifest.release))
        self.desktop_check.set_active(manifest.desktop is not None)
        self.headless_check.set_active(manifest.desktop is None)
        self.desktop_input.set_active({"gnome": 0, "kde": 1, "xfce": 2}.get(manifest.desktop, 0))
        self.cpu_input.set_value(manifest.cpu); self.ram_input.set_value(manifest.memoryMiB)
        self.cpu_pinning_input.set_text(manifest.cpuPinning or "")
        self.disk_input.set_value(manifest.diskGiB); self.pool_input.set_text(manifest.pool)
        self.network_input.set_active({"offline": 0, "normal": 1, "restricted": 2,
                                       "lan-only": 3}[manifest.networkMode])
        profiles = ["maximum-isolation", "normal-development", "restricted-development", "custom"]
        self.security_profile_input.set_active(profiles.index(manifest.securityProfile))
        self.lifecycle_input.set_active({"persistent": 0, "manual-delete": 1,
                                         "delete-on-close": 2,
                                         "restore-initial-on-close": 3,
                                         "persist-workspace": 4}[manifest.lifecycleDisposition])
        self.workspace_size_input.set_value(manifest.workspaceSizeGiB or 20)
        self.bridge_input.set_text(manifest.bridge or "incusbr0")
        self.egress_input.set_text(", ".join(f"{rule.value}:{rule.port}" for rule in manifest.egress))
        self._original_apt_order = manifest.apt
        self._original_pipx_order = manifest.pipx
        self._original_npm_order = manifest.npm
        self._original_external_order = manifest.externalTools
        selected_apt = set(manifest.apt)
        selected_pipx = set(manifest.pipx)
        selected_npm = set(manifest.npm)
        selected_external = set(manifest.externalTools)
        for key, check in self.catalog_checks.items():
            manager, package = (("apt", key) if ":" not in key else key.split(":", 1))
            selected = {"apt": selected_apt, "pipx": selected_pipx,
                        "npm": selected_npm, "external": selected_external}[manager]
            check.set_active(package in selected)
        selected_presets: set[str] = set()
        for key, check in (("python", self.python_check), ("node", self.node_check), ("rust", self.rust_check)):
            enabled = all(package in selected_apt for package in LANGUAGE_PRESETS[key])
            check.set_active(enabled)
            if enabled: selected_presets.update(LANGUAGE_PRESETS[key])
        self.dotnet8_check.set_active("dotnet-sdk-8.0" in selected_apt)
        self.dotnet10_check.set_active("dotnet-sdk-10.0" in selected_apt)
        self.apt_input.set_text(",".join(package for package in manifest.apt
                                         if package not in APT_CATALOG_PACKAGES and
                                         package not in DOTNET_SDK_PACKAGES and
                                         package not in selected_presets))
        self.pip_input.set_text(",".join(manifest.pip))
        self.pipx_input.set_text(",".join(package for package in manifest.pipx
                                         if package not in PIPX_CATALOG_PACKAGES and
                                         package not in AI_CODING_PACKAGES["pipx"]))
        self.npm_input.set_text(",".join(x for x in manifest.npm
                                         if x not in NPM_CATALOG_PACKAGES and
                                         x not in AI_CODING_PACKAGES["npm"]))
        self.cargo_input.set_text(",".join(manifest.cargo))
        self.go_input.set_text(",".join(manifest.go))
        self.environment_view.get_buffer().set_text("\n".join(f"{key}={value}" for key, value in manifest.environment))
        self.secret_ref_names = set(manifest.secrets)
        for editor in tuple(self.copy_rows):
            self._remove_copy_row(editor)
        for copy in manifest.copies:
            self._add_copy_row(copy.kind, copy)
        selected_ai = {"npm": selected_npm, "pipx": selected_pipx}
        for item in AI_CODING_ITEMS:
            self.ai_coding_checks[item.package].set_active(item.package in selected_ai[item.manager])
        self._update_aider_status()
        for editor in tuple(self.mount_rows):
            self._remove_mount_row(editor)
        for mount in manifest.mounts:
            self._add_mount_row(mount)
        self.wizard_step = 11; self._render_step()
