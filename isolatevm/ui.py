"""Native GTK4 interface. All Incus mutations go through IncusService."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Callable

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .diagnostics import diagnose
from .incus import IncusError, IncusService, LocalIncus, VM
from .mock import MockIncus
from .model import INITIAL_SNAPSHOT, Manifest, ValidationError
from .metrics import MetricsSnapshot, cpu_percent_between
from .storage import (audit, complete_onboarding, first_run, history, load_instance_manifest,
                      load_theme, load_auto_snapshot, remove_instance_manifest,
                      save_auto_snapshot, save_instance_manifest, save_theme,
                      export_manifest_versioned)
from .secret_vault import SecretVault, validate_secret_name, validate_secret_value
from .snapshot_policy import PROTECTED_ACTIONS, protection_name
from .cpu import CPUSelectionError, format_cpu_set, parse_cpu_set
from . import change_diff as diff


from .ui_widgets import CSS, label, button, row, entry, combo
from .ui_wizard import WizardMixin
from .ui_details import DetailsMixin
from .ui_metrics import MetricsMixin
from .ui_terminal import TerminalMixin


_DESKTOP_SESSION_ENV = (
    "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
    "XAUTHORITY", "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "XDG_SESSION_DESKTOP",
    "XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID", "GDK_BACKEND",
)


def _local_gui_client_environment(service: LocalIncus) -> dict[str, str]:
    """Keep the local client environment small while preserving desktop launch context."""
    environment = service.terminal_environment()
    for key in _DESKTOP_SESSION_ENV:
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


class IsolateWindow(WizardMixin, DetailsMixin, MetricsMixin, TerminalMixin, Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application) -> None:
        super().__init__(application=app, title="IsolateVM")
        self.set_default_size(1100, 730)
        self.mock = os.environ.get("ISOLATEVM_MOCK") == "1"
        self.secret_vault = SecretVault()
        self.service: IncusService = MockIncus() if self.mock else self._live_service()
        self.current_manifest: Manifest | None = None
        self.selected_vm: VM | None = None
        self.wizard_step = 0
        self._metrics_generation = 0
        self._dashboard_generation = 0
        self._allow_close = False
        self._close_scan_pending = False
        self.connect("close-request", self._close_requested)

        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(self.get_display(), provider,
                                                   Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_child(root)
        header = Gtk.HeaderBar()
        header.set_title_widget(label("IsolateVM", "section-title"))
        if self.mock:
            header.pack_end(label("MODO MOCK", "risk"))
        elif isinstance(self.service, LocalIncus):
            if self.service.access_mode == "admin":
                header.pack_end(label("INCUS · ACESSO AMPLO", "risk"))
            else:
                header.pack_end(label("INCUS · SOCKET DE USUÁRIO", "muted"))
        else:
            header.pack_end(label("INCUS INACESSÍVEL", "risk"))
        root.append(header)
        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        root.append(body)
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        sidebar = Gtk.StackSidebar(stack=self.stack)
        sidebar.set_size_request(220, -1)
        body.append(sidebar)
        body.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        body.append(self.stack)

        self.welcome = self._scroll_page("Bem-vindo", "welcome")
        self.dashboard = self._scroll_page("Dashboard", "dashboard")
        self.diagnostics = self._scroll_page("Diagnóstico do Host", "diagnostics")
        self.wizard = self._scroll_page("Novo Ambiente", "wizard")
        self.details = self._scroll_page("Permissões efetivas", "details")
        self.terminal_page = self._scroll_page("Terminal", "terminal")
        self.metrics_page = self._scroll_page("Monitoramento", "metrics")
        self.templates_page = self._scroll_page("Templates", "templates")
        self.history_page = self._scroll_page("Histórico", "history")
        self.settings_page = self._scroll_page("Configurações", "settings")
        self._build_settings()
        self._build_terminal_page()
        self._build_wizard()
        self._build_welcome()
        if first_run() or (isinstance(self.service, LocalIncus) and self.service.access_mode == "confined"):
            self.stack.set_visible_child_name("welcome")
        else: self.show_dashboard()

    def _live_service(self) -> IncusService:
        try: return LocalIncus()
        except IncusError: return MockUnavailable()

    def _scroll_page(self, title: str, name: str) -> Gtk.Box:
        scroller = Gtk.ScrolledWindow(hexpand=True, vexpand=True)
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.set_margin_start(24); page.set_margin_end(24)
        page.set_margin_top(20); page.set_margin_bottom(24)
        scroller.set_child(page)
        self.stack.add_titled(scroller, name, title)
        if name == "diagnostics": scroller.connect("map", lambda *_: self.show_diagnostics())
        if name == "templates": scroller.connect("map", lambda *_: self.show_templates())
        if name == "history": scroller.connect("map", lambda *_: self.show_history())
        return page

    def _clear(self, box: Gtk.Box) -> None:
        while child := box.get_first_child(): box.remove(child)

    def _build_welcome(self) -> None:
        self.welcome.append(label("Bem-vindo ao IsolateVM", "page-title"))
        self.welcome.append(label("Crie VMs Ubuntu com acesso ao host negado por padrão. O aplicativo não configura Incus nem altera grupos automaticamente."))
        self.welcome.append(label("1. Verifique Ubuntu, KVM, QEMU e Incus.\n2. Configure Incus com um projeto restrito quando possível.\n3. Escolha pool e, se quiser rede, uma bridge.\n4. Revise cada permissão antes de criar.", "muted"))
        if isinstance(self.service, LocalIncus) and self.service.access_mode == "confined":
            self.welcome.append(label("O primeiro contato com o socket de usuário pode criar seu projeto Incus e inicializar o serviço com configurações padrão. Conecte somente após revisar esse efeito no host.", "risk"))
        self.welcome.append(button("Verificar sistema", lambda: self.stack.set_visible_child_name("diagnostics"), "suggested-action"))
        def ready() -> None:
            if isinstance(self.service, LocalIncus) and self.service.confined_connection_pending:
                def connect() -> None:
                    self.service.approve_confined_connection()
                    complete_onboarding()
                    self.show_dashboard()
                self._confirm("Conectar ao Incus de usuário?",
                              "O primeiro contato poderá criar o projeto pessoal user-UID e inicializar o Incus com configurações padrão neste host.",
                              connect)
            else:
                complete_onboarding(); self.show_dashboard()
        self.welcome.append(button("Ir ao dashboard", ready))

    def _toast(self, message: str) -> None:
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, text=message,
                                   buttons=Gtk.ButtonsType.OK)
        dialog.connect("response", lambda d, *_: d.destroy())
        dialog.present()

    def _error_dialog(self, error: Exception) -> None:
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, text=str(error),
                                   buttons=Gtk.ButtonsType.OK)
        if isinstance(error, IncusError) and error.technical:
            dialog.set_property("secondary-text", "Detalhes técnicos: " + error.technical)
        dialog.connect("response", lambda d, *_: d.destroy())
        dialog.present()

    def _secret_value_dialog(self, on_saved: Callable[[str], None], preset_name: str = "") -> None:
        dialog = Gtk.Dialog(title="Salvar secret no cofre do usuário", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Salvar no cofre", Gtk.ResponseType.OK)
        content = dialog.get_content_area()
        content.set_spacing(10); content.set_margin_start(16); content.set_margin_end(16)
        content.set_margin_top(12); content.set_margin_bottom(12)
        name = entry(preset_name)
        name.set_editable(not bool(preset_name))
        password = Gtk.PasswordEntry()
        password.set_placeholder_text("Valor oculto; não será exibido novamente")
        content.append(row("Referência de ambiente", name))
        content.append(row("Valor do secret", password))
        content.append(label("O valor vai para o Secret Service do usuário. O IsolateVM não o grava no manifesto, histórico ou configuração Incus.", "muted"))

        def response(d: Gtk.Dialog, response_id: int) -> None:
            secret_name, secret_value = name.get_text().strip(), password.get_text()
            password.set_text("")
            d.destroy()
            if response_id != Gtk.ResponseType.OK:
                return
            try:
                secret_name = validate_secret_name(secret_name)
                secret_value = validate_secret_value(secret_value)
            except Exception as exc:
                self._toast(str(exc)); return

            def store() -> str:
                self.secret_vault.store(secret_name, secret_value)
                return secret_name

            def saved(result: object) -> None:
                try: audit("secret-store", "host-vault", "ok")
                except OSError: pass
                on_saved(str(result))

            self._work(store, saved)

        dialog.connect("response", response)
        dialog.present()

    def _ask(self, title: str, initial: str, callback: Callable[[str], None]) -> None:
        dialog = Gtk.Dialog(title=title, transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Continuar", Gtk.ResponseType.OK)
        inp = entry(initial)
        inp.set_margin_top(16); inp.set_margin_bottom(16)
        inp.set_margin_start(16); inp.set_margin_end(16)
        dialog.get_content_area().append(inp)
        def answer(d: Gtk.Dialog, response: int) -> None:
            value = inp.get_text().strip()
            d.destroy()
            if response == Gtk.ResponseType.OK: callback(value)
        dialog.connect("response", answer)
        dialog.present()

    def _confirm(self, title: str, detail: str, callback: Callable[[], None]) -> None:
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, text=title,
                                   secondary_text=detail, buttons=Gtk.ButtonsType.CANCEL)
        dialog.add_button("Confirmar", Gtk.ResponseType.OK)
        def answer(d: Gtk.MessageDialog, response: int) -> None:
            d.destroy()
            if response == Gtk.ResponseType.OK: callback()
        dialog.connect("response", answer)
        dialog.present()

    def _review_change(self, name: str, action: str,
                       preview: Callable[[dict], diff.ChangePreview],
                       change: Callable[[], None], done: Callable[[], None] | None = None) -> None:
        def show(effective: object) -> None:
            try:
                result = preview(effective)
            except Exception as exc:
                self._error_dialog(exc)
                return
            detail = result.text()
            if action in PROTECTED_ACTIONS and load_auto_snapshot():
                detail += "\n\nAntes da mudança, será criado um snapshot de proteção. Se ele falhar, a mudança não será aplicada."
            dialog = Gtk.Dialog(title=f"Revisar alteração · {name}", transient_for=self, modal=True)
            dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
            dialog.add_button("Aplicar alterações", Gtk.ResponseType.OK)
            dialog.set_default_size(690, 360)
            scroller = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
            content = Gtk.TextView(editable=False, cursor_visible=False, monospace=True,
                                   wrap_mode=Gtk.WrapMode.WORD_CHAR)
            content.set_margin_start(16); content.set_margin_end(16)
            content.set_margin_top(14); content.set_margin_bottom(14)
            content.get_buffer().set_text(detail)
            scroller.set_child(content)
            dialog.get_content_area().append(scroller)
            def answer(window: Gtk.Dialog, response: int) -> None:
                window.destroy()
                if response == Gtk.ResponseType.OK:
                    def check_reviewed_state() -> None:
                        current = preview(self.service.effective(name))
                        if current != result:
                            raise ValidationError("A configuração efetiva mudou desde a prévia; revise novamente")
                    self._audited(action, name, change, done, check_reviewed_state)
            dialog.connect("response", answer)
            dialog.present()
        self._work(lambda: self.service.effective(name), show)

    def _work(self, fn: Callable[[], object], done: Callable[[object], None] | None = None,
              on_error: Callable[[Exception], None] | None = None) -> None:
        def run() -> None:
            try:
                result = fn()
            except Exception as exc:
                GLib.idle_add(on_error or self._error_dialog, exc)
                return
            if done: GLib.idle_add(done, result)
        threading.Thread(target=run, daemon=True).start()

    def show_dashboard(self) -> None:
        if isinstance(self.service, LocalIncus) and self.service.confined_connection_pending:
            self.stack.set_visible_child_name("welcome")
            return
        self.stack.set_visible_child_name("dashboard")
        self._dashboard_generation += 1
        generation = self._dashboard_generation
        self._clear(self.dashboard)
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        top.append(label("Ambientes virtuais", "page-title"))
        top.append(button("Atualizar", self.show_dashboard))
        top.append(button("+ Novo ambiente", lambda: self.stack.set_visible_child_name("wizard"), "suggested-action"))
        self.dashboard.append(top)
        search = Gtk.SearchEntry(placeholder_text="Buscar VM por nome ou estado")
        self.dashboard.append(search)
        state = label("Carregando VMs…", "muted")
        self.dashboard.append(state)
        cards = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.dashboard.append(cards)
        loaded: list[VM] = []
        usage: dict[str, tuple[MetricsSnapshot, float | None]] = {}
        metrics_complete = False
        def draw() -> None:
            self._clear(cards)
            term = search.get_text().casefold().strip()
            matches = [vm for vm in loaded if term in vm.name.casefold() or term in vm.status.casefold()]
            if not matches:
                cards.append(label("Nenhuma VM corresponde à busca." if loaded else "Nenhuma VM encontrada. Crie um ambiente ou verifique o Incus em Diagnóstico do Host.", "muted"))
            for vm in matches: self._vm_card(vm, cards, usage.get(vm.name), metrics_complete)
        search.connect("search-changed", lambda *_: draw())
        def render(vms: object) -> None:
            if generation != self._dashboard_generation or state.get_parent() != self.dashboard: return
            self.dashboard.remove(state)
            loaded.extend(vms)
            draw()
            running = [vm for vm in loaded if vm.status == "Running"]
            if running:
                self._work(lambda: self._sample_dashboard(running), render_usage)
        def failed(exc: Exception) -> None:
            if generation != self._dashboard_generation or state.get_parent() != self.dashboard: return
            state.set_text(f"Não foi possível listar VMs: {exc}")
            state.add_css_class("error")
        def render_usage(result: object) -> None:
            nonlocal metrics_complete
            if generation != self._dashboard_generation: return
            usage.update(result)
            metrics_complete = True
            draw()
        self._work(self.service.list_vms, render, failed)

    def _sample_dashboard(self, running: list[VM]) -> dict[str, tuple[MetricsSnapshot, float | None]]:
        before: dict[str, tuple[MetricsSnapshot, float]] = {}
        for vm in running:
            try: before[vm.name] = (self.service.metrics(vm.name), time.monotonic())
            except IncusError: pass
        time.sleep(1.2)
        result: dict[str, tuple[MetricsSnapshot, float | None]] = {}
        for vm in running:
            try:
                after = self.service.metrics(vm.name)
                at = time.monotonic()
            except IncusError:
                continue
            first = before.get(vm.name)
            if vm.cpu.isdigit():
                allocated = int(vm.cpu)
            else:
                try: allocated = len(parse_cpu_set(vm.cpu))
                except ValidationError: allocated = None
            percent = cpu_percent_between(first[0], after, at - first[1], allocated) if first else None
            result[vm.name] = (after, percent)
        return result

    def _vm_card(self, vm: VM, parent: Gtk.Box,
                 usage: tuple[MetricsSnapshot, float | None] | None = None,
                 metrics_complete: bool = False) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.add_css_class("card")
        card.append(label(f"{vm.name}    •    {vm.status}", "section-title"))
        card.append(label(f"{vm.os}  ·  {vm.cpu} CPU  ·  {vm.memory} RAM  ·  {vm.disk} disco  ·  IP {vm.ip}"))
        card.append(label(f"Perfil: {vm.security_profile}  ·  Rede: {vm.network_policy}", "muted"))
        if vm.lifecycle_disposition != "persistent":
            lifecycle = {"manual-delete": "descartável · excluir manualmente",
                         "delete-on-close": "descartável · excluir ao fechar",
                         "restore-initial-on-close": "descartável · restaurar inicial ao fechar",
                         "persist-workspace": "restaurar sistema ao fechar · manter /workspace"}.get(
                             vm.lifecycle_disposition, "ciclo de vida desconhecido")
            card.append(label("Ciclo de vida: " + lifecycle,
                              "risk" if vm.lifecycle_disposition in {"delete-on-close", "restore-initial-on-close", "persist-workspace"} else "muted"))
        card.append(label(f"Mounts: {vm.mounts}  ·  Discos de dados: {vm.data_volumes}  ·  Snapshots: {vm.snapshots}", "muted"))
        if vm.copy_state == "pending":
            card.append(label("Cópias únicas pendentes · arquivos ainda não foram colocados no disco da VM", "risk"))
        elif vm.copy_state == "done":
            card.append(label("Cópias únicas concluídas · sem vínculo contínuo com o host", "muted"))
        if vm.status == "Running":
            if usage:
                snapshot, cpu_percent = usage
                cpu = f"{cpu_percent:.1f}%" if cpu_percent is not None else "indisponível"
                def size(value: int | None) -> str:
                    return f"{value / 1024**3:.2f} GiB" if value is not None else "indisponível"
                uptime = (f"{snapshot.uptime_seconds // 3600} h {(snapshot.uptime_seconds % 3600) // 60} min"
                          if snapshot.uptime_seconds is not None else "indisponível")
                card.append(label(f"Uso atual · CPU {cpu} · RAM {size(snapshot.memory_bytes)} / {size(snapshot.memory_total_bytes)}"
                                  f" · disco {size(snapshot.disk_bytes)} / {size(snapshot.disk_total_bytes)} · uptime {uptime}", "muted"))
            else:
                card.append(label("Uso atual: indisponível" if metrics_complete else "Amostrando uso atual…", "muted"))
        else:
            card.append(label("Uso atual: VM parada", "muted"))
        actions = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE,
                              max_children_per_line=5, row_spacing=6, column_spacing=6)
        for text, action in [("Iniciar", "start"), ("Parar", "stop"), ("Reiniciar", "restart")]:
            actions.append(button(text, lambda a=action, pending=(vm.copy_state == "pending"):
                                  self._state(vm.name, a, pending)))
        if vm.status == "Running" and vm.copy_state == "pending":
            actions.append(button("Aplicar cópias pendentes", lambda: self._apply_copies(vm.name)))
        if vm.status == "Running":
            actions.append(button("Forçar parada", lambda: self._confirm(
                "Forçar parada da VM?", "A VM será interrompida imediatamente. Dados não gravados dentro dela podem ser perdidos.",
                lambda: self._state(vm.name, "force-stop")), "destructive-action"))
        actions.append(button("Permissões", lambda: self.show_effective(vm.name)))
        actions.append(button("CPU/RAM", lambda: self._resources_dialog(vm)))
        pin_button = button("Fixar CPUs do host…", lambda: self._cpu_pin_dialog(vm))
        pin_button.set_sensitive(vm.status == "Stopped")
        if vm.status != "Stopped":
            pin_button.set_tooltip_text("Desligue a VM antes de fixar CPUs lógicas do host")
        actions.append(pin_button)
        disk_button = button("Aumentar disco…", lambda: self._disk_grow_dialog(vm))
        disk_supported = vm.disk.endswith("GiB") and vm.disk[:-3].isdigit() and int(vm.disk[:-3]) < 2048
        disk_button.set_sensitive(vm.status == "Stopped" and disk_supported)
        if vm.status != "Stopped":
            disk_button.set_tooltip_text("Desligue a VM antes de aumentar o disco")
        elif not disk_supported:
            disk_button.set_tooltip_text("Requer disco raiz local com tamanho inteiro em GiB, abaixo de 2048 GiB")
        actions.append(disk_button)
        actions.append(button("Métricas", lambda: self.show_metrics(vm)))
        integrated = button("Abrir terminal", lambda: self._open_integrated_terminal(vm.name))
        integrated.set_sensitive(not self.mock and vm.status == "Running")
        if vm.status != "Running":
            integrated.set_tooltip_text("Inicie a VM para abrir um terminal integrado")
        elif self.mock:
            integrated.set_tooltip_text("O modo mock não abre sessões reais no guest")
        actions.append(integrated)
        actions.append(button("Terminal externo", lambda: self._terminal(vm.name)))
        console = button("Console VGA", lambda: self._console(vm.name))
        console_ready = bool(shutil.which("remote-viewer") or shutil.which("spicy"))
        console.set_sensitive(not self.mock and console_ready and vm.status == "Running")
        if not console_ready:
            console.set_tooltip_text("Requer remote-viewer (virt-viewer) ou spicy, além de uma VM em execução")
        actions.append(console)
        actions.append(button("Snapshot", lambda: self._ask("Nome do snapshot", "snapshot-1", lambda s: self._snapshot(vm.name, s))))
        actions.append(button("Snapshots…", lambda: self.show_effective(vm.name)))
        actions.append(button("Clonar", lambda: self._ask("Nome da cópia", vm.name + "-copy", lambda s: self._clone(vm.name, s))))
        actions.append(button("Exportar YAML", lambda: self._export_vm(vm.name)))
        actions.append(button("Exportar versão", lambda: self._export_vm_versioned(vm.name)))
        backup = button("Backup completo", lambda: self._ask(
            "Arquivo de backup .tar.gz", str(Path.home() / f"{vm.name}.tar.gz"),
            lambda path: self._backup_prompt(vm.name, path, data_volumes=vm.data_volumes)))
        backup.set_sensitive(not self.mock)
        if self.mock: backup.set_tooltip_text("Backup completo exige uma VM Incus real")
        actions.append(backup)
        if vm.lifecycle_disposition == "persist-workspace":
            workspace_backup = button("Exportar /workspace", lambda: self._ask(
                "Arquivo de exportação .tar.gz", str(Path.home() / f"{vm.name}-workspace.tar.gz"),
                lambda path: self._workspace_backup_prompt(vm.name, path)))
            workspace_backup.set_sensitive(not self.mock)
            if self.mock: workspace_backup.set_tooltip_text("Exportação de /workspace exige uma VM Incus real")
            actions.append(workspace_backup)
        actions.append(button("Excluir", lambda: self._delete_prompt(
            vm.name, workspace=vm.lifecycle_disposition == "persist-workspace",
            data_volumes=vm.data_volumes), "destructive-action"))
        card.append(actions)
        parent.append(card)

    def _close_requested(self, *_args) -> bool:
        if self._allow_close or self.mock or not isinstance(self.service, LocalIncus):
            return False
        if self.service.confined_connection_pending:
            return False
        if self._close_scan_pending:
            return True
        self._close_scan_pending = True
        self._work(self._disposable_close_targets, self._review_close_targets,
                   self._close_scan_failed)
        return True

    def _disposable_close_targets(self) -> list[tuple[str, str, str]]:
        candidates: list[tuple[str, str, str]] = []
        for vm in self.service.list_vms():
            disposition = vm.lifecycle_disposition
            if disposition not in {"delete-on-close", "restore-initial-on-close", "persist-workspace"}:
                continue
            try:
                manifest = load_instance_manifest(vm.name)
                verified = self.service.verify_managed_lifecycle(
                    vm.name, disposition, manifest.pool, manifest.workspaceSizeGiB)
            except (OSError, ValidationError, IncusError):
                continue
            if (manifest.name != vm.name or manifest.lifecycleDisposition != disposition or
                    not verified):
                continue
            candidates.append((vm.name, vm.status, disposition))
        return candidates

    def _review_close_targets(self, targets: list[tuple[str, str, str]]) -> None:
        if not targets:
            self._allow_close = True
            self.close()
            return
        descriptions = {"delete-on-close": "excluir VM e snapshots",
                        "restore-initial-on-close": "restaurar snapshot inicial",
                        "persist-workspace": "restaurar sistema · manter volume /workspace"}
        lines = [f"{name} · {status} · {descriptions[disposition]}"
                 for name, status, disposition in targets]
        dialog = Gtk.MessageDialog(transient_for=self, modal=True,
                                  text="Há ambientes com ação de ciclo de vida ao fechar",
                                  secondary_text=("Aplicar excluirá VMs marcadas para exclusão ou restaurará o sistema no snapshot inicial. "
                                                  "A restauração descarta mudanças no disco da VM; ambientes configurados para manter /workspace conservam esse volume. "
                                                  "VMs em execução serão paradas. Revise a lista:\n\n" +
                                                  "\n".join(lines)),
                                  buttons=Gtk.ButtonsType.NONE)
        dialog.add_button("Continuar usando", Gtk.ResponseType.CANCEL)
        dialog.add_button("Fechar sem aplicar", Gtk.ResponseType.CLOSE)
        dialog.add_button("Aplicar e fechar", Gtk.ResponseType.APPLY)
        dialog.connect("response", lambda window, response:
                       self._close_response(window, response, targets))
        dialog.present()

    def _close_response(self, dialog: Gtk.MessageDialog, response: int,
                        targets: list[tuple[str, str, str]]) -> None:
        dialog.destroy()
        if response == Gtk.ResponseType.CANCEL:
            self._close_scan_pending = False
        elif response == Gtk.ResponseType.CLOSE:
            for name, _, _ in targets:
                try: audit("disposable-retain", name, "retida", source="close-dialog")
                except OSError: pass
            self._allow_close = True
            self.close()
        elif response == Gtk.ResponseType.APPLY:
            self._work(lambda: self._apply_close_lifecycle(targets),
                       self._finish_disposable_close, self._close_delete_failed)

    def _verify_close_target(self, name: str, disposition: str) -> None:
        vm = next((item for item in self.service.list_vms() if item.name == name), None)
        if vm is None or vm.lifecycle_disposition != disposition:
            raise IncusError(f"{name}: o ciclo de vida mudou; nenhuma ação aplicada")
        manifest = load_instance_manifest(name)
        if (manifest.name != name or manifest.lifecycleDisposition != disposition or
                not self.service.verify_managed_lifecycle(
                    name, disposition, manifest.pool, manifest.workspaceSizeGiB)):
            raise IncusError(f"{name}: propriedade ou ciclo de vida não pôde ser confirmado")
        if disposition in {"restore-initial-on-close", "persist-workspace"} and INITIAL_SNAPSHOT not in self.service.snapshots(name):
            raise IncusError(f"{name}: snapshot inicial ausente; nada foi restaurado")

    def _apply_close_lifecycle(self, targets: list[tuple[str, str, str]]) -> tuple[list[str], list[str]]:
        applied: list[str] = []
        issues: list[str] = []
        for name, _status, disposition in targets:
            operation_ok = True
            try:
                self._verify_close_target(name, disposition)
                if disposition in {"restore-initial-on-close", "persist-workspace"}:
                    current = next(item for item in self.service.list_vms() if item.name == name)
                    if current.status == "Running":
                        self.service.change_state(name, "stop")
                    self.service.restore_snapshot(name, INITIAL_SNAPSHOT)
                elif disposition == "delete-on-close":
                    self.service.delete(name)
                else:
                    raise IncusError(f"{name}: ciclo de vida ao fechar desconhecido")
            except Exception as exc:
                if disposition in {"restore-initial-on-close", "persist-workspace"}:
                    issues.append(f"{name}: {exc}")
                    break
                try:
                    still_exists = any(vm.name == name for vm in self.service.list_vms())
                except Exception:
                    still_exists = True
                if still_exists:
                    issues.append(f"{name}: {exc}")
                    break
                issues.append(f"{name}: VM removida; limpeza Incus precisa de revisão ({exc})")
                operation_ok = False
            applied.append(name)
            if disposition == "delete-on-close":
                try:
                    remove_instance_manifest(name)
                except OSError as exc:
                    issues.append(f"{name}: manifesto local não removido ({exc})")
                    operation_ok = False
            try:
                action = "delete" if disposition == "delete-on-close" else "snapshot-restore"
                audit(action, name, "ok" if operation_ok else "erro", source="auto-close")
            except OSError:
                issues.append(f"{name}: falha ao registrar auditoria")
        return applied, issues

    def _finish_disposable_close(self, result: object) -> None:
        applied, issues = result
        if applied:
            GLib.idle_add(self._toast, "Ciclo de vida aplicado: " + ", ".join(applied))
        if issues:
            self._close_delete_failed(RuntimeError("\n".join(issues)))
            return
        self._allow_close = True
        self.close()

    def _close_scan_failed(self, exc: Exception) -> None:
        self._close_scan_pending = False
        self._error_dialog(exc)

    def _close_delete_failed(self, exc: Exception) -> None:
        self._close_scan_pending = False
        self._error_dialog(exc)

    def _audited(self, action: str, name: str, fn: Callable[[], None],
                 done: Callable[[], None] | None = None,
                 precheck: Callable[[], None] | None = None) -> None:
        def run() -> None:
            try:
                if precheck is not None:
                    precheck()
                if action in PROTECTED_ACTIONS and load_auto_snapshot():
                    snapshot = protection_name(action)
                    try:
                        self.service.snapshot(name, snapshot)
                    except Exception:
                        try: audit("snapshot", name, "erro", source="auto")
                        except OSError: pass
                        raise
                    try: audit("snapshot", name, "ok", source="auto")
                    except OSError: pass
                    GLib.idle_add(self._toast, f"Snapshot de proteção criado: {snapshot}")
                fn()
            except Exception:
                try: audit(action, name, "erro")
                except OSError: pass
                raise
            try: audit(action, name, "ok")
            except OSError as exc:
                GLib.idle_add(self._toast, f"Operação concluída; auditoria local falhou: {exc}")
        self._work(run, lambda *_: (done or self.show_dashboard)())

    def _state(self, name: str, action: str, copy_pending: bool = False) -> None:
        if action == "start" and copy_pending:
            self._audited(action, name, lambda: self.service.change_state(name, action),
                          lambda: (self.show_dashboard(), self._apply_copies(name)))
        else:
            self._audited(action, name, lambda: self.service.change_state(name, action))

    def _apply_copies(self, name: str) -> None:
        status = label("Cópia única: aguardando agente Incus…", "risk")
        page = self.details if self.stack.get_visible_child_name() == "details" else self.dashboard
        page.append(status)
        def progress(message: str) -> None:
            GLib.idle_add(status.set_text, "Cópia única: " + message)
        self._audited("copy-files", name, lambda: self.service.apply_copies(name, progress),
                      lambda: (self._toast("Cópias únicas concluídas no disco da VM"), self.show_dashboard()))

    def _snapshot(self, name: str, snapshot: str) -> None:
        self._audited("snapshot", name, lambda: self.service.snapshot(name, snapshot))

    def _clone(self, name: str, target: str) -> None:
        def clone() -> None:
            self.service.clone(name, target)
            try:
                original = load_instance_manifest(name)
                data = original.to_dict(); data["name"] = target
                if original.lifecycleDisposition != "persist-workspace":
                    data.pop("lifecycle", None)
                save_instance_manifest(Manifest.parse(data, check_copy_sources=False))
            except (ValidationError, OSError):
                pass  # Incus clone succeeded; its effective state is still available.
        self._audited("clone", name, clone)

    def _delete_prompt(self, name: str, workspace: bool = False,
                       data_volumes: int = 0) -> None:
        consequences = [" Discos raiz e snapshots da VM serão removidos."]
        if workspace:
            consequences.append(" O volume separado /workspace e seus dados também serão apagados.")
        if data_volumes:
            consequences.append(f" {data_volumes} disco(s) de dados adicional(is) e todo o conteúdo serão apagados.")
        consequence = "".join(consequences)
        self._ask("Confirme digitando o nome da VM", "", lambda value:
                  self._confirm("Excluir VM definitivamente?", f"VM: {name}.{consequence}",
                                lambda: self._audited("delete", name, lambda: (self.service.delete(name), remove_instance_manifest(name))))
                  if value == name else self._toast("Nome não coincide; exclusão cancelada"))

    def _export_vm(self, name: str) -> None:
        try:
            manifest = load_instance_manifest(name)
        except Exception as exc:
            self._toast(f"{exc}. Para VMs externas, use Permissões efetivas para inspecionar o estado Incus.")
            return
        self._confirm("Exportar manifesto salvo?", "O manifesto registra a criação original. Alterações feitas fora do IsolateVM podem não aparecer nele. Verifique Permissões efetivas antes de reutilizar.",
                      lambda: self._ask("Salvar YAML em", str(Path.home() / f"{name}.yaml"),
                                        lambda path: self._export_to(manifest, path)))

    def _export_vm_versioned(self, name: str) -> None:
        try:
            manifest = load_instance_manifest(name)
        except Exception as exc:
            self._toast(f"{exc}. Consulte Permissões efetivas para inspecionar o estado Incus.")
            return
        self._confirm("Exportar nova versão do manifesto?",
                      f"Será criado {name}-vNNNN.yaml em {Path.home()}. O arquivo registra a configuração original; alterações externas no Incus podem não estar nele. Nenhuma versão anterior será sobrescrita.",
                      lambda: self._export_versioned(manifest))

    def _export_versioned(self, manifest: Manifest) -> None:
        def run() -> Path:
            path = export_manifest_versioned(manifest, Path.home())
            audit("export", manifest.name, "ok")
            return path
        self._work(run, lambda path: self._toast(f"Nova versão salva em {path}"))

    def _terminal(self, name: str) -> None:
        try:
            self._open_terminal(self.service.terminal_argv(name))
        except Exception as exc: self._toast(str(exc))

    def _open_terminal(self, argv: list[str]) -> None:
        if isinstance(self.service, LocalIncus):
            env = _local_gui_client_environment(self.service)
        else:
            env = os.environ.copy()
        subprocess.Popen(["/usr/bin/xdg-terminal-exec", "--", *argv], close_fds=True, env=env)

    def _guest_login(self, name: str) -> None:
        def open_prompt() -> None:
            try: self._open_terminal(self.service.guest_login_argv(name))
            except Exception as exc: self._toast(str(exc))
        self._confirm("Configurar login gráfico?",
                      "Será aberto um terminal para definir a senha do usuário ubuntu dentro da VM. A senha é digitada diretamente no guest; o IsolateVM não a guarda.",
                      open_prompt)

    def _console(self, name: str) -> None:
        try:
            argv = self.service.console_argv(name)
            if isinstance(self.service, LocalIncus):
                env = _local_gui_client_environment(self.service)
            else:
                env = os.environ.copy()
            def run() -> None:
                result = subprocess.run(argv, env=env, capture_output=True, text=True)
                if result.returncode:
                    raise IncusError("Não foi possível abrir a console VGA", result.stderr.strip()[:600])
            self._work(run)
        except Exception as exc: self._toast(str(exc))

    def _backup_prompt(self, name: str, destination: str, data_volumes: int = 0) -> None:
        target = Path(destination)
        separate_workspace = ""
        try:
            if load_instance_manifest(name).lifecycleDisposition == "persist-workspace":
                separate_workspace = " O volume persistente /workspace é separado e não entra neste backup; exporte-o pela ação própria."
        except (OSError, ValidationError):
            pass
        separate_data = (f" {data_volumes} disco(s) de dados customizado(s) também ficam fora; exporte cada um pela aba Armazenamento."
                         if data_volumes else "")
        self._confirm("Exportar backup completo?",
                      f"VM: {name}\nArquivo novo: {target}\nInclui o disco e os snapshots da VM. "
                      "Diretórios do host montados na VM não integram o backup." + separate_workspace + separate_data +
                      " Para maior consistência, pare a VM antes. A exportação pode demorar e ocupar muito espaço.",
                      lambda: self._audited("backup-full", name,
                                            lambda: self.service.export_full(name, target),
                                            lambda: self._toast(f"Backup completo salvo em {target}")))

    def _workspace_backup_prompt(self, name: str, destination: str) -> None:
        target = Path(destination)
        self._confirm("Exportar dados de /workspace?",
                      f"VM: {name}\nArquivo novo: {target}\nSerá exportado o volume customizado separado. Essa exportação não é combinada ao backup da VM; pare a VM para maior consistência.",
                      lambda: self._audited("backup-workspace", name,
                                            lambda: self.service.export_workspace(name, target),
                                            lambda: self._toast(f"Exportação de /workspace salva em {target}")))

    def _resources_dialog(self, vm: VM) -> None:
        dialog = Gtk.Dialog(title=f"Hardware · {vm.name}", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Revisar", Gtk.ResponseType.OK)
        area = dialog.get_content_area()
        area.set_spacing(10); area.set_margin_start(16); area.set_margin_end(16)
        area.set_margin_top(12); area.set_margin_bottom(12)
        cpu = Gtk.SpinButton.new_with_range(1, 64, 1)
        if vm.cpu.isdigit() and 1 <= int(vm.cpu) <= 64:
            current_cpu_count = int(vm.cpu)
        else:
            try: current_cpu_count = len(parse_cpu_set(vm.cpu))
            except (ValidationError, CPUSelectionError): current_cpu_count = 2
        cpu.set_value(current_cpu_count if 1 <= current_cpu_count <= 64 else 2)
        memory = Gtk.SpinButton.new_with_range(512, 262144, 512)
        digits = "".join(x for x in vm.memory if x.isdigit())
        memory.set_value(int(digits) if digits and "MiB" in vm.memory else 4096)
        area.append(row(f"CPU atual: {vm.cpu}", cpu))
        area.append(row(f"RAM atual: {vm.memory}", memory))
        area.append(label("Este editor define a quantidade de vCPUs. Pinning de threads lógicas fica em “Fixar CPUs do host”. O Incus reserva limites de CPU por percentual e prioridade para containers, não VMs.", "muted"))
        def selected(d: Gtk.Dialog, response: int) -> None:
            new_cpu, new_memory = cpu.get_value_as_int(), memory.get_value_as_int()
            d.destroy()
            if response != Gtk.ResponseType.OK: return
            def apply_resources() -> None:
                self.service.set_resources(vm.name, new_cpu, new_memory)
                try:
                    manifest = load_instance_manifest(vm.name)
                    data = manifest.to_dict()
                    data["resources"]["cpu"] = new_cpu
                    data["resources"]["memoryMiB"] = new_memory
                    data["metadata"].pop("cpuPinning", None)
                    save_instance_manifest(Manifest.parse(data, check_copy_sources=False))
                except (OSError, ValidationError):
                    GLib.idle_add(self._toast, "Recursos aplicados; manifesto local indisponível para sincronização")
            self._review_change(vm.name, "resources",
                                lambda effective: diff.resources(effective, new_cpu, new_memory, vm.name),
                                apply_resources)
        dialog.connect("response", selected)
        dialog.present()

    def _cpu_pin_dialog(self, vm: VM) -> None:
        if vm.status != "Stopped":
            self._error_dialog(ValidationError("Desligue a VM antes de fixar CPUs lógicas do host"))
            return
        dialog = Gtk.Dialog(title=f"Fixar CPUs do host · {vm.name}", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        review = dialog.add_button("Revisar", Gtk.ResponseType.OK)
        review.set_sensitive(False)
        area = dialog.get_content_area()
        area.set_spacing(10); area.set_margin_start(16); area.set_margin_end(16)
        area.set_margin_top(12); area.set_margin_bottom(12)
        status = label("Consultando IDs de CPU que o Incus anunciou…", "muted")
        area.append(status)
        selection = entry()
        selection.set_placeholder_text("Ex.: 0-3,6")
        if not vm.cpu.isdigit():
            selection.set_text(vm.cpu)
        area.append(row("CPUs lógicas do host", selection))
        area.append(label("Use IDs ou intervalos separados por vírgula. A quantidade de IDs define o número de vCPUs. Pinning exige VM parada e não reserva as CPUs exclusivamente: outras VMs e processos do host ainda podem usá-las. A topologia física do host pode levar o Incus a recusar combinações incompatíveis.", "risk"))
        available: list[int] = []
        def loaded(values: object) -> None:
            available.extend(int(value) for value in values)
            status.set_text("IDs online: " + (", ".join(str(value) for value in available) if available else "nenhum"))
            if available:
                review.set_sensitive(True)
            else:
                status.add_css_class("error")
        self._work(self.service.host_cpu_ids, loaded)
        def response(window: Gtk.Dialog, response_id: int) -> None:
            raw = selection.get_text().strip()
            window.destroy()
            if response_id != Gtk.ResponseType.OK:
                return
            try:
                normalized = format_cpu_set(parse_cpu_set(raw))
                selected = set(parse_cpu_set(raw))
                if not selected.issubset(set(available)):
                    raise ValidationError("Selecione somente IDs que o Incus informou como online")
            except (ValidationError, CPUSelectionError) as exc:
                self._toast(str(exc))
                return
            def pin_and_sync() -> None:
                self.service.pin_cpus(vm.name, normalized)
                try:
                    manifest = load_instance_manifest(vm.name)
                    data = manifest.to_dict()
                    data["resources"]["cpu"] = len(selected)
                    data["metadata"]["cpuPinning"] = normalized
                    save_instance_manifest(Manifest.parse(data, check_copy_sources=False))
                except (OSError, ValidationError):
                    GLib.idle_add(self._toast, "Pinning aplicado; manifesto local indisponível para sincronização")
            self._review_change(vm.name, "cpu-pin",
                                lambda current: diff.cpu_pin(current, normalized, vm.name),
                                pin_and_sync,
                                self.show_dashboard)
        dialog.connect("response", response)
        dialog.present()

    def _disk_grow_dialog(self, vm: VM) -> None:
        raw_size = vm.disk[:-3] if vm.disk.endswith("GiB") else ""
        if vm.status != "Stopped" or not raw_size.isdigit():
            self._error_dialog(ValidationError("Aumentar o disco requer VM parada e tamanho raiz local em GiB inteiros"))
            return
        old_size = int(raw_size)
        if old_size >= 2048:
            self._error_dialog(ValidationError("O disco já atingiu o limite atual de 2048 GiB"))
            return
        dialog = Gtk.Dialog(title=f"Aumentar disco raiz · {vm.name}", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Revisar", Gtk.ResponseType.OK)
        area = dialog.get_content_area()
        area.set_spacing(10); area.set_margin_start(16); area.set_margin_end(16)
        area.set_margin_top(12); area.set_margin_bottom(12)
        size = Gtk.SpinButton.new_with_range(old_size + 1, 2048, 1)
        size.set_value(min(old_size + 10, 2048))
        area.append(row(f"Tamanho atual: {old_size} GiB · novo tamanho", size))
        area.append(label("Esta operação somente aumenta o disco raiz e não pode ser desfeita por redução. A VM precisa estar parada; depois do próximo boot, a partição ou o sistema de arquivos do guest pode exigir expansão.", "risk"))
        def selected(window: Gtk.Dialog, response: int) -> None:
            new_size = size.get_value_as_int()
            window.destroy()
            if response != Gtk.ResponseType.OK:
                return
            def grow() -> None:
                self.service.resize_root_disk(vm.name, new_size)
                try:
                    manifest = load_instance_manifest(vm.name)
                    data = manifest.to_dict()
                    data["resources"]["diskGiB"] = new_size
                    save_instance_manifest(Manifest.parse(data, check_copy_sources=False))
                except (OSError, ValidationError):
                    GLib.idle_add(self._toast, "Disco aumentado; manifesto local indisponível para sincronização")
            self._review_change(vm.name, "disk-grow",
                                lambda effective: diff.root_disk_grow(effective, new_size, vm.name),
                                grow, self.show_dashboard)
        dialog.connect("response", selected)
        dialog.present()

    def show_diagnostics(self) -> None:
        self._clear(self.diagnostics)
        self.diagnostics.append(label("Diagnóstico do Host", "page-title"))
        self.diagnostics.append(label("Verificações locais. Nenhuma alteração no sistema será feita.", "muted"))
        def render(rows: object) -> None:
            for status, title, detail in rows:
                icon = {"ok": "✓", "warn": "⚠", "error": "✕"}[status]
                self.diagnostics.append(label(f"{icon}  {title}: {detail}", status if status != "warn" else "risk"))
        self._work(diagnose, render)

    def show_history(self) -> None:
        self._clear(self.history_page)
        self.history_page.append(label("Histórico", "page-title"))
        for event in history():
            self.history_page.append(label(f"{event['time']}  {event['vm']}  ·  {event['action']}  ·  {event['result']}  ·  origem: {event.get('source', 'desconhecida')}"))

    def _build_settings(self) -> None:
        self.settings_page.append(label("Configurações", "page-title"))
        self.settings_page.append(label("Tema da interface", "section-title"))
        theme = combo(["Sistema", "Claro", "Escuro"], {"system": 0, "light": 1, "dark": 2}[load_theme()])
        self.settings_page.append(theme)
        def changed(widget: Gtk.ComboBoxText) -> None:
            selected = ["system", "light", "dark"][widget.get_active()]
            save_theme(selected)
            self._apply_theme(selected)
        theme.connect("changed", changed)
        self._apply_theme(load_theme())
        self.settings_page.append(label("Proteção antes de alterações", "section-title"))
        auto_snapshot = Gtk.Switch()
        auto_snapshot.set_active(load_auto_snapshot())
        self.settings_page.append(row("Criar snapshot automaticamente antes de alterar uma VM", auto_snapshot))
        self.settings_page.append(label("Aplica-se a mounts, dispositivos, rede, CPU/RAM e restauração de snapshot. Se o snapshot falhar, a alteração não é aplicada. Ele usa o mesmo pool da VM, pode consumir espaço e não inclui arquivos do host compartilhados.", "muted"))
        auto_snapshot.connect("notify::active", lambda widget, *_: save_auto_snapshot(widget.get_active()))
        self.settings_page.append(label("Configuração Incus global, grupos e firewall são administrados fora do aplicativo.", "muted"))

    @staticmethod
    def _apply_theme(theme: str) -> None:
        modes = {"system": Adw.ColorScheme.DEFAULT,
                 "light": Adw.ColorScheme.FORCE_LIGHT,
                 "dark": Adw.ColorScheme.FORCE_DARK}
        Adw.StyleManager.get_default().set_color_scheme(modes[theme])


class MockUnavailable:
    """Explicit disabled service when Incus is missing; never silently simulates real operations."""
    def _error(self, *_args, **_kwargs):
        raise IncusError("Incus não está instalado ou acessível. Use ISOLATEVM_MOCK=1 somente para testar a interface.")

    def list_vms(self): return []
    def __getattr__(self, _: str): return self._error


class IsolateApp(Gtk.Application):
    def __init__(self) -> None:
        super().__init__(application_id="org.isolatevm.IsolateVM", flags=Gio.ApplicationFlags.FLAGS_NONE)

    def do_activate(self) -> None:
        Adw.init()
        window = self.props.active_window or IsolateWindow(self)
        window.present()


def main() -> int:
    return IsolateApp().run([])
