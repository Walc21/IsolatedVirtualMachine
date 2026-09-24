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
from .model import Manifest, ValidationError
from .metrics import MetricsSnapshot, cpu_percent_between
from .storage import (audit, complete_onboarding, first_run, history, load_instance_manifest,
                      load_theme, remove_instance_manifest, save_instance_manifest, save_theme)


from .ui_widgets import CSS, label, button, row, entry, combo
from .ui_wizard import WizardMixin
from .ui_details import DetailsMixin
from .ui_metrics import MetricsMixin


class IsolateWindow(WizardMixin, DetailsMixin, MetricsMixin, Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application) -> None:
        super().__init__(application=app, title="IsolateVM")
        self.set_default_size(1100, 730)
        self.mock = os.environ.get("ISOLATEVM_MOCK") == "1"
        self.service: IncusService = MockIncus() if self.mock else self._live_service()
        self.current_manifest: Manifest | None = None
        self.selected_vm: VM | None = None
        self.wizard_step = 0
        self._metrics_generation = 0
        self._dashboard_generation = 0

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
        self.metrics_page = self._scroll_page("Monitoramento", "metrics")
        self.templates_page = self._scroll_page("Templates", "templates")
        self.history_page = self._scroll_page("Histórico", "history")
        self.settings_page = self._scroll_page("Configurações", "settings")
        self._build_settings()
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
            allocated = int(vm.cpu) if vm.cpu.isdigit() else None
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
        card.append(label(f"Mounts: {vm.mounts}  ·  Snapshots: {vm.snapshots}", "muted"))
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
            actions.append(button(text, lambda a=action: self._state(vm.name, a)))
        if vm.status == "Running":
            actions.append(button("Forçar parada", lambda: self._confirm(
                "Forçar parada da VM?", "A VM será interrompida imediatamente. Dados não gravados dentro dela podem ser perdidos.",
                lambda: self._state(vm.name, "force-stop")), "destructive-action"))
        actions.append(button("Permissões", lambda: self.show_effective(vm.name)))
        actions.append(button("CPU/RAM", lambda: self._resources_dialog(vm)))
        actions.append(button("Métricas", lambda: self.show_metrics(vm)))
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
        backup = button("Backup completo", lambda: self._ask(
            "Arquivo de backup .tar.gz", str(Path.home() / f"{vm.name}.tar.gz"),
            lambda path: self._backup_prompt(vm.name, path)))
        backup.set_sensitive(not self.mock)
        if self.mock: backup.set_tooltip_text("Backup completo exige uma VM Incus real")
        actions.append(backup)
        actions.append(button("Excluir", lambda: self._delete_prompt(vm.name), "destructive-action"))
        card.append(actions)
        parent.append(card)

    def _audited(self, action: str, name: str, fn: Callable[[], None],
                 done: Callable[[], None] | None = None) -> None:
        def run() -> None:
            try:
                fn()
            except Exception:
                try: audit(action, name, "erro")
                except OSError: pass
                raise
            try: audit(action, name, "ok")
            except OSError as exc:
                GLib.idle_add(self._toast, f"Operação concluída; auditoria local falhou: {exc}")
        self._work(run, lambda *_: (done or self.show_dashboard)())

    def _state(self, name: str, action: str) -> None:
        self._audited(action, name, lambda: self.service.change_state(name, action))

    def _snapshot(self, name: str, snapshot: str) -> None:
        self._audited("snapshot", name, lambda: self.service.snapshot(name, snapshot))

    def _clone(self, name: str, target: str) -> None:
        def clone() -> None:
            self.service.clone(name, target)
            try:
                original = load_instance_manifest(name)
                data = original.to_dict(); data["name"] = target
                save_instance_manifest(Manifest.parse(data))
            except (ValidationError, OSError):
                pass  # Incus clone succeeded; its effective state is still available.
        self._audited("clone", name, clone)

    def _delete_prompt(self, name: str) -> None:
        self._ask("Confirme digitando o nome da VM", "", lambda value:
                  self._confirm("Excluir VM definitivamente?", f"VM: {name}. Discos e snapshots serão removidos.",
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

    def _terminal(self, name: str) -> None:
        try:
            self._open_terminal(self.service.terminal_argv(name))
        except Exception as exc: self._toast(str(exc))

    def _open_terminal(self, argv: list[str]) -> None:
        env = os.environ.copy()
        if isinstance(self.service, LocalIncus):
            env["INCUS_CONF"] = str(self.service.client_config_dir)
            env.pop("INCUS_REMOTE", None)
            env.pop("INCUS_SOCKET", None)
            env.pop("INCUS_DIR", None)
            env.pop("INCUS_PROJECT", None)
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
            env = os.environ.copy()
            if isinstance(self.service, LocalIncus):
                env["INCUS_CONF"] = str(self.service.client_config_dir)
                env.pop("INCUS_REMOTE", None)
                env.pop("INCUS_SOCKET", None)
                env.pop("INCUS_DIR", None)
                env.pop("INCUS_PROJECT", None)
            def run() -> None:
                result = subprocess.run(argv, env=env, capture_output=True, text=True)
                if result.returncode:
                    raise IncusError("Não foi possível abrir a console VGA", result.stderr.strip()[:600])
            self._work(run)
        except Exception as exc: self._toast(str(exc))

    def _backup_prompt(self, name: str, destination: str) -> None:
        target = Path(destination)
        self._confirm("Exportar backup completo?",
                      f"VM: {name}\nArquivo novo: {target}\nInclui o disco e os snapshots da VM. "
                      "Diretórios do host montados na VM não integram o backup. Para maior consistência, pare a VM antes. A exportação pode demorar e ocupar muito espaço.",
                      lambda: self._audited("backup-full", name,
                                            lambda: self.service.export_full(name, target),
                                            lambda: self._toast(f"Backup completo salvo em {target}")))

    def _resources_dialog(self, vm: VM) -> None:
        dialog = Gtk.Dialog(title=f"Hardware · {vm.name}", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Revisar", Gtk.ResponseType.OK)
        area = dialog.get_content_area()
        area.set_spacing(10); area.set_margin_start(16); area.set_margin_end(16)
        area.set_margin_top(12); area.set_margin_bottom(12)
        cpu = Gtk.SpinButton.new_with_range(1, 64, 1)
        cpu.set_value(int(vm.cpu) if vm.cpu.isdigit() and 1 <= int(vm.cpu) <= 64 else 2)
        memory = Gtk.SpinButton.new_with_range(512, 262144, 512)
        digits = "".join(x for x in vm.memory if x.isdigit())
        memory.set_value(int(digits) if digits and "MiB" in vm.memory else 4096)
        area.append(row(f"CPU atual: {vm.cpu}", cpu))
        area.append(row(f"RAM atual: {vm.memory}", memory))
        def selected(d: Gtk.Dialog, response: int) -> None:
            new_cpu, new_memory = cpu.get_value_as_int(), memory.get_value_as_int()
            d.destroy()
            if response != Gtk.ResponseType.OK: return
            self._confirm("Aplicar alteração de hardware?",
                          f"CPU: {vm.cpu} → {new_cpu}\nRAM: {vm.memory} → {new_memory}MiB. A VM pode precisar reiniciar.",
                          lambda: self._audited("resources", vm.name,
                                                lambda: self.service.set_resources(vm.name, new_cpu, new_memory)))
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
            self.history_page.append(label(f"{event['time']}  {event['vm']}  ·  {event['action']}  ·  {event['result']}"))

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
