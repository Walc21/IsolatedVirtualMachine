"""Integrated guest terminal backed by an Incus exec PTY."""
from __future__ import annotations

import os
import signal

import gi
try:
    gi.require_version("Vte", "3.91")
    from gi.repository import Vte
except (ImportError, ValueError):  # Keep diagnostics and mock mode usable without VTE.
    Vte = None  # type: ignore[assignment]

from gi.repository import GLib, Gtk

from .incus import IncusError, LocalIncus
from .ui_widgets import button, label


class TerminalMixin:
    def _build_terminal_page(self) -> None:
        self.terminal_status = label("Abra uma VM em execução para iniciar uma sessão.", "muted")
        self.terminal_page.append(self.terminal_status)
        self.terminal_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8,
                                        vexpand=True)
        self.terminal_page.append(self.terminal_content)
        self.terminal_widget = None
        self.terminal_pid: int | None = None

    def _open_integrated_terminal(self, name: str) -> None:
        if self.mock:
            self.stack.set_visible_child_name("terminal")
            self.terminal_status.set_text("Terminal real indisponível no modo mock.")
            return
        if Vte is None:
            self._toast("Terminal integrado indisponível: instale gir1.2-vte-3.91.")
            return
        if not isinstance(self.service, LocalIncus):
            self._toast("Terminal integrado requer uma conexão local Incus autorizada.")
            return
        try:
            argv = self.service.terminal_argv(name)
            envv = [f"{key}={value}" for key, value in self.service.terminal_environment().items()]
        except Exception as exc:
            self._toast(str(exc))
            return

        self._stop_integrated_terminal()
        self._clear(self.terminal_content)
        self.stack.set_visible_child_name("terminal")
        self.terminal_status.set_text(
            f"{name} · shell como root dentro da VM · comandos executam no guest")
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.append(button("Encerrar sessão", self._stop_integrated_terminal))
        self.terminal_content.append(actions)
        terminal = Vte.Terminal()
        terminal.set_scrollback_lines(10000)
        terminal.set_scroll_on_keystroke(True)
        terminal.set_audible_bell(False)
        terminal.set_input_enabled(False)
        terminal.set_hexpand(True)
        terminal.set_vexpand(True)
        scroller = Gtk.ScrolledWindow(hexpand=True, vexpand=True)
        scroller.set_child(terminal)
        self.terminal_content.append(scroller)
        self.terminal_widget = terminal
        terminal.connect("child-exited", self._integrated_terminal_exited)

        def spawned(widget, pid, error, _data) -> None:
            if widget is not self.terminal_widget:
                if pid > 0:
                    try:
                        os.kill(int(pid), signal.SIGTERM)
                    except (ProcessLookupError, OSError):
                        pass
                return
            if error is not None:
                self.terminal_status.set_text(f"Não foi possível abrir a sessão Incus: {error.message}")
                self.terminal_widget = None
                return
            self.terminal_pid = int(pid)
            widget.watch_child(self.terminal_pid)
            widget.set_input_enabled(True)
            widget.grab_focus()

        try:
            terminal.spawn_async(
                Vte.PtyFlags.DEFAULT, None, argv, envv, GLib.SpawnFlags.DEFAULT, None,
                timeout=-1, cancellable=None, callback=spawned, user_data=None)
        except (GLib.Error, OSError, TypeError) as exc:
            self.terminal_status.set_text(f"Não foi possível iniciar o terminal: {exc}")
            self.terminal_widget = None

    def _integrated_terminal_exited(self, widget, status: int) -> None:
        if widget is not self.terminal_widget:
            return
        self.terminal_pid = None
        widget.set_input_enabled(False)
        self.terminal_status.set_text(f"Sessão Incus encerrada (status {status}).")

    def _stop_integrated_terminal(self) -> None:
        pid = self.terminal_pid
        self.terminal_pid = None
        widget = self.terminal_widget
        self.terminal_widget = None
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as exc:
                self._toast(f"Não foi possível encerrar o cliente Incus: {exc}")
        if widget is not None:
            widget.set_input_enabled(False)
        if hasattr(self, "terminal_status"):
            self.terminal_status.set_text("Sessão encerrada.")
