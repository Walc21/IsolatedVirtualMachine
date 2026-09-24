"""Creation wizard and template flow for IsolateVM."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk

from .model import Manifest, Mount, ValidationError
from .policy import assess
from .planning import CreationPlan, plan_creation
from .provision import cloud_config
from .software_catalog import CATALOG_GROUPS, CATALOG_PACKAGES, LANGUAGE_PRESETS
from .storage import audit, export_manifest, import_manifest, load_template, save_instance_manifest, save_template, templates
from .ui_widgets import label, button, row, entry, combo


@dataclass
class MountEditor:
    frame: Gtk.Frame
    host: Gtk.Entry
    guest: Gtk.Entry
    rw: Gtk.CheckButton


class WizardMixin:
    def _build_wizard(self) -> None:
        self._clear(self.wizard)
        self.wizard.append(label("Novo Ambiente", "page-title"))
        self.wizard.append(label("Criação declarativa. A VM nasce parada; você a inicia após revisar.", "muted"))
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
        self.ram_input = Gtk.SpinButton.new_with_range(512, 262144, 512); self.ram_input.set_value(4096)
        self.disk_input = Gtk.SpinButton.new_with_range(8, 2048, 1); self.disk_input.set_value(30)
        self.pool_input = entry("default")
        self.network_input = combo(["offline", "normal", "restricted"])
        self.bridge_input = entry("incusbr0")
        self.egress_input = entry("github.com:443, api.github.com:443")
        self.security_profile_input = combo(["maximum-isolation", "normal-development", "restricted-development", "custom"])
        self.mount_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.mount_empty_label = label("Nenhuma pasta do host compartilhada", "muted")
        self.mount_list.append(self.mount_empty_label)
        self.mount_rows: list[MountEditor] = []
        self.add_mount_button = button("+ Compartilhar pasta…", self._add_mount_row)
        self.apt_input = entry()
        self.pip_input = entry()
        self.npm_input = entry()
        self.cargo_input = entry()
        self.go_input = entry()
        self._original_apt_order: tuple[str, ...] = ()
        self.catalog_checks: dict[str, Gtk.CheckButton] = {}
        self.catalog_sections: list[Gtk.Expander] = []
        for title, items in CATALOG_GROUPS:
            section = Gtk.Expander(label=title)
            section.set_expanded(title == "Básico")
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            body.set_margin_start(12); body.set_margin_top(6); body.set_margin_bottom(6)
            for item in items:
                check = Gtk.CheckButton(label=f"{item.label} · {item.package}")
                if item.package in {"docker.io", "podman"}:
                    check.set_tooltip_text("Instala dentro da VM; recursos de contêiner podem exigir suporte adicional do guest")
                self.catalog_checks[item.package] = check
                body.append(check)
            section.set_child(body)
            self.catalog_sections.append(section)
        self.python_check = Gtk.CheckButton(label="Python (python3, python3-pip)")
        self.node_check = Gtk.CheckButton(label="Node.js (nodejs, npm)")
        self.rust_check = Gtk.CheckButton(label="Rust (rustc, cargo)")
        self.codex_check = Gtk.CheckButton(label="OpenAI Codex CLI na VM (npm, sem credenciais)")
        self.environment_view = Gtk.TextView()
        self.environment_view.set_monospace(True)
        self.environment_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.environment_view.set_size_request(-1, 120)
        self.save_template_check = Gtk.CheckButton(label="Salvar como template sem paths pessoais")
        self._render_step()

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
        elif self.wizard_step == 3:
            self.step_body.append(row("Disco (GiB)", self.disk_input))
            self.step_body.append(row("Pool Incus", self.pool_input))
        elif self.wizard_step == 4:
            self.step_body.append(row("Rede · offline por padrão", self.network_input))
            self.step_body.append(row("Bridge Incus (rede normal ou restrita)", self.bridge_input))
            self.step_body.append(row("Saída restrita (domínio, IP ou CIDR:porta; separados por vírgula)", self.egress_input))
            self.step_body.append(label("Rede restrita usa proxy HTTPS por VM, bloqueia DNS e tráfego direto. Domínios são resolvidos pelo proxy; UDP não é permitido.", "risk"))
        elif self.wizard_step == 5:
            self.step_body.append(label("Acessos ao Host", "section-title"))
            self.step_body.append(self.mount_list)
            self.step_body.append(self.add_mount_button)
            self.add_mount_button.set_sensitive(len(self.mount_rows) < 16)
            self.step_body.append(label("Pasta compartilhada permanece vinculada ao host. Nenhuma pasta é copiada automaticamente.", "muted"))
        elif self.wizard_step == 6:
            self.step_body.append(label("Selecione pacotes por categoria. Todos serão registrados como APT no manifesto.", "muted"))
            for section in self.catalog_sections:
                self.step_body.append(section)
            self.step_body.append(row("Outros pacotes APT (separados por vírgula)", self.apt_input))
            self.step_body.append(row("Pacotes Python no venv da VM (nome ou nome==versão)", self.pip_input))
            self.step_body.append(row("Pacotes npm globais na VM (nome ou nome@versão)", self.npm_input))
            self.step_body.append(row("Crates Cargo (crate@X.Y.Z)", self.cargo_input))
            self.step_body.append(row("Ferramentas Go (módulo/comando@vX.Y.Z)", self.go_input))
            self.step_body.append(label("Instalação via cloud-init no primeiro boot. No modo offline, downloads podem falhar.", "muted"))
            self.step_body.append(label("Cargo e Go exigem versão exata. Docker/Podman rodam no guest; disponibilidade de recursos de contêiner depende da VM. .NET, uv, rustup, bun, kubectl, Helm e Terraform ainda não têm seleção assistida.", "risk"))
        elif self.wizard_step == 7:
            for widget in (self.python_check, self.node_check, self.rust_check):
                self.step_body.append(widget)
            self.step_body.append(label("AI Coding", "section-title"))
            self.step_body.append(self.codex_check)
            self.step_body.append(label("Codex é instalado dentro da VM. Faça login apenas na primeira execução na VM; nenhuma autenticação do host é copiada.", "muted"))
        elif self.wizard_step == 8:
            self.step_body.append(label("Somente valores não secretos. Uma linha NOME=VALOR por variável.", "risk"))
            self.step_body.append(self.environment_view)
            self.step_body.append(label("Os valores serão incluídos no manifesto exportado, na configuração Incus e em /etc/environment da VM.", "muted"))
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
            self.step_body.append(label("Máximo isolamento: sem NIC, mounts, dispositivos repassados ou secrets. Desenvolvimento normal/custom: somente acessos escolhidos explicitamente.", "muted"))
            self.step_body.append(label("Desenvolvimento restrito indisponível: falta proxy de saída com allowlist e DNS controlado.", "risk"))
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
                    self.step_body.append(button("Exportar manifesto…", self._export_current))
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

    def _form_manifest(self) -> Manifest:
        requested_apt = [x.strip() for x in self.apt_input.get_text().split(",") if x.strip()]
        requested_apt.extend(package for package, check in self.catalog_checks.items() if check.get_active())
        if self.python_check.get_active(): requested_apt.extend(LANGUAGE_PRESETS["python"])
        if self.node_check.get_active(): requested_apt.extend(LANGUAGE_PRESETS["node"])
        if self.rust_check.get_active(): requested_apt.extend(LANGUAGE_PRESETS["rust"])
        requested_apt = list(dict.fromkeys(requested_apt))
        packages = [package for package in self._original_apt_order if package in requested_apt]
        packages.extend(package for package in requested_apt if package not in packages)
        pip_packages = [x.strip() for x in self.pip_input.get_text().split(",") if x.strip()]
        npm_packages = [x.strip() for x in self.npm_input.get_text().split(",") if x.strip()]
        cargo_packages = [x.strip() for x in self.cargo_input.get_text().split(",") if x.strip()]
        go_packages = [x.strip() for x in self.go_input.get_text().split(",") if x.strip()]
        if self.codex_check.get_active(): npm_packages.append("@openai/codex@latest")
        mounts = []
        for index, editor in enumerate(self.mount_rows, start=1):
            host = editor.host.get_text().strip()
            if not host:
                raise ValidationError(f"Pasta {index}: escolha um diretório do host ou remova a linha")
            mounts.append({"host": host, "guest": editor.guest.get_text().strip(),
                           "mode": "rw" if editor.rw.get_active() else "ro"})
        mode = self.network_input.get_active_text()
        egress = []
        if mode == "restricted":
            for value in self.egress_input.get_text().split(","):
                destination = value.strip()
                if not destination or destination.count(":") != 1:
                    raise ValidationError("Saída restrita: use destino:porta, separado por vírgula")
                target, port = destination.rsplit(":", 1)
                kind = "cidr" if "/" in target else ("ip" if target.replace(".", "").isdigit() else "domain")
                if not port.isdigit(): raise ValidationError("Saída restrita: porta inválida")
                egress.append({"kind": kind, "value": target, "port": int(port), "protocol": "tcp"})
        raw = {"schemaVersion": 1, "name": self.name_input.get_text().strip(),
               "os": {"distribution": "ubuntu", "release": self.release_input.get_active_text(),
                      **({"desktop": ("gnome", "kde", "xfce")[self.desktop_input.get_active()]}
                         if self.desktop_check.get_active() else {})},
               "resources": {"cpu": self.cpu_input.get_value_as_int(),
                             "memoryMiB": self.ram_input.get_value_as_int(),
                             "diskGiB": self.disk_input.get_value_as_int(), "pool": self.pool_input.get_text().strip()},
               "network": {"mode": mode, **({"bridge": self.bridge_input.get_text().strip()} if mode in {"normal", "restricted"} else {}),
                           **({"egress": egress} if egress else {})},
               "security": {"profile": "restricted-development" if mode == "restricted" else self.security_profile_input.get_active_text()},
               "mounts": mounts, "software": {"apt": packages, "pip": pip_packages, "npm": npm_packages,
                                              "cargo": cargo_packages, "go": go_packages},
               "environment": self._environment(),
               "metadata": {}}
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

    def _back(self) -> None:
        self.wizard_step -= 1; self._render_step()

    def _next(self) -> None:
        if self.wizard_step < 12:
            self.wizard_step += 1; self._render_step(); return
        manifest = self.current_manifest
        if not manifest: return
        self._confirm("Criar VM Incus?", "A imagem poderá ser baixada e um disco criado. Nenhuma configuração global do host será alterada.",
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
                        save_template(manifest.name, manifest); audit("template", manifest.name, "ok")
                except OSError as exc:
                    GLib.idle_add(self._toast, f"VM criada; registro local incompleto: {exc}")
            finally:
                GLib.idle_add(self.next_btn.set_sensitive, True)
        def done(_: object) -> None:
            self.next_btn.set_sensitive(True)
            self._toast(f"VM {manifest.name} criada e parada. Inicie pelo dashboard.")
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

    def _save_template(self, name: str, manifest: Manifest) -> None:
        try:
            path = save_template(name, manifest)
            audit("template", manifest.name, "ok")
            self._toast(f"Template salvo em {path}; mounts pessoais foram removidos.")
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
        self.templates_page.append(label("Templates locais excluem mounts e secrets. Importações passam pelo mesmo validador do wizard.", "muted"))
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
        self.disk_input.set_value(manifest.diskGiB); self.pool_input.set_text(manifest.pool)
        self.network_input.set_active({"offline": 0, "normal": 1, "restricted": 2}[manifest.networkMode])
        profiles = ["maximum-isolation", "normal-development", "restricted-development", "custom"]
        self.security_profile_input.set_active(profiles.index(manifest.securityProfile))
        self.bridge_input.set_text(manifest.bridge or "incusbr0")
        self.egress_input.set_text(", ".join(f"{rule.value}:{rule.port}" for rule in manifest.egress))
        self._original_apt_order = manifest.apt
        selected_apt = set(manifest.apt)
        for package, check in self.catalog_checks.items():
            check.set_active(package in selected_apt)
        selected_presets: set[str] = set()
        for key, check in (("python", self.python_check), ("node", self.node_check), ("rust", self.rust_check)):
            enabled = all(package in selected_apt for package in LANGUAGE_PRESETS[key])
            check.set_active(enabled)
            if enabled: selected_presets.update(LANGUAGE_PRESETS[key])
        self.apt_input.set_text(",".join(package for package in manifest.apt
                                         if package not in CATALOG_PACKAGES and package not in selected_presets))
        self.pip_input.set_text(",".join(manifest.pip))
        self.npm_input.set_text(",".join(x for x in manifest.npm if x != "@openai/codex@latest"))
        self.cargo_input.set_text(",".join(manifest.cargo))
        self.go_input.set_text(",".join(manifest.go))
        self.environment_view.get_buffer().set_text("\n".join(f"{key}={value}" for key, value in manifest.environment))
        self.codex_check.set_active("@openai/codex@latest" in manifest.npm)
        for editor in tuple(self.mount_rows):
            self._remove_mount_row(editor)
        for mount in manifest.mounts:
            self._add_mount_row(mount)
        self.wizard_step = 11; self._render_step()
