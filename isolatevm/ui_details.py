"""Effective permissions and managed mount controls."""
from __future__ import annotations

from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .model import INITIAL_SNAPSHOT, Mount, ValidationError
from .incus import DATA_DEVICE, validate_data_volume
from .storage import history, load_instance_manifest, saved_network_bridge
from .usb import UsbDevice
from .gpu import GpuDevice
from .pci import PciDevice
from .ui_widgets import label, button, row, entry
from . import change_diff as diff


class DetailsMixin:
    def show_effective(self, name: str) -> None:
        self.stack.set_visible_child_name("details")
        self._clear(self.details)
        detail_root = self.details
        self.details.append(label(f"Detalhes da VM · {name}", "page-title"))
        self.details.append(label("Configuração expandida do Incus. Acesso obtido dentro do guest e regras externas de firewall/DNS exigem verificação adicional.", "muted"))
        tabs = Gtk.Stack(transition_type=Gtk.StackTransitionType.NONE, vexpand=True)
        tabs.set_transition_duration(0)
        pages: dict[str, Gtk.Box] = {}
        for key, title in (("overview", "Visão geral"), ("hardware", "Hardware"),
                           ("storage", "Armazenamento"), ("files", "Arquivos compartilhados"),
                           ("network", "Rede"), ("software", "Software"),
                           ("security", "Segurança"), ("snapshots", "Snapshots"),
                           ("logs", "Logs"), ("terminal", "Terminal"),
                           ("provisioning", "Provisionamento"), ("advanced", "Configuração avançada")):
            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            page.set_margin_top(12); page.set_margin_bottom(18)
            pages[key] = page
            tabs.add_titled(page, key, title)
        switcher = Gtk.StackSwitcher(stack=tabs)
        self.details.append(switcher)
        self.details.append(tabs)
        def render(value: object) -> None:
            data = value
            settings = data.get("config", {}).get("config", {})
            devices = data.get("config", {}).get("devices", {})
            self.details = pages["overview"]
            self.details.append(label("Permissões efetivas", "section-title"))
            root = devices.get("root", {}) if isinstance(devices, dict) else {}
            overview_rows = [
                f"CPU: {settings.get('limits.cpu', 'não informado')}",
                f"RAM: {settings.get('limits.memory', 'não informado')}",
                f"Disco raiz: {root.get('size', 'não informado') if isinstance(root, dict) else 'não informado'}",
                f"Perfil de segurança: {data.get('security_profile', 'não verificado')}",
                f"Pastas do host: {len(data.get('mounts', []))} · NICs: {len(data.get('nics', []))} · volumes adicionais: {len(data.get('volumes', []))}",
            ]
            for item in overview_rows:
                self.details.append(label(item))
            self.details.append(label("O estado de acesso do guest ou políticas externas de firewall e DNS exigem verificação própria.", "muted"))
            self.details = pages["files"]
            self.details.append(label("Acessos ao Host · pastas", "section-title"))
            mounts = data["mounts"]
            self.details.append(button("+ Adicionar pasta…", lambda: self._mount_dialog(name)))
            if not mounts: self.details.append(label("Nenhuma pasta do host listada como dispositivo disk Incus"))
            for item in mounts:
                strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                strip.append(label(f"{item['source']} → {item['path']} [{item['mode']}]"))
                if item["managed"]:
                    strip.append(button("Remover", lambda x=item: self._review_change(
                        name, "mount-remove", lambda current: diff.mount_remove(current, x["device"], name),
                        lambda: self.service.remove_mount(name, x["device"]),
                        lambda: self.show_effective(name))))
                self.details.append(strip)
            self.details = pages["storage"]
            self.details.append(label("Disco raiz e volumes Incus", "section-title"))
            self.details.append(label(f"Disco raiz: {root.get('size', 'não informado') if isinstance(root, dict) else 'não informado'}", "muted"))
            self.details.append(button("+ Criar disco de dados…", lambda: self._data_volume_dialog(name)))
            if not data["volumes"]: self.details.append(label("Nenhum volume adicional listado"))
            for item in data["volumes"]:
                strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                strip.append(label(f"{item['device']}: {item['pool']}/{item['source']} · {item['size']} → {item['path']} [{item['mode']}]") )
                if item.get("managed") and DATA_DEVICE.fullmatch(item["device"]):
                    backup = button("Exportar backup…", lambda current=item:
                                    self._data_volume_backup(name, current["device"], current["source"]))
                    backup.set_sensitive(not self.mock)
                    if self.mock:
                        backup.set_tooltip_text("Backup de volume Incus exige uma VM real parada")
                    strip.append(backup)
                    strip.append(button("Excluir disco e dados…", lambda device=item["device"]:
                                        self._data_volume_remove(name, device), "destructive-action"))
                self.details.append(strip)
            self.details.append(label("Volumes Incus ficam separados do disco raiz. Discos de dados gerenciados pelo IsolateVM não entram no manifesto exportado nem nos snapshots/backups da VM; o clone faz uma cópia independente. Faça backup do volume separadamente.", "risk"))
            self.details = pages["network"]
            self.details.append(label("Rede", "section-title"))
            self.details.append(label(data["network"], "risk" if data["nics"] or data["possible_network_devices"] else "muted"))
            for nic in data["nics"]:
                self.details.append(label(f"{nic['device']}: {nic['network']} · tipo {nic['nictype']}"))
            self.details.append(label("Sites, IPs e portas permitidos: desconhecidos sem inspeção de rede externa.", "muted"))
            saved_bridge = saved_network_bridge(name)
            if saved_bridge and data["can_block_network"]:
                self.details.append(button("Bloquear rede Incus", lambda: self._review_change(
                    name, "network-block", lambda current: diff.network_block(current, name),
                    lambda: self.service.block_network(name),
                    lambda: self.show_effective(name))))
            elif saved_bridge and not data["nics"]:
                self.details.append(button("Restaurar política de rede", lambda: self._review_change(
                    name, "network-restore", lambda current: diff.network_restore(current, saved_bridge, name),
                    lambda: self.service.restore_network(name, saved_bridge),
                    lambda: self.show_effective(name))))
            elif saved_bridge:
                self.details.append(label("Bloqueio automático indisponível: há dispositivos ou configuração de rede não gerenciada.", "risk"))
            self.details = pages["hardware"]
            self.details.append(label("Recursos efetivos", "section-title"))
            self.details.append(label(f"CPU: {settings.get('limits.cpu', 'não informado')} · RAM: {settings.get('limits.memory', 'não informado')}", "muted"))
            self.details.append(label("Recursos configuráveis no dashboard: quantidade de vCPUs, RAM e expansão do disco raiz. Pinning de CPU exige VM parada.", "muted"))
            self.details.append(label("Dispositivos", "section-title"))
            self.details.append(button("+ Anexar USB…", lambda: self._usb_dialog(name)))
            self.details.append(button("+ Anexar GPU física…", lambda: self._gpu_dialog(name)))
            self.details.append(button("+ Anexar dispositivo PCI…", lambda: self._pci_dialog(name)))
            self.details.append(label("USB usa serial único quando disponível; sem serial único, usa o endereço atual de barramento/dispositivo. PCI bruto exige VM parada e autorização do projeto Incus. Bridges, GPUs e placas de rede não aparecem no seletor PCI; use os controles próprios. O Incus só oferece unix-char/unix-hotplug para containers, não VMs; use passthrough USB para adaptadores seriais USB. Nada é anexado automaticamente.", "risk"))
            for device in data["other_devices"]:
                strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                identity = f" · {device['identity']}" if device.get("identity") else ""
                strip.append(label(f"{device['device']}: {device['type']}{identity}"))
                remover = {"usb": self.service.remove_usb_device,
                           "gpu": self.service.remove_gpu_device,
                           "pci": self.service.remove_pci_device}.get(device["type"])
                if device.get("managed") and remover:
                    strip.append(button("Remover", lambda item=device, remove=remover: self._review_change(
                        name, f"{item['type']}-remove",
                        lambda current: diff.device_remove(current, item["device"], name),
                        lambda: remove(name, item["device"]),
                        lambda: self.show_effective(name))))
                self.details.append(strip)
            if not data["other_devices"]: self.details.append(label("Nenhum outro dispositivo Incus listado"))
            self.details = pages["security"]
            self.details.append(label("Perfis Incus", "section-title"))
            self.details.append(label(", ".join(data["profiles"]) if data["profiles"] else "Nenhum perfil herdado"))
            self.details.append(label("Perfil IsolateVM: " + data["security_profile"]))
            for warning in data["warnings"]:
                self.details.append(label("ATENÇÃO: " + warning, "risk"))
            self.details = pages["software"]
            self.details.append(label("Software declarado", "section-title"))
            initial_snapshot_protected = False
            manifest = None
            try:
                manifest = load_instance_manifest(name)
                initial_snapshot_protected = manifest.lifecycleDisposition in {
                    "restore-initial-on-close", "persist-workspace"}
                if manifest.lifecycleDisposition == "persist-workspace":
                    self.details.append(label(
                        f"/workspace fica em um volume Incus separado de {manifest.workspaceSizeGiB} GiB. Snapshots e backup da VM não incluem seus dados; use Exportar /workspace no dashboard.",
                        "risk"))
                self._copy_controls(name, manifest, data, pages["files"])
                self._secret_controls(name, manifest, pages["security"])
                self.details = pages["software"]
                self.details.append(label("Ambiente: " + (manifest.desktop.upper() if manifest.desktop else "Headless")))
                self.details.append(label("APT: " + (", ".join(manifest.apt) or "nenhum")))
                self.details.append(label("Python: " + (", ".join(manifest.pip) or "nenhum")))
                self.details.append(label("npm: " + (", ".join(manifest.npm) or "nenhum")))
                self.details.append(label("Cargo: " + (", ".join(manifest.cargo) or "nenhum")))
                self.details.append(label("Go: " + (", ".join(manifest.go) or "nenhum")))
                self.details.append(label("DevOps externo: " + (", ".join(manifest.externalTools) or "nenhum")))
                self.details.append(label("Variáveis declaradas: " + (", ".join(key for key, _ in manifest.environment) or "nenhuma")))
                self.details.append(label("Inventário observado no guest", "section-title"))
                inventory_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
                self.details.append(inventory_box)
                inventory_button = button("Verificar instalação e versões no guest",
                                          lambda: show_inventory())
                self.details.append(inventory_button)
                self.details.append(label("Consulta os gerenciadores sem instalar ou remover pacotes. Exige VM ligada e agente Incus ativo; compara apenas o manifesto salvo. O próprio guest fornece as versões e pode alterá-las.", "muted"))
                def show_inventory() -> None:
                    inventory_button.set_sensitive(False)
                    inventory_button.set_label("Consultando guest…")
                    def render_inventory(items: object) -> None:
                        self._clear(inventory_box)
                        if not items:
                            inventory_box.append(label("Nenhum pacote selecionado para verificar.", "muted"))
                        names = {"apt": "APT", "pip": "Python", "pipx": "pipx",
                                 "npm": "npm", "cargo": "Cargo", "go": "Go"}
                        statuses = {"installed": "instalado", "missing": "ausente",
                                    "version-mismatch": "versão divergente",
                                    "unavailable": "não verificável", "simulated": "simulado"}
                        for item in items:
                            state = statuses.get(item.status, "desconhecido")
                            suffix = f" · versão {item.version}" if item.version else ""
                            style = "risk" if item.status in {"missing", "unavailable", "version-mismatch"} else "muted"
                            inventory_box.append(label(
                                f"{names.get(item.manager, item.manager)} · {item.package}: {state}{suffix}", style))
                        inventory_button.set_sensitive(True)
                        inventory_button.set_label("Verificar novamente")
                    def inventory_error(exc: Exception) -> None:
                        inventory_button.set_sensitive(True)
                        inventory_button.set_label("Tentar verificação novamente")
                        self._error_dialog(exc)
                    self._work(lambda: self.service.software_inventory(name),
                               render_inventory, inventory_error)
                self.details = pages["provisioning"]
                self.details.append(label("Provisionamento inicial", "section-title"))
                if manifest.desktop:
                    self.details.append(label("Para login gráfico, configure uma senha no guest pelo terminal Incus; ela não consta no manifesto.", "risk"))
                    if not self.mock:
                        self.details.append(button("Configurar login gráfico…", lambda: self._guest_login(name)))
                self.details.append(label("Registro de criação; instalação e versões no guest não foram verificadas.", "muted"))
                status_label = label("Estado do cloud-init ainda não consultado.", "muted")
                self.details.append(status_label)
                def show_status() -> None:
                    def render_status(result: object) -> None:
                        state_names = {"running": "em andamento", "done": "concluído", "error": "erro",
                                       "disabled": "desabilitado", "degraded done": "concluído com avisos",
                                       "unknown": "desconhecido", "simulado": "simulado"}
                        parts = ["cloud-init: " + state_names.get(result.status, "desconhecido")]
                        if result.stage: parts.append("etapa: " + result.stage)
                        if result.error_count: parts.append(f"avisos/erros: {result.error_count}")
                        status_label.set_text(" · ".join(parts))
                    self._work(lambda: self.service.provisioning_status(name), render_status)
                self.details.append(button("Verificar cloud-init no guest", show_status))
                self.details.append(label("A VM precisa estar ligada e com o agente Incus ativo. O estado concluído não inventaria versões instaladas.", "muted"))
            except (OSError, ValidationError):
                self.details.append(label("Manifesto local indisponível. Consulte a VM para inventariar software.", "muted"))
                self.details.append(label("Referências de secrets desconhecidas; nenhuma será inferida da configuração Incus.", "muted"))
            self.details = pages["snapshots"]
            self.details.append(label("Snapshots", "section-title"))
            self.details.append(label("Data, estado e tamanho vêm dos metadados expostos pelo Incus. O Incus não aceita descrição personalizada ao criar snapshots; quando não houver uma descrição, isso aparece como indisponível.", "muted"))
            shots_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self.details.append(shots_box)
            def show_shots(items: object) -> None:
                if not items: shots_box.append(label("Nenhum snapshot"))
                for snapshot in items:
                    snap = snapshot.name
                    strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    strip.append(label(snap))
                    if not (initial_snapshot_protected and snap == INITIAL_SNAPSHOT):
                        strip.append(button("Renomear", lambda s=snap: self._ask(
                            "Novo nome do snapshot", s,
                            lambda new: self._confirm("Renomear snapshot?", f"{s} → {new}",
                                                      lambda: self._audited("snapshot-rename", name,
                                                                            lambda: self.service.rename_snapshot(name, s, new),
                                                                            lambda: self.show_effective(name))))))
                    restore_note = (" O volume separado /workspace permanece com seu conteúdo atual; o snapshot da VM não o restaura."
                                    if manifest is not None and manifest.lifecycleDisposition == "persist-workspace" else "")
                    strip.append(button("Restaurar", lambda s=snap: self._confirm(
                        "Restaurar snapshot?", f"A VM {name} voltará ao estado de {s}. Mudanças posteriores serão perdidas.{restore_note}",
                        lambda: self._audited("snapshot-restore", name, lambda: self.service.restore_snapshot(name, s)))))
                    if not (initial_snapshot_protected and snap == INITIAL_SNAPSHOT):
                        strip.append(button("Excluir", lambda s=snap: self._confirm(
                            "Excluir snapshot?", f"Snapshot {s} de {name} será removido.",
                            lambda: self._audited("snapshot-delete", name, lambda: self.service.delete_snapshot(name, s)))))
                    shots_box.append(strip)
                    size = (f"{snapshot.size_bytes / 1024**2:.1f} MiB"
                            if snapshot.size_bytes is not None else "não informado pelo Incus")
                    state = ("inclui estado de memória" if snapshot.stateful else
                             "somente disco" if snapshot.stateful is False else "não informado")
                    created = snapshot.created_at or "não informado"
                    description = snapshot.description or "indisponível no Incus"
                    shots_box.append(label(
                        f"Criado: {created} · Estado: {state} · Tamanho: {size}\nDescrição: {description}",
                        "muted"))
            self._work(lambda: self.service.snapshot_details(name), show_shots)
            self.details = pages["logs"]
            self.details.append(label("Histórico local de operações", "section-title"))
            entries = [item for item in history() if item.get("vm") == name]
            if entries:
                for item in entries:
                    self.details.append(label(f"{item.get('time', 'sem data')} · {item.get('action', 'ação')} · {item.get('result', 'estado')}", "muted"))
            else:
                self.details.append(label("Nenhuma operação local registrada para esta VM.", "muted"))
            self.details.append(label("Este histórico registra ações iniciadas pelo IsolateVM; não é o journal do host nem os logs internos do guest.", "risk"))
            self.details = pages["terminal"]
            self.details.append(label("Terminal integrado", "section-title"))
            self.details.append(label("O terminal abre uma sessão Incus no shell root da VM. Use o terminal apenas dentro da VM selecionada.", "muted"))
            self.details.append(button("Abrir terminal integrado", lambda: self._open_integrated_terminal(name)))
            self.details.append(label("A sessão exige VM em execução e uma instalação local real do Incus; o modo mock não abre sessões.", "muted"))
            self.details = pages["advanced"]
            self.details.append(label("Configuração Incus expandida", "section-title"))
            block = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
            import yaml
            block.get_buffer().set_text(yaml.safe_dump(data["config"], allow_unicode=True, sort_keys=False))
            self.details.append(block)
            self.details = detail_root
        self._work(lambda: self.service.effective(name), render)

    def _copy_controls(self, name: str, manifest: object, data: dict, target: Gtk.Box) -> None:
        self.details = target
        self.details.append(label("Cópias únicas no disco da VM", "section-title"))
        if not manifest.copies:
            self.details.append(label("Nenhuma cópia única declarada.", "muted"))
            return
        config = data.get("config", {}).get("config", {})
        state = config.get("user.isolatevm.copy-state", "desconhecido")
        descriptions = {"pending": "pendente", "done": "concluída", "none": "não declarada"}
        self.details.append(label("Estado Incus: " + descriptions.get(state, "desconhecido"),
                                  "risk" if state == "pending" else "muted"))
        for copy in manifest.copies:
            self.details.append(label(f"{copy.host} → {copy.guest} ({'pasta' if copy.kind == 'directory' else 'arquivo'}; ocultos: {'sim' if copy.include_hidden else 'não'})"))
        self.details.append(label("A origem é lida apenas durante a transferência. O conteúdo gravado permanece no disco e pode constar em snapshots ou exports.", "muted"))
        if state == "pending":
            self.details.append(button("Aplicar cópias pendentes", lambda: self._apply_copies(name)))
            self.details.append(label("Ligue a VM e aguarde o agente Incus antes de aplicar. Arquivos existentes com conteúdo diferente não serão sobrescritos.", "muted"))

    def _secret_controls(self, name: str, manifest: object, target: Gtk.Box) -> None:
        self.details = target
        refs = tuple(manifest.secrets)
        self.details.append(label("Secrets referenciados", "section-title"))
        if not refs:
            self.details.append(label("Nenhum secret referenciado por esta VM.", "muted"))
            return
        self.details.append(label("Referências: " + ", ".join(refs), "muted"))
        self.details.append(label("Valores não aparecem no manifesto, no histórico ou na configuração Incus. A entrega é manual e temporária em /run dentro da VM.", "risk"))
        status = {secret_name: label(f"{secret_name}: consultando cofre…", "muted") for secret_name in refs}
        for secret_name in refs:
            strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            strip.append(status[secret_name])
            strip.append(button("Atualizar valor…", lambda n=secret_name:
                                self._secret_value_dialog(lambda _saved: self.show_effective(name), n)))
            strip.append(button("Remover do cofre", lambda n=secret_name: self._confirm(
                "Remover secret do cofre do usuário?",
                f"A referência {n} continuará no manifesto. O valor guardado será apagado; cópias já entregues à VM permanecem até limpar /run ou desligar.",
                lambda: self._audited("secret-delete", "host-vault",
                                      lambda: self.secret_vault.delete(n),
                                      lambda: self.show_effective(name)))))
            self.details.append(strip)
        if self.mock:
            self.details.append(label("Modo mock: valores reais do cofre não são consultados nem enviados.", "muted"))
            return
        self.details.append(button("Entregar secrets à VM em execução…", lambda: self._confirm(
            "Enviar referências à VM?",
            f"Serão enviados os valores de {', '.join(refs)} pela entrada padrão do canal local do agente Incus. Eles ficam em arquivos root-owned 0640, legíveis pelo grupo ubuntu, no tmpfs /run; processos do usuário ubuntu podem lê-los. O conteúdo some ao desligar/reiniciar a VM ou ao limpar manualmente.",
            lambda: self._audited("secret-inject", name,
                                  lambda: self.service.inject_secrets(name, self.secret_vault.get_many),
                                  lambda: self.show_effective(name)))))
        self.details.append(button("Limpar secrets temporários da VM…", lambda: self._confirm(
            "Limpar secrets da VM?",
            "Os arquivos gerenciados em /run/isolatevm-secrets serão removidos. Processos que já leram um valor podem mantê-lo em memória.",
            lambda: self._audited("secret-clear", name, lambda: self.service.clear_secrets(name),
                                  lambda: self.show_effective(name)))))

        def found(names: object) -> None:
            available = set(names)
            for secret_name, state in status.items():
                state.set_text(f"{secret_name}: " + ("salvo no cofre" if secret_name in available else "ausente do cofre"))

        def vault_error(exc: Exception) -> None:
            for state in status.values(): state.set_text("Cofre indisponível nesta sessão")
            self._error_dialog(exc)

        self._work(self.secret_vault.names, found, vault_error)

    def _data_volume_dialog(self, name: str) -> None:
        dialog = Gtk.Dialog(title="Criar disco de dados", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        review = dialog.add_button("Revisar", Gtk.ResponseType.OK)
        review.set_sensitive(False)
        content = dialog.get_content_area()
        content.set_spacing(10); content.set_margin_start(16); content.set_margin_end(16)
        content.set_margin_top(12); content.set_margin_bottom(12)
        volume = entry("project-data")
        pool = Gtk.ComboBoxText()
        size = Gtk.SpinButton.new_with_range(1, 2048, 1)
        size.set_value(10)
        guest_path = entry("/data")
        readonly = Gtk.CheckButton(label="Somente leitura dentro da VM (RO)")
        content.append(row("Nome novo do volume", volume))
        content.append(row("Pool Incus", pool))
        content.append(row("Tamanho (GiB)", size))
        content.append(row("Caminho dentro do guest", guest_path))
        content.append(readonly)
        content.append(label("O volume será criado pelo Incus e anexado à VM parada. A exclusão remove os dados do volume. O conteúdo fica separado do disco raiz e pode não ser incluído em snapshots ou backups da VM.", "risk"))
        pools: list[str] = []
        def loaded(items: object) -> None:
            pools.extend(str(item) for item in items)
            for item in pools:
                pool.append_text(item)
            pool.set_active(0 if pools else -1)
            review.set_sensitive(bool(pools))
            if not pools:
                content.append(label("Nenhum pool Incus disponível.", "error"))
        self._work(self.service.pools, loaded,
                   lambda exc: content.append(label("Não foi possível listar pools: " + str(exc), "error")))
        def response(window: Gtk.Dialog, response_id: int) -> None:
            selected_pool = pool.get_active_text()
            selected_volume = volume.get_text().strip()
            selected_size = size.get_value_as_int()
            selected_path = guest_path.get_text().strip()
            selected_readonly = readonly.get_active()
            window.destroy()
            if response_id != Gtk.ResponseType.OK:
                return
            try:
                validate_data_volume(selected_pool or "", selected_volume, selected_size,
                                     selected_path, selected_readonly)
            except ValidationError as exc:
                self._toast(str(exc)); return
            self._review_change(
                name, "disk-volume-add",
                lambda current: diff.data_volume_add(current, selected_pool or "",
                                                       selected_volume, selected_size,
                                                       selected_path, selected_readonly, name),
                lambda: self.service.create_data_volume(name, selected_pool or "",
                                                        selected_volume, selected_size,
                                                        selected_path, selected_readonly),
                lambda: self.show_effective(name))
        dialog.connect("response", response)
        dialog.present()

    def _data_volume_remove(self, name: str, device: str) -> None:
        self._review_change(
            name, "disk-volume-delete",
            lambda current: diff.data_volume_remove(current, device, name),
            lambda: self.service.delete_data_volume(name, device),
            lambda: self.show_effective(name))

    def _data_volume_backup(self, name: str, device: str, volume: str) -> None:
        self._ask("Arquivo de backup do disco de dados",
                  str(Path.home() / f"{name}-{device}-{volume}.tar.gz"),
                  lambda destination: self._data_volume_backup_prompt(name, device, destination))

    def _data_volume_backup_prompt(self, name: str, device: str, destination: str) -> None:
        target = Path(destination)
        self._confirm("Exportar disco de dados separado?",
                      f"VM: {name} · disco {device}\nArquivo novo: {target}\n"
                      "O volume será exportado separadamente do backup completo da VM. "
                      "A VM precisa estar parada para reduzir alterações durante a exportação.",
                      lambda: self._audited("backup-data-volume", name,
                                            lambda: self.service.export_data_volume(name, device, target),
                                            lambda: self._toast(f"Backup do disco salvo em {target}")))

    def _usb_dialog(self, name: str) -> None:
        dialog = Gtk.Dialog(title="Anexar dispositivo USB", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Revisar", Gtk.ResponseType.OK)
        content = dialog.get_content_area(); content.set_spacing(10)
        content.set_margin_start(16); content.set_margin_end(16); content.set_margin_top(12); content.set_margin_bottom(12)
        content.append(label("A lista vem de /sys. O Incus selecionará o periférico pelo serial se ele for único; caso contrário, pelo endereço atual de barramento/dispositivo. Reconecte e selecione novamente após trocar de porta ou reiniciar o dispositivo.", "risk"))
        chooser = Gtk.ComboBoxText(); selected: list[UsbDevice] = []
        def serial_is_unique(item: UsbDevice, candidates: list[UsbDevice]) -> bool:
            return bool(item.serial) and sum(
                other.vendor_id == item.vendor_id and other.product_id == item.product_id and
                other.serial == item.serial for other in candidates) == 1
        def identity(item: UsbDevice, candidates: list[UsbDevice]) -> str:
            selector = (f"serial {item.serial}" if serial_is_unique(item, candidates) else
                        f"bus {item.busnum} device {item.devnum}")
            return f"{item.vendor_id}:{item.product_id} · {selector}"
        def devices_ready(items: object) -> None:
            selected.extend(items)
            for item in selected:
                chooser.append_text(f"{item.description} · {identity(item, selected)} · {item.path}")
            chooser.set_active(0 if selected else -1)
            if not selected: content.append(label("Nenhum dispositivo USB físico elegível foi encontrado.", "muted"))
        self._work(lambda: self.service.host_usb_devices(), devices_ready)
        content.append(chooser)
        def response(d: Gtk.Dialog, response_id: int) -> None:
            index = chooser.get_active(); d.destroy()
            if response_id != Gtk.ResponseType.OK: return
            if index < 0 or index >= len(selected): self._toast("Escolha um dispositivo USB"); return
            item = selected[index]
            selector_args = ((f"serial={item.serial}",) if serial_is_unique(item, selected) else
                             (f"busnum={item.busnum}", f"devnum={item.devnum}"))
            attributes = (f"vendorid={item.vendor_id}", f"productid={item.product_id}",
                          *selector_args, "required=false")
            self._review_change(name, "usb-add",
                                lambda current: diff.device_add(current, "USB", item.description,
                                                                identity(item, selected), name, attributes),
                                lambda: self.service.add_usb_device(name, item),
                                lambda: self.show_effective(name))
        dialog.connect("response", response); dialog.present()

    def _gpu_dialog(self, name: str) -> None:
        dialog = Gtk.Dialog(title="Anexar GPU física", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL); dialog.add_button("Revisar", Gtk.ResponseType.OK)
        content = dialog.get_content_area(); content.set_spacing(10)
        content.set_margin_start(16); content.set_margin_end(16); content.set_margin_top(12); content.set_margin_bottom(12)
        content.append(label("A GPU física será vinculada à VM pelo endereço PCI. Para VMs, Incus não suporta hotplug; desligue a VM. A GPU pode estar em uso pelo host e o passthrough pode afetar a sessão gráfica.", "risk"))
        chooser = Gtk.ComboBoxText(); selected: list[GpuDevice] = []
        def devices_ready(items: object) -> None:
            selected.extend(items)
            for item in selected: chooser.append_text(f"{item.description} · {item.vendor_id}:{item.product_id}")
            chooser.set_active(0 if selected else -1)
            if not selected: content.append(label("Nenhuma GPU PCI elegível foi encontrada.", "muted"))
        self._work(lambda: self.service.host_gpu_devices(), devices_ready); content.append(chooser)
        def response(d: Gtk.Dialog, response_id: int) -> None:
            index = chooser.get_active(); d.destroy()
            if response_id != Gtk.ResponseType.OK: return
            if index < 0 or index >= len(selected): self._toast("Escolha uma GPU"); return
            item = selected[index]
            self._review_change(name, "gpu-add",
                                lambda current: diff.device_add(
                                    current, "GPU", item.description, item.pci, name,
                                    ("gputype=physical", f"pci={item.pci}",
                                     f"vendorid={item.vendor_id}", f"productid={item.product_id}")),
                                lambda: self.service.add_gpu_device(name, item),
                                lambda: self.show_effective(name))
        dialog.connect("response", response); dialog.present()

    def _pci_dialog(self, name: str) -> None:
        dialog = Gtk.Dialog(title="Anexar dispositivo PCI bruto", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        review = dialog.add_button("Revisar", Gtk.ResponseType.OK)
        review.set_sensitive(False)
        content = dialog.get_content_area(); content.set_spacing(10)
        content.set_margin_start(16); content.set_margin_end(16)
        content.set_margin_top(12); content.set_margin_bottom(12)
        content.append(label("PCI bruto não oferece hotplug em VMs. A entrega pode retirar o dispositivo do host; armazenamento, controladores USB e outros dispositivos do sistema podem tornar o host ou a VM inoperante. Incus também pode negar a operação se o projeto bloquear PCI. O IsolateVM não altera drivers nem permissões do host.", "risk"))
        acknowledged = Gtk.CheckButton(label="Entendo o risco do passthrough PCI e selecionei um dispositivo dispensável no host")
        content.append(acknowledged)
        device_available = [False]
        acknowledged.connect("toggled", lambda widget: review.set_sensitive(
            widget.get_active() and device_available[0]))
        chooser = Gtk.ComboBoxText(); selected: list[PciDevice] = []
        def devices_ready(items: object) -> None:
            selected.extend(items)
            device_available[0] = bool(selected)
            for item in selected:
                chooser.append_text(f"{item.description}")
            chooser.set_active(0 if selected else -1)
            if not selected:
                content.append(label("Nenhum dispositivo PCI genérico elegível foi encontrado.", "muted"))
                review.set_sensitive(False)
            else:
                review.set_sensitive(acknowledged.get_active())
        self._work(self.service.host_pci_devices, devices_ready)
        content.append(chooser)
        def response(d: Gtk.Dialog, response_id: int) -> None:
            index = chooser.get_active(); d.destroy()
            if response_id != Gtk.ResponseType.OK: return
            if not acknowledged.get_active():
                self._toast("Confirme que revisou o risco do passthrough PCI")
                return
            if index < 0 or index >= len(selected):
                self._toast("Escolha um dispositivo PCI")
                return
            item = selected[index]
            self._review_change(name, "pci-add",
                                lambda current: diff.device_add(
                                    current, "PCI", item.description, item.address, name,
                                    (f"address={item.address}", "firmware=false")),
                                lambda: self.service.add_pci_device(name, item),
                                lambda: self.show_effective(name))
        dialog.connect("response", response); dialog.present()

    def _mount_dialog(self, name: str) -> None:
        dialog = Gtk.Dialog(title="Adicionar pasta do host", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Revisar", Gtk.ResponseType.OK)
        content = dialog.get_content_area()
        content.set_spacing(10); content.set_margin_start(16); content.set_margin_end(16)
        content.set_margin_top(12); content.set_margin_bottom(12)
        host = entry(); guest = entry("/workspace")
        rw = Gtk.CheckButton(label="Leitura e escrita (RW)")
        content.append(row("Pasta do host", host))
        content.append(row("Destino na VM", guest))
        content.append(rw)
        def selected(d: Gtk.Dialog, response: int) -> None:
            data = {"host": host.get_text().strip(), "guest": guest.get_text().strip(),
                    "mode": "rw" if rw.get_active() else "ro"}
            d.destroy()
            if response != Gtk.ResponseType.OK: return
            try: mount = Mount.parse(data)
            except Exception as exc: self._toast(str(exc)); return
            self._review_change(name, "mount-add",
                                lambda current: diff.mount_add(current, mount, name),
                                lambda: self.service.add_mount(name, mount),
                                lambda: self.show_effective(name))
        dialog.connect("response", selected)
        dialog.present()
