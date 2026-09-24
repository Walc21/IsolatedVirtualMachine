"""Effective permissions and managed mount controls."""
from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .model import INITIAL_SNAPSHOT, Mount, ValidationError
from .storage import load_instance_manifest, saved_network_bridge
from .usb import UsbDevice
from .gpu import GpuDevice
from .ui_widgets import label, button, row, entry
from . import change_diff as diff


class DetailsMixin:
    def show_effective(self, name: str) -> None:
        self.stack.set_visible_child_name("details")
        self._clear(self.details)
        self.details.append(label(f"Permissões efetivas · {name}", "page-title"))
        self.details.append(label("Configuração expandida do Incus. Acesso obtido dentro do guest e regras externas de firewall/DNS exigem verificação adicional.", "muted"))
        def render(value: object) -> None:
            data = value
            self.details.append(label("Acessos ao Host · pastas", "section-title"))
            mounts = data["mounts"]
            self.details.append(button("+ Adicionar pasta…", lambda: self._mount_dialog(name)))
            if not mounts: self.details.append(label("Nenhuma pasta do host listada como dispositivo disk Incus"))
            for item in mounts:
                strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                strip.append(label(f"{item['source']} → {item['path']} [{item['mode']}]"))
                if item["managed"]:
                    strip.append(button("Remover", lambda x=item: self._review_change(
                        name, "mount-remove", lambda current: diff.mount_remove(current, x["device"]),
                        lambda: self.service.remove_mount(name, x["device"]),
                        lambda: self.show_effective(name))))
                self.details.append(strip)
            self.details.append(label("Discos e volumes adicionais", "section-title"))
            if not data["volumes"]: self.details.append(label("Nenhum volume adicional listado"))
            for item in data["volumes"]:
                self.details.append(label(f"{item['device']}: {item['source']} → {item['path']}"))
            self.details.append(label("Rede", "section-title"))
            self.details.append(label(data["network"], "risk" if data["nics"] or data["possible_network_devices"] else "muted"))
            for nic in data["nics"]:
                self.details.append(label(f"{nic['device']}: {nic['network']} · tipo {nic['nictype']}"))
            self.details.append(label("Sites, IPs e portas permitidos: desconhecidos sem inspeção de rede externa.", "muted"))
            saved_bridge = saved_network_bridge(name)
            if saved_bridge and data["can_block_network"]:
                self.details.append(button("Bloquear rede Incus", lambda: self._review_change(
                    name, "network-block", diff.network_block,
                    lambda: self.service.block_network(name),
                    lambda: self.show_effective(name))))
            elif saved_bridge and not data["nics"]:
                self.details.append(button("Restaurar política de rede", lambda: self._review_change(
                    name, "network-restore", lambda current: diff.network_restore(current, saved_bridge),
                    lambda: self.service.restore_network(name, saved_bridge),
                    lambda: self.show_effective(name))))
            elif saved_bridge:
                self.details.append(label("Bloqueio automático indisponível: há dispositivos ou configuração de rede não gerenciada.", "risk"))
            self.details.append(label("Dispositivos", "section-title"))
            self.details.append(button("+ Anexar USB…", lambda: self._usb_dialog(name)))
            self.details.append(button("+ Anexar GPU física…", lambda: self._gpu_dialog(name)))
            self.details.append(label("USB usa serial único quando disponível; sem serial único, usa o endereço atual de barramento/dispositivo. Ao reconectar, selecione novamente. Acesso a câmera, áudio ou armazenamento depende do periférico; nada é anexado automaticamente.", "muted"))
            for device in data["other_devices"]:
                strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                identity = f" · {device['identity']}" if device.get("identity") else ""
                strip.append(label(f"{device['device']}: {device['type']}{identity}"))
                if device.get("managed"):
                    strip.append(button("Remover", lambda item=device: self._review_change(
                        name, "usb-remove" if item["type"] == "usb" else "gpu-remove",
                        lambda current: diff.device_remove(current, item["device"]),
                        lambda: self.service.remove_usb_device(name, item["device"]) if item["type"] == "usb" else self.service.remove_gpu_device(name, item["device"]),
                        lambda: self.show_effective(name))))
                self.details.append(strip)
            if not data["other_devices"]: self.details.append(label("Nenhum outro dispositivo Incus listado"))
            self.details.append(label("Perfis Incus", "section-title"))
            self.details.append(label(", ".join(data["profiles"]) if data["profiles"] else "Nenhum perfil herdado"))
            self.details.append(label("Perfil IsolateVM: " + data["security_profile"]))
            for warning in data["warnings"]:
                self.details.append(label("ATENÇÃO: " + warning, "risk"))
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
                self._copy_controls(name, manifest, data)
                self._secret_controls(name, manifest)
                self.details.append(label("Ambiente: " + (manifest.desktop.upper() if manifest.desktop else "Headless")))
                self.details.append(label("APT: " + (", ".join(manifest.apt) or "nenhum")))
                self.details.append(label("Python: " + (", ".join(manifest.pip) or "nenhum")))
                self.details.append(label("npm: " + (", ".join(manifest.npm) or "nenhum")))
                self.details.append(label("Cargo: " + (", ".join(manifest.cargo) or "nenhum")))
                self.details.append(label("Go: " + (", ".join(manifest.go) or "nenhum")))
                self.details.append(label("DevOps externo: " + (", ".join(manifest.externalTools) or "nenhum")))
                self.details.append(label("Variáveis declaradas: " + (", ".join(key for key, _ in manifest.environment) or "nenhuma")))
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
            self.details.append(label("Snapshots", "section-title"))
            shots_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self.details.append(shots_box)
            def show_shots(items: object) -> None:
                if not items: shots_box.append(label("Nenhum snapshot"))
                for snap in items:
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
            self._work(lambda: self.service.snapshots(name), show_shots)
            self.details.append(label("Configuração simulada" if self.mock else "Configuração Incus expandida", "section-title"))
            block = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
            import yaml
            block.get_buffer().set_text(yaml.safe_dump(data["config"], allow_unicode=True, sort_keys=False))
            self.details.append(block)
        self._work(lambda: self.service.effective(name), render)

    def _copy_controls(self, name: str, manifest: object, data: dict) -> None:
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

    def _secret_controls(self, name: str, manifest: object) -> None:
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

    def _usb_dialog(self, name: str) -> None:
        dialog = Gtk.Dialog(title="Anexar dispositivo USB", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Revisar", Gtk.ResponseType.OK)
        content = dialog.get_content_area(); content.set_spacing(10)
        content.set_margin_start(16); content.set_margin_end(16); content.set_margin_top(12); content.set_margin_bottom(12)
        content.append(label("A lista vem de /sys. O Incus selecionará o periférico pelo serial se ele for único; caso contrário, pelo endereço atual de barramento/dispositivo. Reconecte e selecione novamente após trocar de porta ou reiniciar o dispositivo.", "risk"))
        chooser = Gtk.ComboBoxText(); selected: list[UsbDevice] = []
        def identity(item: UsbDevice) -> str:
            selector = f"serial {item.serial}" if item.serial else f"bus {item.busnum} device {item.devnum}"
            return f"{item.vendor_id}:{item.product_id} · {selector}"
        def devices_ready(items: object) -> None:
            selected.extend(items)
            for item in selected:
                chooser.append_text(f"{item.description} · {identity(item)} · {item.path}")
            chooser.set_active(0 if selected else -1)
            if not selected: content.append(label("Nenhum dispositivo USB físico elegível foi encontrado.", "muted"))
        self._work(lambda: self.service.host_usb_devices(), devices_ready)
        content.append(chooser)
        def response(d: Gtk.Dialog, response_id: int) -> None:
            index = chooser.get_active(); d.destroy()
            if response_id != Gtk.ResponseType.OK: return
            if index < 0 or index >= len(selected): self._toast("Escolha um dispositivo USB"); return
            item = selected[index]
            self._review_change(name, "usb-add",
                                lambda current: diff.device_add(current, "USB", item.description,
                                                                identity(item)),
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
                                lambda current: diff.device_add(current, "GPU", item.description, item.pci),
                                lambda: self.service.add_gpu_device(name, item),
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
                                lambda current: diff.mount_add(current, mount),
                                lambda: self.service.add_mount(name, mount),
                                lambda: self.show_effective(name))
        dialog.connect("response", selected)
        dialog.present()
