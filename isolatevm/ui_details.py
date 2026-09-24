"""Effective permissions and managed mount controls."""
from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .model import Mount, ValidationError
from .storage import load_instance_manifest, saved_network_bridge
from .usb import UsbDevice
from .gpu import GpuDevice
from .ui_widgets import label, button, row, entry


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
                    strip.append(button("Remover", lambda x=item: self._confirm(
                        "Remover acesso ao host?", f"- {x['source']} → {x['path']} [{x['mode']}]. A VM pode precisar reiniciar.",
                        lambda: self._audited("mount-remove", name,
                                              lambda: self.service.remove_mount(name, x["device"]),
                                              lambda: self.show_effective(name)))))
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
                self.details.append(button("Bloquear rede Incus", lambda: self._confirm(
                    "Remover NIC eth0?", "- NIC eth0 conectada\n+ Sem NIC Incus. A VM pode precisar reiniciar.",
                    lambda: self._audited("network-block", name,
                                          lambda: self.service.block_network(name),
                                          lambda: self.show_effective(name)))))
            elif saved_bridge and not data["nics"]:
                self.details.append(button("Restaurar política de rede", lambda: self._confirm(
                    "Restaurar conexão?", f"- Sem NIC\n+ eth0 na bridge {saved_bridge}. Saída sem filtro de domínio.",
                    lambda: self._audited("network-restore", name,
                                          lambda: self.service.restore_network(name, saved_bridge),
                                          lambda: self.show_effective(name)))))
            elif saved_bridge:
                self.details.append(label("Bloqueio automático indisponível: há dispositivos ou configuração de rede não gerenciada.", "risk"))
            self.details.append(label("Dispositivos", "section-title"))
            self.details.append(button("+ Anexar USB…", lambda: self._usb_dialog(name)))
            self.details.append(button("+ Anexar GPU física…", lambda: self._gpu_dialog(name)))
            self.details.append(label("USB é repassado apenas por ID de fabricante/produto. Acesso a câmera, áudio ou armazenamento depende do próprio dispositivo; nada é anexado automaticamente.", "muted"))
            for device in data["other_devices"]:
                strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                strip.append(label(f"{device['device']}: {device['type']}"))
                if device.get("managed"):
                    strip.append(button("Remover", lambda item=device: self._confirm(
                        "Remover dispositivo?", f"- {item['device']} ({item['type']})",
                        lambda: self._audited("usb-remove" if item["type"] == "usb" else "gpu-remove", name,
                                              lambda: self.service.remove_usb_device(name, item["device"]) if item["type"] == "usb" else self.service.remove_gpu_device(name, item["device"]),
                                              lambda: self.show_effective(name)))))
                self.details.append(strip)
            if not data["other_devices"]: self.details.append(label("Nenhum outro dispositivo Incus listado"))
            self.details.append(label("Perfis Incus", "section-title"))
            self.details.append(label(", ".join(data["profiles"]) if data["profiles"] else "Nenhum perfil herdado"))
            self.details.append(label("Perfil IsolateVM: " + data["security_profile"]))
            for warning in data["warnings"]:
                self.details.append(label("ATENÇÃO: " + warning, "risk"))
            self.details.append(label("Software declarado", "section-title"))
            try:
                manifest = load_instance_manifest(name)
                self.details.append(label("Ambiente: " + (manifest.desktop.upper() if manifest.desktop else "Headless")))
                self.details.append(label("APT: " + (", ".join(manifest.apt) or "nenhum")))
                self.details.append(label("Python: " + (", ".join(manifest.pip) or "nenhum")))
                self.details.append(label("npm: " + (", ".join(manifest.npm) or "nenhum")))
                self.details.append(label("Cargo: " + (", ".join(manifest.cargo) or "nenhum")))
                self.details.append(label("Go: " + (", ".join(manifest.go) or "nenhum")))
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
            self.details.append(label("Credenciais", "section-title"))
            self.details.append(label("O IsolateVM não injeta secrets. Credenciais configuradas fora dele ou criadas dentro do guest não podem ser inferidas da configuração Incus.", "muted"))
            self.details.append(label("Snapshots", "section-title"))
            shots_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            self.details.append(shots_box)
            def show_shots(items: object) -> None:
                if not items: shots_box.append(label("Nenhum snapshot"))
                for snap in items:
                    strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    strip.append(label(snap))
                    strip.append(button("Renomear", lambda s=snap: self._ask(
                        "Novo nome do snapshot", s,
                        lambda new: self._confirm("Renomear snapshot?", f"{s} → {new}",
                                                  lambda: self._audited("snapshot-rename", name,
                                                                        lambda: self.service.rename_snapshot(name, s, new),
                                                                        lambda: self.show_effective(name))))))
                    strip.append(button("Restaurar", lambda s=snap: self._confirm(
                        "Restaurar snapshot?", f"A VM {name} voltará ao estado de {s}. Mudanças posteriores serão perdidas.",
                        lambda: self._audited("snapshot-restore", name, lambda: self.service.restore_snapshot(name, s)))))
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

    def _usb_dialog(self, name: str) -> None:
        dialog = Gtk.Dialog(title="Anexar dispositivo USB", transient_for=self, modal=True)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Revisar", Gtk.ResponseType.OK)
        content = dialog.get_content_area(); content.set_spacing(10)
        content.set_margin_start(16); content.set_margin_end(16); content.set_margin_top(12); content.set_margin_bottom(12)
        content.append(label("A lista vem de /sys. O dispositivo será identificado pelo par vendor/product e pode corresponder a outro dispositivo idêntico conectado depois.", "risk"))
        chooser = Gtk.ComboBoxText(); selected: list[UsbDevice] = []
        def devices_ready(items: object) -> None:
            selected.extend(items)
            for item in selected:
                chooser.append_text(f"{item.description} · {item.vendor_id}:{item.product_id} · {item.path}")
            chooser.set_active(0 if selected else -1)
            if not selected: content.append(label("Nenhum dispositivo USB físico elegível foi encontrado.", "muted"))
        self._work(lambda: self.service.host_usb_devices(), devices_ready)
        content.append(chooser)
        def response(d: Gtk.Dialog, response_id: int) -> None:
            index = chooser.get_active(); d.destroy()
            if response_id != Gtk.ResponseType.OK: return
            if index < 0 or index >= len(selected): self._toast("Escolha um dispositivo USB"); return
            item = selected[index]
            self._confirm("Anexar dispositivo USB?",
                          f"+ {item.description}\nID: {item.vendor_id}:{item.product_id}\nA VM poderá acessar este tipo de USB quando estiver disponível.",
                          lambda: self._audited("usb-add", name, lambda: self.service.add_usb_device(name, item),
                                                lambda: self.show_effective(name)))
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
            self._confirm("Anexar GPU física?", f"+ {item.description}\nPCI: {item.pci}\nA GPU ficará disponível para a VM e pode deixar de estar disponível ao host.",
                          lambda: self._audited("gpu-add", name, lambda: self.service.add_gpu_device(name, item), lambda: self.show_effective(name)))
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
            self._confirm("Aplicar alteração de acesso?",
                          f"+ {mount.host} → {mount.guest} [{mount.mode.upper()}]. A VM pode precisar reiniciar.",
                          lambda: self._audited("mount-add", name,
                                                lambda: self.service.add_mount(name, mount),
                                                lambda: self.show_effective(name)))
        dialog.connect("response", selected)
        dialog.present()
