"""On-demand metrics view with an actual interval for CPU and network rates."""
from __future__ import annotations

import time

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .incus import VM
from .metrics import MetricsSnapshot, cpu_percent_between
from .ui_widgets import label, button


def _size(value: int | None) -> str:
    if value is None: return "indisponível"
    return f"{value / 1024**3:.2f} GiB"


class MetricsMixin:
    def show_metrics(self, vm: VM) -> None:
        self._metrics_generation += 1
        generation = self._metrics_generation
        self.stack.set_visible_child_name("metrics")
        self._clear(self.metrics_page)
        self.metrics_page.append(label(f"Monitoramento · {vm.name}", "page-title"))
        self.metrics_page.append(label("Leituras sob demanda do estado Incus. Contadores indisponíveis não são estimados.", "muted"))
        self.metrics_page.append(button("Atualizar métricas", lambda: self.show_metrics(vm)))
        progress = label("Amostrando CPU e rede por 1,2 segundo…", "muted")
        self.metrics_page.append(progress)

        def sample() -> tuple[MetricsSnapshot, MetricsSnapshot, float]:
            first = self.service.metrics(vm.name)
            start = time.monotonic()
            time.sleep(1.2)
            second = self.service.metrics(vm.name)
            return first, second, time.monotonic() - start

        def render(result: object) -> None:
            if generation != self._metrics_generation: return
            first, second, elapsed = result
            self.metrics_page.remove(progress)
            allocated = int(vm.cpu) if vm.cpu.isdigit() and int(vm.cpu) > 0 else None
            cpu_percent = cpu_percent_between(first, second, elapsed, allocated)
            self._metric_bar("CPU · taxa sobre vCPUs alocadas", cpu_percent)
            self._metric_bar("RAM", self._percentage(second.memory_bytes, second.memory_total_bytes))
            self.metrics_page.append(label(f"RAM: {_size(second.memory_bytes)} usados de {_size(second.memory_total_bytes)}"))
            self._metric_bar("Disco raiz", self._percentage(second.disk_bytes, second.disk_total_bytes))
            self.metrics_page.append(label(f"Disco raiz: {_size(second.disk_bytes)} usados de {_size(second.disk_total_bytes)}"))
            self.metrics_page.append(label("Rede · taxa total da amostra", "section-title"))
            for title, before, after in (("Recebidos", first.network_rx_bytes, second.network_rx_bytes),
                                         ("Enviados", first.network_tx_bytes, second.network_tx_bytes)):
                rate = f"{(after - before) / elapsed / 1024:.1f} KiB/s" if before is not None and after is not None and after >= before else "indisponível"
                self.metrics_page.append(label(f"{title}: {rate}"))
            uptime = second.uptime_seconds
            self.metrics_page.append(label(f"Uptime: {uptime // 3600} h {(uptime % 3600) // 60} min" if uptime is not None else "Uptime: indisponível"))

        self._work(sample, render)

    @staticmethod
    def _percentage(used: int | None, total: int | None) -> float | None:
        return used / total * 100 if used is not None and total is not None and total > 0 else None

    def _metric_bar(self, title: str, percent: float | None) -> None:
        value = "indisponível" if percent is None else f"{percent:.1f}%"
        self.metrics_page.append(label(f"{title}: {value}", "section-title"))
        if percent is not None:
            bar = Gtk.ProgressBar()
            bar.set_fraction(min(1.0, max(0.0, percent / 100)))
            self.metrics_page.append(bar)
