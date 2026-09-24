"""Shared GTK widgets and styling."""
from __future__ import annotations

from typing import Callable
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk


CSS = """
window { background: @window_bg_color; }
.page-title { font-size: 25px; font-weight: 700; margin-bottom: 8px; }
.muted { color: @insensitive_fg_color; }
.card { background: @card_bg_color; border: 1px solid @borders; border-radius: 12px; padding: 16px; margin: 7px; }
.risk { color: #d87924; font-weight: 700; }
.good { color: #2ca56d; }
.error { color: #d64a4a; }
.section-title { font-size: 17px; font-weight: 700; margin-top: 10px; }
"""


def label(text: str, css: str | None = None, wrap: bool = True) -> Gtk.Label:
    item = Gtk.Label(label=text, xalign=0, wrap=wrap, selectable=True)
    if css: item.add_css_class(css)
    return item


def button(text: str, callback: Callable, css: str | None = None) -> Gtk.Button:
    item = Gtk.Button(label=text)
    item.connect("clicked", lambda *_: callback())
    if css: item.add_css_class(css)
    return item


def row(title: str, widget: Gtk.Widget) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
    box.append(label(title))
    box.append(widget)
    return box


def entry(text: str = "") -> Gtk.Entry:
    item = Gtk.Entry()
    item.set_text(text)
    return item


def combo(values: list[str], active: int = 0) -> Gtk.ComboBoxText:
    item = Gtk.ComboBoxText()
    for value in values: item.append_text(value)
    item.set_active(active)
    return item
