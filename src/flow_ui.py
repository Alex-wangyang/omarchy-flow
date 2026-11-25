#!/usr/bin/python3
"""Native settings window for the private, local Flow daemon."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk

from flow_control import (ControlClient, ControlError, LAYOUT_GRID, build_settings_update,
                          move_peer_slot, remove_peer_slot, toggle_peer_enabled)

from flow_i18n import (CONTROL_ERRORS, EDGES, LANGUAGES, display_event, display_summary, load_ui_language,
                       save_ui_language, tr)

LAYOUT_LABELS = {"horizontal": "Horizontal", "vertical": "Vertical", "left-top": "Top left",
                 "right-top": "Top right", "left-bottom": "Bottom left", "right-bottom": "Bottom right"}
MODIFIER_LABELS = ("Ctrl (Mac default)", "Super (Win / Cmd)", "Alt")
MODIFIERS = ("ctrl", "super", "alt")
CSS = """
window.flow { background: #141414; color: #f4f4f6; }
.flow headerbar, .footer { background: #1c1c1c; }
.flow switch:checked, .layout.selected, .primary { background: #00f5d4; color: #071c18; }
.canvas { background: #141414; }
.peer-card { padding: 10px; border-radius: 12px; background: #0e0e10; border: 1px solid #39393d; }
.peer-card.local { background: #00f5d4; color: #092420; border-color: #00f5d4; }
.peer-card.disabled { background: #242428; color: #c5c5ca; }
.peer-card.empty { border: 1px dashed #525258; background: transparent; }
.peer-card .connected { color: #00f5d4; }
.peer-card button { padding: 3px 6px; min-height: 22px; }
.peer-card.local button { color: #092420; }
.wire { background: #54545a; }
.layout { padding: 7px; border-radius: 9px; background: #242428; }
.pill { border-radius: 20px; padding: 3px 9px; background: #2b2b30; font-size: 11px; }
.panel { background: #1c1c1c; border: 1px solid #2b2b30; border-radius: 12px; padding: 12px; }
.drawer { background: #1c1c1c; }
"""


def host_rows(status):
    settings = status["settings"]
    if settings:
        return settings["peers"]
    ch = status["local_channel"]
    return [dict(slot=i, channel=i, keyboard_channel=0xffffffff,
                 host_id=status["host_id"] if i == ch else "", enabled=i == ch,
                 connected=i == ch, is_local=i == ch, peer_ip=None) for i in range(3)]


def monitor_lines(status, lang="en"):
    settings = status["settings"] or {}
    rule = (tr(lang, "Hold {key} at the edge", key=status["preferences"]["modifier_key"].title())
            if settings.get("ctrl_key") else tr(lang, "Move the pointer to the edge"))
    hosts = {p["host_id"]: p["peer_ip"] for p in settings.get("peers", ())}
    lines = []
    for m in status["monitors"]:
        lines.append(f"{m['name']}   {m['width']} × {m['height']}   ({m['x']}, {m['y']})")
        for edge, target in m["routes"].items():
            lines.append(f"  {tr(lang, EDGES[edge])} → {hosts.get(target) or target} · {rule}")
        if not m["routes"]:
            lines.append("  " + tr(lang, "No crossing edges"))
    return "\n".join(lines) or tr(lang, "No local display information")


def box(vertical=False, spacing=8):
    return Gtk.Box(orientation=Gtk.Orientation.VERTICAL if vertical else Gtk.Orientation.HORIZONTAL,
                   spacing=spacing)


def padded(widget, n):
    for side in ("top", "bottom", "start", "end"):
        getattr(widget, "set_margin_" + side)(n)
    return widget


def label(text="", style=None):
    widget = Gtk.Label(label=text, xalign=0)
    if style:
        widget.add_css_class(style)
    return widget


def button(text, callback, style=None):
    widget = Gtk.Button(label=text)
    widget.connect("clicked", lambda *_: callback())
    if style:
        widget.add_css_class(style)
    return widget


def line(title_widget, control):
    row = box()
    title_widget.set_hexpand(True)
    row.append(title_widget)
    control.set_valign(Gtk.Align.CENTER)
    row.append(control)
    return row


def clear(widget):
    while child := widget.get_first_child():
        widget.remove(child)


def mini_layout(mode):
    grid = Gtk.Grid(column_spacing=2, row_spacing=2, halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
    for x, y in LAYOUT_GRID[mode]:
        pixel = Gtk.Box(width_request=5, height_request=4)
        pixel.add_css_class("wire")
        grid.attach(pixel, x, y, 1, 1)
    return grid


class Window(Adw.ApplicationWindow):
    def __init__(self, app, socket_path):
        super().__init__(application=app, title="Omarchy Flow", default_width=1110, default_height=750)
        self.add_css_class("flow")
        self.lang = load_ui_language()
        self.localized = []
        self.active_toasts = {}
        self.banner_message = "Connecting to the Flow service"
        self.control_error = ""
        self.client = ControlClient(socket_path)
        self.worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="flow-control")
        self.status = None
        self.mutation_generation = 0
        self.online = self.polling = self.busy = self.closed = self.refreshing = False
        self.canvas_key = None
        self.poll_timer = None

        root = box(True, 0)
        self.toasts = Adw.ToastOverlay(child=root)
        self.set_content(self.toasts)
        header = Adw.HeaderBar()
        header.set_title_widget(Gtk.Box())
        self.mouse = label("Omarchy Flow", "heading")
        self.connection = label(self.t("Connecting"), "pill")
        header.pack_start(self.mouse)
        header.pack_start(self.connection)
        self.master = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.master.connect("notify::active", lambda w, _: self.setting(on=w.get_active()))
        self.more = self.localize(Gtk.ToggleButton(), "More settings")
        header.pack_end(self.more)
        header.pack_end(self.master)
        header.pack_end(label("Flow", "heading"))
        root.append(header)
        self.banner = Adw.Banner(title=self.t(self.banner_message))
        self.localize(self.banner, "Retry connection", "set_button_label")
        self.banner.connect("button-clicked", self.retry)
        root.append(self.banner)
        self.split = Adw.OverlaySplitView(vexpand=True)
        self.split.set_sidebar_position(Gtk.PackType.END)
        self.split.set_min_sidebar_width(305)
        self.split.set_max_sidebar_width(340)
        self.split.set_show_sidebar(False)
        self.more.bind_property("active", self.split, "show-sidebar",
                                GObject.BindingFlags.BIDIRECTIONAL | GObject.BindingFlags.SYNC_CREATE)
        root.append(self.split)
        self.set_size_request(460, 420)
        breakpoint = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 900px"))
        breakpoint.add_setter(self.split, "collapsed", True)
        self.add_breakpoint(breakpoint)

        self.canvas = padded(box(True, 16), 20)
        self.canvas.add_css_class("canvas")
        canvas_scroll = Gtk.ScrolledWindow(child=self.canvas)
        self.split.set_content(canvas_scroll)
        self.cards = Gtk.Grid(halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER, vexpand=True)
        self.canvas.append(self.cards)
        self.canvas.append(self.static_label("Layout", "heading"))
        choices = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, homogeneous=True,
                              max_children_per_line=6, min_children_per_line=3, column_spacing=4)
        self.layout_buttons = {}
        for mode, title in LAYOUT_LABELS.items():
            b = Gtk.Button()
            b.add_css_class("layout")
            contents = box(spacing=5)
            contents.set_halign(Gtk.Align.CENTER)
            contents.append(mini_layout(mode))
            contents.append(self.static_label(title))
            b.set_child(contents)
            b.connect("clicked", lambda _, m=mode: self.setting(layout=m))
            self.layout_buttons[mode] = b
            choices.append(b)
        self.canvas.append(choices)
        panel = box(True)
        panel.add_css_class("panel")
        panel.append(self.static_label("Local displays and crossing edges", "heading"))
        self.monitors = label()
        self.monitors.set_wrap(True)
        panel.append(self.monitors)
        self.canvas.append(panel)
        self.drawer = self.make_drawer()
        self.split.set_sidebar(Gtk.ScrolledWindow(child=self.drawer))
        footer = padded(box(), 8)
        footer.add_css_class("footer")
        self.hardware = label("Bolt", "pill")
        footer.append(self.hardware)
        self.latest = label(self.t("Connecting"))
        self.latest.set_hexpand(True)
        self.latest.set_xalign(1)
        self.latest.set_ellipsize(3)
        footer.append(self.latest)
        root.append(footer)
        self.sensitivity()
        self.poll_timer = GLib.timeout_add(1500, self.poll)
        self.connect("close-request", self.shutdown)
        self.poll()

    def t(self, message, **values):
        return tr(self.lang, message, **values)

    def localize(self, widget, message, setter="set_label"):
        update = getattr(widget, setter)
        self.localized.append((update, message))
        update(self.t(message))
        return widget

    def static_label(self, message, style=None):
        return self.localize(label(style=style), message)

    def toast(self, message, **values):
        toast = Adw.Toast(title=self.t(message, **values), use_markup=False)
        self.active_toasts[toast] = (message, values)
        toast.connect("dismissed", lambda t: self.active_toasts.pop(t, None))
        self.toasts.add_toast(toast)

    def change_language(self, selector, _):
        lang = LANGUAGES[selector.get_selected()]
        if self.lang == lang:
            return
        try:
            save_ui_language(lang)
        except (OSError, ValueError):
            selector.set_selected(LANGUAGES.index(self.lang))
            self.toast("Could not save the language preference")
            return
        self.lang = lang
        for update, message in self.localized:
            update(self.t(message))
        for toast, (message, values) in self.active_toasts.items():
            toast.set_title(self.t(message, **values))
        self.refreshing = True
        selected = self.mod.get_selected()
        self.mod.set_model(Gtk.StringList.new([self.t(key) for key in MODIFIER_LABELS]))
        self.mod.set_selected(selected)
        self.refreshing = False
        if self.status:
            self.render(self.status)
        self.update_banner()
        if not self.online:
            self.latest.set_text(self.t("Service offline" if self.banner_message == "Cannot connect to the local Flow service"
                                        else "Connecting"))
        self.sensitivity()

    def update_banner(self):
        title = self.t(self.banner_message)
        if self.control_error:
            detail = CONTROL_ERRORS[self.control_error] if self.lang == "zh" else self.control_error
            title += " · " + detail
        self.banner.set_title(title)

    def make_drawer(self):
        drawer = padded(box(True, 10), 16)
        drawer.add_css_class("drawer")
        drawer.append(self.static_label("Flow settings", "title-2"))
        self.language = Gtk.DropDown.new_from_strings(["English", "中文"])
        self.language.set_selected(LANGUAGES.index(self.lang))
        self.language.connect("notify::selected", self.change_language)
        drawer.append(line(self.static_label("Language"), self.language))
        controls = box(True, 10)
        self.daemon_controls = controls
        drawer.append(controls)
        controls.append(self.static_label("Switch computers", "heading"))
        self.edge_only = self.localize(Gtk.CheckButton(), "Move the pointer to the edge")
        self.ctrl = self.localize(Gtk.CheckButton(), "Hold the modifier at the edge")
        self.ctrl.set_group(self.edge_only)
        for w, value in ((self.edge_only, False), (self.ctrl, True)):
            w.connect("toggled", lambda widget, v=value: widget.get_active() and self.setting(ctrl_key=v))
            controls.append(w)
        controls.append(self.static_label("Local modifier key", "heading"))
        self.mod = Gtk.DropDown.new_from_strings([self.t(key) for key in MODIFIER_LABELS])
        self.mod.connect("notify::selected", lambda w, _: not self.refreshing and self.action(
            "update_preferences", modifier_key=MODIFIERS[w.get_selected()]))
        controls.append(self.mod)
        controls.append(self.static_label("Edge gestures", "heading"))
        self.spins = {}
        for key, title, lo, hi, step in (("edge_threshold", "Edge pressure threshold", 5, 500, 1),
                                         ("edge_cooldown", "Switch cooldown (seconds)", .1, 5., .1)):
            spin = Gtk.SpinButton.new_with_range(lo, hi, step)
            spin.connect("value-changed", lambda w, k=key: self.action(
                "update_preferences", **{k: w.get_value_as_int() if k == "edge_threshold" else w.get_value()}))
            controls.append(line(self.static_label(title), spin))
            self.spins[key] = spin
        self.flags = {}
        for key, title in (("copy_paste", "Copy & Paste"), ("keyboard_link", "Keyboard Link")):
            w = Gtk.Switch()
            w.connect("notify::active", lambda switch, _, k=key: self.setting(**{k: switch.get_active()}))
            controls.append(line(self.static_label(title), w))
            self.flags[key] = w
            if key == "copy_paste":
                self.clipboard_note = label("", "dim-label")
                self.clipboard_note.set_wrap(True)
                controls.append(self.clipboard_note)
        self.keyboard = label()
        controls.append(self.keyboard)
        controls.append(self.localize(button("", lambda: self.action("rescan_devices")), "Rescan Bolt devices"))
        controls.append(Gtk.Separator())
        controls.append(self.static_label("Find other computers", "heading"))
        self.ip = self.localize(Gtk.Entry(), "Optional IP · 192.168.1.x", "set_placeholder_text")
        controls.append(self.ip)
        controls.append(self.localize(button("", self.discover), "Search local network"))
        controls.append(line(self.static_label("Reset Flow"),
                             self.localize(button("", self.confirm_reset, "destructive-action"), "Reset")))
        return drawer

    def discover(self):
        ip = self.ip.get_text().strip()
        self.action("discover_peers", force=True, **({"peer_ip": ip} if ip else {}))

    def confirm_reset(self):
        dialog = Adw.AlertDialog(
            heading=self.t("Reset Flow?"),
            body=self.t("Remove this computer from the layout and sync the change to connected computers."))
        dialog.add_response("cancel", self.t("Cancel"))
        dialog.add_response("reset", self.t("Reset"))
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _, response: response == "reset" and self.action("reset_flow"))
        dialog.present(self)

    def setting(self, **changes):
        if self.status and not self.refreshing:
            self.action("update_settings", **build_settings_update(self.status["settings"], **changes))

    def edit_card(self, op, *args):
        self.setting(peers=op(host_rows(self.status), *args))

    def card(self, row):
        i, host = row["slot"], row["host_id"]
        card = box(True, 3)
        card.add_css_class("peer-card")
        card.set_size_request(134, 80)
        if not host:
            card.add_css_class("empty")
            add = button(self.t("+ Add computer"), lambda: self.action("discover_peers", force=True), "flat")
            add.set_vexpand(True)
            card.append(add)
            return card
        local, enabled = row["is_local"], row["enabled"]
        if local or not enabled:
            card.add_css_class("local" if local else "disabled")
        title = box(spacing=3)
        name = label(host, "heading")
        name.set_max_width_chars(16)
        name.set_ellipsize(3)
        name.set_hexpand(True)
        title.append(name)
        menu = Gtk.MenuButton(icon_name="view-more-symbolic")
        menu.add_css_class("flat")
        actions = padded(box(True, 2), 4)
        for caption, callback, allowed in (
                ("Move earlier", partial(self.edit_card, move_peer_slot, i, i-1), i > 0),
                ("Move later", partial(self.edit_card, move_peer_slot, i, i+1), i < 2),
                ("Disable" if enabled else "Enable", partial(self.edit_card, toggle_peer_enabled, i), not local),
                ("Remove from Flow", partial(self.edit_card, remove_peer_slot, i), not local)):
            entry = button(self.t(caption), lambda cb=callback: (menu.popdown(), cb()), "flat")
            entry.set_sensitive(allowed)
            actions.append(entry)
        menu.set_popover(Gtk.Popover(child=actions))
        title.append(menu)
        card.append(title)
        state = ("Local · Connected" if local else "Disabled" if not enabled else
                 "Connected" if row["connected"] else "Offline")
        card.append(label(self.t(state), "connected" if row["connected"] and enabled and not local else None))
        card.append(label(row.get("peer_ip") or f"Ch {row['channel'] + 1}", "caption"))
        if not enabled:
            card.append(button(self.t("Enable"), partial(self.edit_card, toggle_peer_enabled, i), "primary"))
        return card

    def arrange(self, mode, rows):
        key = self.lang, mode, rows
        if key == self.canvas_key:
            return
        self.canvas_key = key
        clear(self.cards)
        positions = LAYOUT_GRID.get(mode, LAYOUT_GRID["horizontal"])
        for (x, y), row in zip(positions, rows):
            self.cards.attach(self.card(row), x*2, y*2, 1, 1)
        for (x, y), (u, v) in zip(positions, positions[1:]):
            horizontal = y == v
            wire = Gtk.Box(width_request=24 if horizontal else 2, height_request=2 if horizontal else 18,
                           halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
            wire.add_css_class("wire")
            self.cards.attach(wire, x+u, y+v, 1, 1)

    def render(self, data):
        self.status, self.refreshing = data, True
        try:
            settings = data["settings"] or {}
            prefs = data["preferences"]
            mouse = data["mouse"]["name"]
            mouse_name = self.t("Bolt mouse") if mouse == "Bolt mouse" else mouse
            self.mouse.set_text(mouse_name)
            local = next((p for p in host_rows(data) if p["is_local"]), {})
            participating = local.get("enabled") and bool(local.get("host_id"))
            self.master.set_active(bool(participating and settings.get("on", True)))
            self.connection.set_text(self.t("Connected" if participating else "This computer has not joined Flow"))
            self.ctrl.set_active(settings.get("ctrl_key", False))
            self.edge_only.set_active(not self.ctrl.get_active())
            self.mod.set_selected(MODIFIERS.index(prefs["modifier_key"]))
            self.mod.set_sensitive(self.ctrl.get_active())
            for k, w in self.spins.items():
                w.set_value(prefs[k])
            clip = data.get("clipboard", {})
            detail = (self.t("Transferring…") if clip.get("busy") else
                      display_summary(self.lang, clip.get("last_summary")))
            note = self.t("Copy text, images, files and folders in both directions")
            self.clipboard_note.set_text(note + ("\n" + detail if detail else ""))
            for k, w in self.flags.items():
                w.set_active(settings.get(k, False))
            mode = settings.get("layout", "horizontal")
            for k, w in self.layout_buttons.items():
                if k == mode:
                    w.add_css_class("selected")
                else:
                    w.remove_css_class("selected")
            self.arrange(mode, host_rows(data))
            self.monitors.set_text(monitor_lines(data, self.lang))
            keyboard = data.get("keyboard")
            keyboard_name = keyboard["name"] if keyboard else self.t("No paired keyboard found")
            if keyboard_name == "Bolt keyboard":
                keyboard_name = self.t("Bolt keyboard")
            self.keyboard.set_text(keyboard_name)
            linked = keyboard and settings.get("keyboard_link")
            self.hardware.set_text("Bolt · " + mouse_name +
                                   ("  +  " + keyboard_name if linked else " · " + self.t("Keyboard unlinked")))
            self.latest.set_text(display_event(self.lang, data["events"][-1]) if data["events"] else
                                 self.t("Connected to the Flow service"))
        finally:
            self.refreshing = False

    def sensitivity(self):
        for w in (self.canvas, self.daemon_controls, self.master):
            w.set_sensitive(self.online and not self.busy)
        if not self.online:
            self.connection.set_text(self.t("Offline"))

    def retry(self, *_):
        self.banner.set_revealed(False)
        self.poll()

    def poll(self):
        if not self.closed and not self.polling and not self.busy:
            self.polling = True
            self.request("get_status", {})
        return not self.closed

    def action(self, method, **params):
        if self.refreshing or self.busy or not self.online:
            return
        self.mutation_generation += 1
        self.busy = True
        self.sensitivity()
        self.request(method, params)

    def request(self, method, params):
        generation = self.mutation_generation
        future = self.worker.submit(self.client.call, method, **params)
        future.add_done_callback(lambda f: GLib.idle_add(self.complete, method, f, generation))

    def complete(self, method, future, generation):
        if self.closed:
            return False
        poll = method == "get_status"
        if poll:
            self.polling = False
            if self.busy or generation != self.mutation_generation:
                return False
        else:
            self.busy = False
        try:
            data = future.result()
        except ControlError as exc:
            if self.status:
                self.render(self.status)
            self.banner_message = "Action could not be completed"
            self.control_error = str(exc) if str(exc) in CONTROL_ERRORS else ""
            self.update_banner()
            self.banner.set_revealed(True)
        except (OSError, ValueError, KeyError):
            self.online = False
            self.banner_message = "Cannot connect to the local Flow service"
            self.control_error = ""
            self.update_banner()
            self.banner.set_revealed(True)
            self.latest.set_text(self.t("Service offline"))
        else:
            if not self.online or not poll:
                self.banner.set_revealed(False)
            self.online = True
            self.render(data)
            if data.get("delivery_errors"):
                peers = ", ".join(entry["host_id"] for entry in data["delivery_errors"])
                self.toast("Saved locally. No confirmation from {peers}.", peers=peers)
            if method == "rescan_devices":
                names = ", ".join(device["name"] for device in data["devices"])
                if names:
                    self.toast("Bolt · {names}", names=names)
                else:
                    self.toast("No paired devices found")
            elif method == "discover_peers":
                self.toast("Searching the local network")
        self.sensitivity()
        return False

    def shutdown(self, *_):
        self.closed = True
        if self.poll_timer:
            GLib.source_remove(self.poll_timer)
        self.client.close()
        self.worker.shutdown(wait=False, cancel_futures=True)
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-sock")
    args = parser.parse_args()
    app = Adw.Application(application_id="io.github.alexwangyang.OmarchyFlow", flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def activate(application):
        if not application.get_active_window():
            Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
            css = Gtk.CssProvider()
            css.load_from_string(CSS)
            Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css,
                                                     Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            win = Window(application, args.control_sock)
        else:
            win = application.get_active_window()
        win.present()

    app.connect("activate", activate)
    return app.run([])


if __name__ == "__main__":
    raise SystemExit(main())
