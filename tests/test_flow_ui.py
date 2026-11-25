"""Exercise the installed system GTK bindings without using the user's display."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


class SystemGtkTests(unittest.TestCase):
    python = "/usr/bin/python3"

    @classmethod
    def setUpClass(cls):
        probe = "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1'); from gi.repository import Gtk, Adw"
        if not Path(cls.python).exists() or subprocess.run(
                [cls.python, "-c", probe], capture_output=True).returncode:
            raise unittest.SkipTest("system GTK4/Libadwaita unavailable")

    def test_import_and_status_model_without_crypto_or_display(self):
        subprocess.run([self.python, "-B", "-c", """
import sys
sys.modules['cryptography'] = None
import flow_ui as ui
s = dict(settings=None, host_id='Linux', local_channel=2, monitors=[],
         preferences={'modifier_key':'super'})
rows = ui.host_rows(s)
assert [p['is_local'] for p in rows] == [False, False, True]
assert len(ui.monitor_lines(s)) > 0
rows[0].update(host_id='Mac', peer_ip='192.0.2.1')
s.update(settings={'ctrl_key':True, 'peers':rows},
         monitors=[dict(name='eDP-1', x=10, y=-5, width=100, height=200, routes={'LEFT':'Mac'})])
assert ui.host_rows(s) == rows
lines = ui.monitor_lines(s)
assert all(t in lines for t in ('eDP-1', '(10, -5)', 'Left edge → 192.0.2.1', 'Super'))
assert '左边缘 → 192.0.2.1' in ui.monitor_lines(s, "zh")
"""], check=True, cwd=Path(__file__).resolve().parents[1] / "src")

    @unittest.skipUnless(shutil.which("gtk4-broadwayd"), "headless GTK Broadway unavailable")
    def test_window_poll_offline_and_render_all_layouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, XDG_RUNTIME_DIR=tmp, GDK_BACKEND="broadway", BROADWAY_DISPLAY=":71",
                       XDG_CONFIG_HOME=tmp, GTK_A11Y="none", GSETTINGS_BACKEND="memory", XDG_CACHE_HOME=tmp)
            with subprocess.Popen(["gtk4-broadwayd", "-u", tmp + "/web.sock", ":71"], env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as backend:
                try:
                    for _ in range(100):
                        if (Path(tmp)/"web.sock").exists() or backend.poll() is not None:
                            break
                        time.sleep(.01)
                    proc = subprocess.run([self.python, "-B", "-c", """
import json, os, socket, threading, time
from pathlib import Path
import flow_ui as ui
from flow_control import DEFAULTS
ui.Adw.init()
app = ui.Adw.Application(application_id='io.github.alexwangyang.OmarchyFlow', flags=ui.Gio.ApplicationFlags.NON_UNIQUE)
assert app.register(None)
path = Path(os.environ['XDG_RUNTIME_DIR'])/'control.sock'
w = ui.Window(app, path)
w.present()
loop = ui.GLib.MainContext.default()
deadline = time.monotonic() + 2
while w.polling and time.monotonic() < deadline:
    loop.iteration(False)
    time.sleep(.005)
assert not w.online and w.banner.get_revealed()
w.more.set_active(True)
assert w.split.get_show_sidebar()
assert w.language.is_sensitive() and not w.daemon_controls.is_sensitive()
assert w.lang == 'en' and w.banner.get_title() == 'Cannot connect to the local Flow service'
assert w.latest.get_text() == 'Service offline'
w.ip.set_text('192.0.2.4')
w.language.set_selected(1)
assert w.banner.get_title() == '无法连接本机 Flow 服务' and w.latest.get_text() == '服务离线'
assert w.more.get_label() == '更多设置' and w.banner.get_button_label() == '重试连接'
assert w.ip.get_text() == '192.0.2.4' and w.ip.get_placeholder_text() == '可选 IP · 192.168.1.x'
assert ui.load_ui_language() == 'zh' and w.mutation_generation == 0
from unittest.mock import patch
with patch.object(ui, 'save_ui_language', side_effect=PermissionError):
    w.language.set_selected(0)
    assert w.lang == 'zh' and w.language.get_selected() == 1
    assert '无法保存语言设置' in [t.get_title() for t in w.active_toasts]
data = dict(settings=None, host_id='Omarchy', local_channel=1, mouse={'name':'MX'},
            keyboard={'name':'K865'}, preferences=dict(DEFAULTS), monitors=[], events=['2026-01-01 12:34:56  Flow IN · LEFT · Ch 2'])
rows = ui.host_rows(data)
rows[0].update(host_id='Mac', enabled=False)
for mode in ui.LAYOUT_GRID:
    data['settings'] = dict(layout=mode, peers=rows, on=True, ctrl_key=True, keyboard_link=True)
    w.render(data)
    assert w.master.get_active() and w.mod.get_sensitive()
    assert w.layout_buttons[mode].has_css_class('selected')
    for x,y in ui.LAYOUT_GRID[mode]:
        assert w.cards.get_child_at(2*x,2*y).has_css_class('peer-card')
assert 'K865' in w.hardware.get_text()
data['clipboard'] = {'enabled':True, 'busy':True, 'last_summary':None}
w.render(data)
assert '传输中' in w.clipboard_note.get_text()
data['clipboard'].update(busy=False, last_summary='Clipboard IN · text (12 B)')
w.render(data)
assert '文件夹' in w.clipboard_note.get_text() and '(12 B)' in w.clipboard_note.get_text()
calls = []
# The first poll connects to a missing path. The same window recovers and edits
# settings once a local server appears; no real desktop or Flow peer is used.
with socket.socket(socket.AF_UNIX) as listener:
    listener.bind(str(path))
    listener.listen(2)
    listener.settimeout(3)
    def serve():
        for _ in range(2):
            conn, _ = listener.accept()
            with conn, conn.makefile("rb") as r:
                req = json.loads(r.readline())
                calls.append(req)
                if req['method'] == 'update_settings':
                    data['settings']['on'] = req['params']['on']
                conn.sendall((json.dumps({'result': data}) + chr(10)).encode())
    data['settings']['counter'] = 17
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    def wait_for(condition):
        deadline = time.monotonic() + 2
        while not condition() and time.monotonic() < deadline:
            loop.iteration(False)
            time.sleep(.002)
        assert condition()
    w.retry()
    wait_for(lambda: w.online and not w.polling)
    assert not w.banner.get_revealed()
    def labels(widget):
        if isinstance(widget, ui.Gtk.Label):
            yield widget.get_text()
        child = widget.get_first_child()
        while child:
            yield from labels(child)
            child = child.get_next_sibling()
    w.toast("Searching the local network")
    for index, more, empty, layout, summary, event, toast in (
            (0, 'More settings', '+ Add computer', 'Top left', 'text (12 B)', 'Left edge', 'Searching the local network'),
            (1, '更多设置', '+ 添加电脑', '左上', '文本 (12 B)', '左边缘', '正在搜索局域网电脑')):
        w.language.set_selected(index)
        assert w.more.get_label() == more and empty in set(labels(w.cards))
        assert layout in set(labels(w.layout_buttons['left-top']))
        assert summary in w.clipboard_note.get_text() and event in w.latest.get_text()
        assert toast in [t.get_title() for t in w.active_toasts]
        assert w.mutation_generation == 0 and not w.busy
    w.master.set_active(False)
    wait_for(lambda: not w.busy)
    assert calls == [dict(method="get_status", params={}),
                     dict(method="update_settings", params=dict(expected_counter=17, on=False))]
    assert not w.status['settings']['on']
    t.join(2)
    from concurrent.futures import Future
    stale = Future()
    stale.set_result({**data, 'settings': {**data['settings'], 'on': True}})
    w.polling = True
    w.complete('get_status', stale, w.mutation_generation - 1)
    assert not w.polling and not w.master.get_active()
    rows[1].update(host_id='', enabled=False)
    w.render({**data, 'settings': {**data['settings'], 'on': True, 'peers': rows}})
    w.sensitivity()
    assert not w.master.get_active() and w.connection.get_text() == '本机未加入 Flow'
w.close()
assert w.client.closed
reopened = ui.Window(app, path)
reopened.present()
assert reopened.lang == 'zh' and reopened.language.get_selected() == 1
assert reopened.more.get_label() == '更多设置'
reopened.close()
"""], env=env, cwd=Path(__file__).resolve().parents[1] / "src", text=True, capture_output=True, timeout=8)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertNotIn("Traceback", proc.stderr)
                    self.assertNotIn("CRITICAL", proc.stderr)
                finally:
                    backend.terminate()
                    backend.wait(timeout=2)
