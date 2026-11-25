"""Drive the bar CLI with a temporary control socket and without site packages."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flow_bar import project
from flow_i18n import save_ui_language

SCRIPT = Path(__file__).resolve().parents[1] / "src" / "flow_bar.py"


def status():
    return dict(host_id="Linux", local_channel=2, active_owner="Mac", mouse={"name": "MX"},
                keyboard={"name": "K865", "serial_number": "PRIVATE"}, secret="PRIVATE",
                settings={"on": True, "copy_paste": True, "keyboard_link": False, "ctrl_key": True,
                          "peers": [dict(host_id="Linux", is_local=True, enabled=True, connected=True),
                                    dict(host_id="Mac", is_local=False, enabled=True, connected=True,
                                         peer_ip="PRIVATE")]},
                preferences={"modifier_key": "super"}, events=[],
                clipboard={"enabled": True, "busy": False, "last_summary": "Clipboard IN · text (12 B)",
                           "text": "PRIVATE"})


class BarTests(unittest.TestCase):
    def setUp(self):
        base = "/tmp" if len(tempfile.gettempdir()) > 60 else None
        temp = tempfile.TemporaryDirectory(dir=base, prefix="ofb-")
        self.addCleanup(temp.cleanup)
        self.env = dict(os.environ, XDG_RUNTIME_DIR=temp.name, XDG_CONFIG_HOME=temp.name)
        self.path = Path(temp.name) / "omarchy-flow/control.sock"
        self.path.parent.mkdir(mode=0o700)

    def cli(self, *args):
        return subprocess.run([sys.executable, "-B", "-S", SCRIPT, *args], env=self.env,
                              text=True, capture_output=True, timeout=5)

    def exchange(self, args, method, params, reply, code=0):
        requests = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.path))
            server.listen(1)
            server.settimeout(4)

            def serve():
                conn, _ = server.accept()
                with conn, conn.makefile("rb") as stream:
                    requests.append(json.loads(stream.readline()))
                    conn.sendall(json.dumps(reply).encode() + b"\n")

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                result = self.cli(*args)
            finally:
                thread.join()
                self.path.unlink()
        self.assertEqual(requests, [{"method": method, "params": params}])
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertNotIn("PRIVATE", result.stdout)
        return json.loads(result.stdout)

    def test_status_status_only_and_projection(self):
        data = status()
        data["events"] = ["2026-11-25 10:20:30  Discovery · PRIVATE"] * 15
        out = self.exchange(["status"], "get_status", {}, {"result": data})
        self.assertEqual(out["language"], "en")
        self.assertEqual(out["events"], ["Discovery"] * 5)
        self.assertTrue(out["online"] and out["flow_on"])
        self.assertEqual(out["peers"], [{"host_id": "Mac", "enabled": True, "connected": True}])
        self.assertEqual((out["mouse"], out["keyboard"]), ("MX", "K865"))
        self.assertEqual(out["preferences"], {"modifier_key": "super"})
        self.assertEqual(out["clipboard"]["last_summary"], "Clipboard IN · text (12 B)")

    def test_missing_settings_and_local_membership(self):
        data = status()
        data["settings"]["peers"][0]["host_id"] = ""
        self.assertFalse(project(data)["flow_on"])
        data.update(settings=None, keyboard=None)
        out = project(data)
        self.assertTrue(out["flow_on"])
        self.assertEqual(out["peers"], [])
        self.assertEqual(out["keyboard"], "")

    def test_unrecognized_summary_events_and_display_limits(self):
        data = status()
        data.update(mouse={"name": "X\n" + "Y" * 200}, events=["not an event", "date  PRIVATE"])
        data["clipboard"]["last_summary"] = "Clipboard OUT · text (12 B) PRIVATE"
        out = project(data)
        self.assertIsNone(out["clipboard"]["last_summary"])
        self.assertEqual(out["events"], [])
        self.assertEqual(out["mouse"], "X " + "Y" * 62)

    def test_set_only_requested_field_and_partial_delivery(self):
        data = status()
        data["delivery_errors"] = [{"error": "PRIVATE"}]
        out = self.exchange(["set-setting", "copy_paste", "off"], "update_settings",
                            {"copy_paste": False}, {"result": data})
        self.assertTrue(out["online"])
        self.assertIn("peer", out["notice"])
        self.assertNotEqual(self.cli("set-setting", "peers", "on").returncode, 0)
        self.assertNotEqual(self.cli("set-setting", "on", "invalid").returncode, 0)

    def test_rescan_and_rejected_action(self):
        self.assertTrue(self.exchange(["rescan"], "rescan_devices", {},
                                      {"result": status()})["online"])
        out = self.exchange(["rescan"], "rescan_devices", {}, {"error": "PRIVATE"}, code=1)
        self.assertIn("unconfirmed", out["notice"])

    def test_chinese_status_and_notices(self):
        save_ui_language("zh", self.path.with_name("ui.json"))
        data = status()
        out = self.exchange(["status"], "get_status", {}, {"result": data})
        self.assertEqual(out["language"], "zh")
        self.assertEqual(out["clipboard"]["last_summary"], "Clipboard IN · text (12 B)")
        self.assertEqual(out["clipboard"]["display_summary"], "剪贴板接收 · 文本 (12 B)")
        data["delivery_errors"] = [{"error": "PRIVATE"}]
        out = self.exchange(["set-setting", "on", "on"], "update_settings", {"on": True}, {"result": data})
        self.assertIn("尚未确认", out["notice"])
        error = self.exchange(["rescan"], "rescan_devices", {}, {"error": "PRIVATE"}, code=1)
        self.assertEqual(error, {"language": "zh", "notice": "操作尚未确认。正在刷新状态。"})
        self.assertEqual(json.loads(self.cli("status").stdout), {"online": False, "language": "zh"})

    def test_offline_is_quiet(self):
        result = self.cli("status")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {"online": False, "language": "en"})
