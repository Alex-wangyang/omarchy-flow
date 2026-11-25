"""UI preferences never enter the daemon's private settings or control protocol."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from flow_i18n import display_event, display_summary, load_ui_language, save_ui_language, ui_preferences_path


class LanguageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / "omarchy-flow" / "ui.json"

    def test_private_round_trip_and_rollback(self):
        self.assertEqual(load_ui_language(self.path), "en")
        self.assertFalse(self.path.parent.exists())
        self.path.parent.mkdir(mode=0o700)
        prefs = self.path.with_name("preferences.json")
        prefs.write_bytes(b'{"modifier_key":"super"}')
        for lang in ("zh", "en"):
            save_ui_language(lang, self.path)
            self.assertEqual(json.loads(self.path.read_text()), {"language": lang})
            self.assertEqual(load_ui_language(self.path), lang)
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            save_ui_language("de", self.path)
        self.assertEqual(prefs.read_bytes(), b'{"modifier_key":"super"}')

    def test_xdg_path(self):
        with patch.dict(os.environ, {"HOME": str(self.root), "XDG_CONFIG_HOME": str(self.root / "xdg")}):
            save_ui_language("zh")
            self.assertEqual(ui_preferences_path(), self.root / "xdg/omarchy-flow/ui.json")
            self.assertEqual(ui_preferences_path().parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(load_ui_language(), "zh")
            for value in ("relative", ""):
                os.environ["XDG_CONFIG_HOME"] = value
                self.assertEqual(ui_preferences_path(), self.root / ".config/omarchy-flow/ui.json")
                self.assertEqual(load_ui_language(), "en")

    def test_malformed_insecure_or_unsupported(self):
        save_ui_language("zh", self.path)
        for raw in (b"{", b"\xff", b"[]", b'{"language":[]}', b'{"language":"unknown"}', b" " * 1025):
            self.path.write_bytes(raw)
            self.assertEqual(load_ui_language(self.path), "en")
        save_ui_language("zh", self.path)
        self.path.chmod(0o644)
        self.assertEqual(load_ui_language(self.path), "en")
        self.path.chmod(0o600)
        self.path.parent.chmod(0o755)
        self.assertEqual(load_ui_language(self.path), "en")
        self.path.parent.chmod(0o700)
        alias = self.path.with_name("link")
        alias.symlink_to(self.path)
        self.assertEqual(load_ui_language(alias), "en")

    def test_only_public_measurements_are_translated(self):
        for raw, translated in (("text (12 B)", "文本 (12 B)"), ("image (20x30)", "图像 (20×30)"),
                                ("3 files (1.2 MiB)", "3 个文件 (1.2 MiB)"),
                                ("1 files offered", "已提供 1 个文件"),
                                ("file data served", "已发送文件数据")):
            for direction, prefix in (("IN", "剪贴板接收"), ("OUT", "剪贴板发送")):
                summary = "Clipboard " + direction + " · " + raw
                expected = "Clipboard " + direction + " · " + ("1 file offered" if raw == "1 files offered" else raw)
                self.assertEqual(display_summary("en", summary), expected)
                self.assertEqual(display_summary("zh", summary), prefix + " · " + translated)
                self.assertIsNone(display_summary("zh", summary + " secret"))

    def test_timestamped_events(self):
        stamp = "2026-01-01 12:34:56  "
        for raw, en, zh in (("Flow IN · LEFT · Ch 2", "Switched here · Left edge · Ch 2", "已切换到本机 · 左边缘 · Ch 2"),
                            ("Discovery · search", "Searching the local network", "正在搜索局域网电脑"),
                            ("Settings sync · 14", "Settings synced · 14", "设置已同步 · 14"),
                            ("Unrecognized event", "Flow activity", "Flow 活动")):
            self.assertEqual(display_event("en", stamp + raw), stamp + en)
            self.assertEqual(display_event("zh", stamp + raw), stamp + zh)
