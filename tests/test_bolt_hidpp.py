import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

import bolt_hidpp as hid
import flow_daemon


class BoltTests(unittest.TestCase):
    def setUp(self):
        self.device, self.receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(self.device.close)
        self.addCleanup(self.receiver.close)
        self.receiver.settimeout(0.3)
        self.fd = self.device.fileno()
        self.requests = []

    def test_default_state_and_provision_cli_follow_xdg(self):
        with tempfile.TemporaryDirectory() as tmp:
            for setting, parent in ((tmp, Path(tmp)), ("relative", Path.home() / ".config")):
                with self.subTest(setting=setting), patch.dict(os.environ, XDG_CONFIG_HOME=setting):
                    expected = parent / "omarchy-flow" / "state.json"
                    self.assertEqual(hid.default_state_path(), expected)
                    with patch.object(flow_daemon, "provision_local_devices", return_value={}) as provision:
                        with contextlib.redirect_stdout(io.StringIO()):
                            flow_daemon.main(["provision"])
                        provision.assert_called_once_with(expected, None, clear_password=False)

    def feature(self, slot, index, func, request, response):
        header = bytes([0x11, slot, index, func << 4 | 14])
        self.requests.append(header + request.ljust(16, b"\0"))
        if response is not None:
            self.receiver.send(header + response.ljust(16, b"\0"))

    def root(self, slot, feature, index):
        self.feature(slot, 0, 0, feature.to_bytes(2, "big"), bytes([index]))

    def device_info(self, slot, payload_hex="03 10203040 00 02 b035 00000000000100"):
        self.root(slot, 3, 8)
        self.feature(slot, 8, 0, b"", bytes.fromhex(payload_hex))

    def verify_requests(self):
        for expected in self.requests:
            self.assertEqual(self.receiver.recv(64), expected)
        self.assertFalse(hid.select.select([self.receiver], [], [], 0)[0])

    def test_device_info_transport_order(self):
        # BLE / Logi Bolt single-transport mouse & keyboard (0x0002).
        self.device_info(2, "03 11223344 00 02 b035 00000000000100")
        self.assertEqual(hid.read_device_info(self.fd, 2),
                         {"device_id": 0x02b035, "serial_number": 0x11223344})
        self.device_info(1, "03 55667788 00 02 b381 00000000000100")
        self.assertEqual(hid.read_device_info(self.fd, 1),
                         {"device_id": 0x02b381, "serial_number": 0x55667788})
        # BT + BLE (0x0003): BLE model ID is second 2-byte slot.
        self.device_info(2, "01 10203040 00 03 aabb c123 0000")
        self.assertEqual(hid.read_device_info(self.fd, 2),
                         {"device_id": 0x02c123, "serial_number": 0x10203040})
        # eQuad only (0x0004): eQuad model ID is first 2-byte slot.
        self.device_info(2, "01 10203040 00 04 4099 0000 0000")
        self.assertEqual(hid.read_device_info(self.fd, 2),
                         {"device_id": 0x024099, "serial_number": 0x10203040})
        self.verify_requests()

    def test_pairing_register_fallback(self):
        self.root(2, 3, 0)
        self.requests.append(bytes.fromhex("10 ff 83 b5 52 00 00"))
        self.receiver.send(bytes.fromhex("11 ff 83 b5 52 02 23 c1 10 20 30 40") + bytes(8))
        self.assertEqual(hid.read_device_info(self.fd, 2),
                         {"device_id": 0x2c123, "serial_number": 0x10203040})
        self.verify_requests()

    def test_switch_resolves_replaced_slot_and_rediscovers_path(self):
        from flow_switcher import Switcher
        device = {"device_id": 0x2b035, "serial_number": 12, "slot": 2}
        switcher = Switcher({"mouse": device})
        paths = iter((["first"], ["second"]))
        identity = {"device_id": 0x2b035, "serial_number": 12}
        def info(fd, slot):
            return identity if slot == 3 else {}
        with patch("flow_switcher.bolt_receivers", side_effect=lambda: next(paths)), \
             patch("flow_switcher._pairing_info", side_effect=lambda fd, slot: (0xb035, slot*4)), \
             patch("flow_switcher.read_device_info", side_effect=info), \
             patch("os.open", side_effect=[10,11]) as opened, patch("os.close"), \
             patch("flow_switcher.set_current_host") as switch:
            for target in (1,0):
                switcher.switch("mouse",target)
            self.assertEqual([c.args for c in switch.call_args_list], [(10,3,1),(11,3,0)])
            self.assertEqual([c.args[0] for c in opened.call_args_list], ["first","second"])
        with patch("os.open") as opened:
            Switcher({"mouse":device}, dry_run=True).switch("mouse",1)
            opened.assert_not_called()

    def test_switch_fast_path_reuses_verified_change_host_and_checks_pairing_record(self):
        from flow_switcher import Switcher
        switcher = Switcher({"keyboard": {"device_id": 0x2b381, "serial_number": 0x11223344, "slot": 1}})
        pairing = {1: (0xb381, 0x11223344)}
        def pairing_info(fd, slot):
            if slot not in pairing:
                raise OSError("empty slot")
            return pairing[slot]
        # First switch verifies live identity and learns feature 0x1814 index + host count.
        token = hid.SOFTWARE_ID.set(0x0D)
        try:
            self.receiver.send(bytes([0x11, 1, 0, 0x0D, 8]).ljust(20, b"\0"))
            self.receiver.send(bytes([0x11, 1, 8, 0x0D]) + bytes.fromhex("03 11223344 00 02 b381 00000000000100"))
            self.receiver.send(bytes([0x11, 1, 0, 0x0D, 9]).ljust(20, b"\0"))
            self.receiver.send(bytes([0x11, 1, 9, 0x0D, 3, 2]).ljust(20, b"\0"))
            self.requests.extend([
                bytes([0x11, 1, 0, 0x0D, 0, 3]).ljust(20, b"\0"),
                bytes([0x11, 1, 8, 0x0D]).ljust(20, b"\0"),
                bytes([0x11, 1, 0, 0x0D, 0x18, 0x14]).ljust(20, b"\0"),
                bytes([0x11, 1, 9, 0x0D]).ljust(20, b"\0"),
                bytes([0x11, 1, 9, 0x1D, 1]).ljust(20, b"\0"),
            ])
            with patch("flow_switcher.bolt_receivers", return_value=["/dev/hidraw0"]), \
                 patch("flow_switcher._pairing_info", side_effect=pairing_info), \
                 patch("os.open", return_value=self.fd), patch("os.close"):
                self.assertTrue(switcher.switch("keyboard", 1))
                # Second switch checks only local pairing register and sends one SetCurrentHost packet.
                self.requests.append(bytes([0x11, 1, 9, 0x1D, 0]).ljust(20, b"\0"))
                with patch("flow_switcher.read_device_info", side_effect=AssertionError("unexpected RF query")):
                    self.assertTrue(switcher.switch("keyboard", 0))
                # Out-of-range channel rejects and evicts cached feature metadata.
                with self.assertRaises(ValueError):
                    switcher.switch("keyboard", 3)
                self.assertEqual(switcher._verified, {})
                # Re-paired slot change falls back to scan and re-learns on the new slot.
                pairing.clear()
                pairing[4] = (0xb381, 0x11223344)
                self.receiver.send(bytes([0x11, 4, 0, 0x0D, 8]).ljust(20, b"\0"))
                self.receiver.send(bytes([0x11, 4, 8, 0x0D]) + bytes.fromhex("03 11223344 00 02 b381 00000000000100"))
                self.receiver.send(bytes([0x11, 4, 0, 0x0D, 9]).ljust(20, b"\0"))
                self.receiver.send(bytes([0x11, 4, 9, 0x0D, 3, 2]).ljust(20, b"\0"))
                self.requests.extend([
                    bytes([0x11, 4, 0, 0x0D, 0, 3]).ljust(20, b"\0"),
                    bytes([0x11, 4, 8, 0x0D]).ljust(20, b"\0"),
                    bytes([0x11, 4, 0, 0x0D, 0x18, 0x14]).ljust(20, b"\0"),
                    bytes([0x11, 4, 9, 0x0D]).ljust(20, b"\0"),
                    bytes([0x11, 4, 9, 0x1D, 1]).ljust(20, b"\0"),
                ])
                with patch("flow_switcher.read_device_info", side_effect=lambda fd, slot:
                           hid.read_device_info(fd, slot) if slot == 4 else (_ for _ in ()).throw(OSError("empty"))):
                    self.assertTrue(switcher.switch("keyboard", 1))
                self.assertEqual(switcher.devices["keyboard"]["slot"], 4)
        finally:
            hid.SOFTWARE_ID.reset(token)
        self.verify_requests()

    def identifier(self):
        self.root(2, 0x21, 7)
        for part in (0, 1):
            self.feature(2, 7, part, b"", bytes(range(part * 16, (part+1) * 16)))

    def test_identifier_halves_and_lowercase(self):
        self.identifier()
        self.assertTrue(hid.read_crypto_identifier(self.fd, 2) == bytes(range(32)).hex())
        self.verify_requests()

    def host_info(self, slot, current=2):
        self.root(slot, 0x1814, 9)
        self.feature(slot, 9, 0, b"", bytes([3, current]))

    def test_get_and_explicit_set_current_host(self):
        self.host_info(1)
        self.assertEqual(hid.get_host_info(self.fd, 1), (3, 2))
        self.host_info(1)
        self.feature(1, 9, 1, b"\x01", None)
        self.assertIsNone(hid.set_current_host(self.fd, 1, 1))
        self.host_info(1)
        with self.assertRaises(ValueError):
            hid.set_current_host(self.fd, 1, 3)
        self.verify_requests()

    def test_unrelated_reports_and_errors(self):
        self.receiver.send(bytes.fromhex("10 01 00 00 ff ff ff"))
        self.root(2, 0x21, 0)
        self.assertIsNone(hid.get_feature_index(self.fd, 2, 0x21))
        self.receiver.send(bytes.fromhex("11 02 ff 00 0e 07") + bytes(14))
        with self.assertRaises(OSError):
            hid.get_feature_index(self.fd, 2, 3)

    def paired(self, slot, name):
        self.requests.append(bytes([16, 255, 131, 181, 96+slot, 1, 0]))
        if name:
            self.receiver.send(bytes([17, 255, 131, 181, 96+slot, 1, len(name)]) + name.ljust(13, b"\0"))
        else:
            self.receiver.send(bytes([16, 255, 143, 131, 181, 8, 0]))

    def test_provision_cli_private_state_and_redacted_output(self):
        for slot, name in ((1, b"keyboard"), (2, b"mouse")):
            self.paired(slot, name)
            self.root(slot, 0x1814, 9)
            self.root(slot, 0x21, 7 if slot == 2 else 0)
            self.device_info(slot)
            self.host_info(slot)
            if slot == 2:
                self.identifier()
        for slot in range(3, 7):
            self.paired(slot, b"")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config/state.json"
            output = io.StringIO()
            def injected(config, host, **options):
                return hid.provision_local_devices(config, host, fd=self.fd, **options)
            with patch.object(flow_daemon, "provision_local_devices", side_effect=injected):
                with contextlib.redirect_stdout(output):
                    flow_daemon.main(["provision", "--config", str(path), "--host-id", "Linux"])
            self.assertFalse(bytes(range(32)).hex() in output.getvalue())
            info = json.loads(output.getvalue())
            self.assertTrue(info["mouse"]["has_random"])
            self.assertFalse(info["keyboard"]["has_random"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            state = flow_daemon.load_state(path)
            self.assertTrue(state["mouse"]["random"] == bytes(range(32)).hex())
            self.assertEqual(state["keyboard"]["channel"], 2)
            self.assertEqual(state["host_id"], "Linux")
            self.verify_requests()
            with patch.object(hid, "_read_slots", side_effect=TimeoutError):
                with self.assertRaises(TimeoutError):
                    hid.provision_local_devices(path, fd=self.fd)
            self.assertTrue(flow_daemon.load_state(path) == state)
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                flow_daemon.load_state(path)


class InventoryTests(unittest.TestCase):
    def test_explicit_hidraw_must_be_a_management_interface(self):
        with patch("pathlib.Path.resolve", return_value=Path("/dev/input/event2")), \
             patch.object(hid, "bolt_receivers", return_value=[Path("/dev/hidraw5")]), \
             patch("os.open") as opened:
            with self.assertRaises(ValueError):
                hid.inventory_bolt_devices("/dev/input/event2")
            opened.assert_not_called()

    def test_inventory_multifragment_name_and_deadline(self):
        first = bytes([15]) + b"123456789abcd"
        with patch.object(hid, "read_name_part", side_effect=[first, b"ef" + bytes(12)]):
            self.assertEqual(hid._inventory_slot(1, 2)["name"], "123456789abcdef")
        with patch.object(hid, "time") as clock, patch.object(hid, "read_name_part",
                return_value=first) as read:
            clock.monotonic.side_effect = [3, 5]
            token = hid._SCAN_DEADLINE.set(4)
            try:
                with self.assertRaises(TimeoutError):
                    hid._inventory_slot(1, 2)
            finally:
                hid._SCAN_DEADLINE.reset(token)
            read.assert_called_once_with(1, 2, 1)

    def test_device_name_uses_byte_offsets(self):
        pieces = [bytes([20]), b"1234567890123456", b"7890".ljust(16, b"\0")]
        with patch.object(hid, "_required_feature", return_value=5) as feature, \
             patch.object(hid, "_feature", side_effect=pieces) as read:
            self.assertEqual(hid._device_name(1, 2), "12345678901234567890")
            feature.assert_called_once_with(1, 2, 5)
            self.assertEqual([c.args for c in read.call_args_list],
                             [(1, 2, 5, 0), (1, 2, 5, 1, b"\0"), (1, 2, 5, 1, b"\x10")])

    def test_offline_and_online_inventory_never_reads_secrets(self):
        rows = [{"status": "paired", "name": "Bolt keyboard"},
                {"status": "paired", "name": "Bolt mouse"}, {"status": "timeout"}]
        with patch.object(hid, "bolt_path", return_value="/receiver"), patch("os.open", return_value=11), \
             patch("os.close") as close, \
             patch.object(hid, "_inventory_slot", side_effect=rows), \
             patch.object(hid, "_pairing_record", side_effect=[bytes.fromhex("510181b300000001"),
                                                              bytes.fromhex("520235b000000002")]), \
             patch.object(hid, "_device_name", side_effect=[OSError(), "MX Master"]), \
             patch.object(hid, "get_host_info", side_effect=[OSError(), (3, 2)]), \
             patch.object(hid, "read_crypto_identifier") as crypto, \
             patch.object(hid, "set_current_host") as switch:
            devices = hid.inventory_bolt_devices("/receiver")
        self.assertEqual(devices, [
            dict(name="Bolt keyboard", channel=None, slot=1, kind="keyboard", serial_number=1, device_id=0x2b381),
            dict(name="MX Master", channel=2, slot=2, kind="mouse", serial_number=2, device_id=0x2b035)])
        crypto.assert_not_called()
        switch.assert_not_called()
        close.assert_called_once_with(11)


class ProvisionSafetyTests(unittest.TestCase):
    def test_reserved_paths_fail_before_receiver_access(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(hid, "bolt_receivers") as receivers:
            root = Path(tmp)
            alias = root / "state.json"
            alias.symlink_to(root / "preferences.json")
            for path in (root / "preferences.json", root / "control.sock", alias):
                for mode in ("provision", "run"):
                    with self.subTest(mode=mode, name=path.name), contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit):
                            flow_daemon.main([mode, "--config", str(path)])
            receivers.assert_not_called()

    def test_password_survives_reprovision_and_clear_is_explicit(self):
        from test_flow_daemon import STATE
        with tempfile.TemporaryDirectory() as tmp, patch.object(hid, "_provision_devices",
                return_value={"mouse": {**STATE["mouse"], "slot": 2}}) as reader:
            path = Path(tmp) / "state.json"
            path.write_text(json.dumps({**STATE, "password": "sample-pass"}))
            path.chmod(0o600)
            summary = hid.provision_local_devices(path)
            self.assertFalse("sample-pass" in json.dumps(summary), "secret leaked")
            self.assertTrue(hid.load_state(path)["password"] == "sample-pass", "password changed")
            with contextlib.redirect_stdout(io.StringIO()):
                flow_daemon.main(["provision", "--config", str(path), "--clear-password"])
            self.assertFalse("password" in hid.load_state(path))
            path.write_text('{"password": 42}')
            reader.reset_mock()
            with self.assertRaises(ValueError):
                hid.provision_local_devices(path)
            reader.assert_not_called()

    def test_hidraw_provision_open_does_not_follow_links(self):
        with patch.object(hid, "bolt_receivers", return_value=["device"]), \
                patch("os.open", side_effect=OSError) as op, self.assertRaises(OSError):
            hid._provision_devices(None)
        self.assertTrue(op.call_args.args[1] & os.O_NOFOLLOW)


class RetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_keyboard_recovers_once(self):
        from flow_switcher import Switcher
        s = Switcher({})
        with patch.object(s, "switch", side_effect=[True, OSError("receiver busy"), True]) as switch, \
             self.assertLogs("omarchy-flow", level="WARNING") as log:
            s.submit_crossing(1, 2)
            await s.task
        self.assertIn("keyboard switch unavailable (OSError)", log.output[0])
        self.assertEqual([c.args for c in switch.call_args_list], [("mouse", 1, 1)] + [("keyboard", 2, 1)] * 2)

    async def test_failed_mouse_never_starts_keyboard(self):
        from flow_switcher import Switcher
        s = Switcher({})
        with patch.object(s, "switch", side_effect=OSError) as switch:
            s.submit_crossing(1, 2)
            await s.task
        self.assertEqual([c.args for c in switch.call_args_list], [("mouse", 1, 1)] * 2)

    async def test_new_crossing_supersedes_pending_mouse_retry_and_keyboard(self):
        from flow_switcher import Switcher
        import threading
        s = Switcher({})
        started, release = threading.Event(), threading.Event()
        def hardware(role, channel, generation):
            if generation == 1:
                started.set()
                release.wait(2)
                raise OSError()
            return True
        with patch.object(s, "switch", side_effect=hardware) as switch:
            s.submit_crossing(1, 2)
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 1))
                s.submit_crossing(0, 1)
            finally:
                release.set()
                await s.task
        self.assertEqual([c.args for c in switch.call_args_list],
                         [("mouse", 1, 1), ("mouse", 0, 2), ("keyboard", 1, 2)])

    def test_invalidated_after_feature_query_skips_final_hid_write(self):
        from flow_switcher import Switcher, StaleCrossing
        s = Switcher({})
        def last_query(*args):
            s.invalidate()
            return bytes([3, 0])
        with patch.object(hid, "_required_feature", return_value=7), \
                patch.object(hid, "_feature", side_effect=last_query) as feature, self.assertRaises(StaleCrossing):
            hid.set_current_host(1, 2, 1, guard=s.write_guard(s.generation))
        feature.assert_called_once_with(1, 2, 7, 0)

    async def test_close_suppresses_retry(self):
        from flow_switcher import Switcher
        s = Switcher({})
        def unavailable(*args):
            s.closed.set()
            raise OSError("gone")
        with patch.object(s, "switch", side_effect=unavailable) as switch, \
             self.assertLogs("omarchy-flow", level="WARNING"):
            s.submit_crossing(1, 2)
            await s.task
        switch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
