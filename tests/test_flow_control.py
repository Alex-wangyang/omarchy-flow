import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

import flow_control as control
from flow_daemon import FlowDaemon, LAYOUTS, Tunnel
from hyprland_edges import Edge, Monitor, MouseEdges
from marconi_packets import BeaconPacket, InitiateDiscoveryPacket, Peer, SettingsPacket
from test_flow_daemon import STATE


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.rows = [dict(channel=i, slot=i, host_id=name, enabled=True, is_local=i == 2,
                          connected=True, peer_ip=None, keyboard_channel=i)
                     for i, name in enumerate(("Mac", "Other", "Linux"))]

    def test_six_layouts_match_wire_routes(self):
        deltas = {Edge.LEFT: (-1, 0), Edge.RIGHT: (1, 0), Edge.TOP: (0, -1), Edge.BOTTOM: (0, 1)}
        self.assertEqual(set(control.LAYOUT_GRID), {k.decode() for k in LAYOUTS})
        for layout, directions in LAYOUTS.items():
            coords = control.LAYOUT_GRID[layout.decode()]
            self.assertEqual(tuple((b[0]-a[0], b[1]-a[1]) for a, b in zip(coords, coords[1:])),
                             tuple(deltas[e] for e in directions))

    def test_slot_operators_and_wire_patch(self):
        rows = self.rows
        swapped = control.swap_peer_slots(rows, 0, 2)
        self.assertEqual([r["channel"] for r in swapped], [2, 1, 0])
        moved = control.move_peer_slot(rows, 0, 2)
        self.assertEqual([r["channel"] for r in moved], [1, 2, 0])
        disabled = control.toggle_peer_enabled(moved, 2)
        removed = control.remove_peer_slot(disabled, 2)
        self.assertFalse(disabled[2]["enabled"])
        self.assertEqual(removed[2]["host_id"], "")
        self.assertEqual([r["slot"] for r in removed], [0, 1, 2])
        update = control.build_settings_update({"counter": 19}, peers=removed, ctrl_key=True)
        self.assertEqual(update["expected_counter"], 19)
        self.assertTrue(update["ctrl_key"])
        self.assertEqual(update["peers"][2], {"channel": 0, "host_id": "", "enabled": False})
        self.assertEqual(rows[0]["host_id"], "Mac")
        self.assertTrue(rows[0]["enabled"])

    def test_invalid_actions(self):
        for op in (control.toggle_peer_enabled, control.remove_peer_slot):
            with self.assertRaises(control.ControlError):
                op(self.rows, 2)
        for i in (-1, 3, True):
            with self.assertRaises(control.ControlError):
                control.move_peer_slot(self.rows, i, 1)

    def test_load_defaults_explicit_override_and_file_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private/preferences.json"
            self.assertEqual(control.load_preferences(path, {}), control.DEFAULTS)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            control.load_preferences(path, {"modifier_key": "alt"})
            self.assertEqual(control.load_preferences(path, {})["modifier_key"], "alt")
            other = path.with_suffix(".link")
            other.symlink_to(path)
            with self.assertRaises(OSError):
                control.load_preferences(other, {})
            with self.assertRaises(ValueError):
                control.save_preferences(other, control.DEFAULTS)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                control.load_preferences(path, {})
            self.assertTrue(other.is_symlink())


    def test_invalid_state_exception_has_no_json_document(self):
        from flow_daemon import load_state
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text('{"password": "private-test-password",')
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "^invalid state file$") as error:
                load_state(path)
            self.assertFalse(hasattr(error.exception, "doc") or error.exception.__context__, "secret leaked")

    def test_pinned_json_write_survives_directory_rename(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private"
            other = path.with_name("original")
            with control.private_dir(path) as directory:
                path.rename(other)
                path.mkdir(mode=0o700)
                control.write_private_json(directory, "preferences.json", control.DEFAULTS)
                self.assertEqual(control.read_private_json(directory, "preferences.json"), control.DEFAULTS)
            self.assertFalse((path / "preferences.json").exists())
            self.assertTrue((other / "preferences.json").is_file())


@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux control socket credentials")
class ControlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "runtime/control.sock"
        self.prefs = Path(temp.name) / "config/preferences.json"
        desktop = Mock()
        desktop.get_monitors.return_value = [Monitor("left", 0, 0, 100, 100),
                                             Monitor("right", 100, 0, 100, 100)]
        self.daemon = FlowDaemon({**STATE, "password": "private-test-password"},
                                 desktop=desktop, preferences_path=self.prefs, control_sock=self.path,
                                 udp_discovery_port=0, udp_nodestore_port=0, tcp_port=0,
                                 bind="127.0.0.1", broadcast="127.0.0.1")
        self.inventory = patch("flow_daemon.inventory_bolt_devices", return_value=[]).start()
        self.addCleanup(patch.stopall)
        await self.daemon.start()
        self.addAsyncCleanup(self.daemon.close)
        self.client = control.ControlClient(self.path)

    async def call(self, method, **params):
        return await asyncio.to_thread(self.client.call, method, **params)

    def connect_peers(self):
        peers = []
        for ch in (0, 1):
            host = f"remote-{ch}".encode()
            tunnel = Mock(peer_channel=ch)
            tunnel.send_settings = AsyncMock()
            tunnel.writer.get_extra_info.return_value = (f"127.0.0.{ch+2}", 59869)
            self.daemon.tunnels[host] = tunnel
            peers.append(tunnel)
        return peers

    async def test_socket_identity_status_modes_and_no_secrets(self):
        info = self.path.stat()
        self.assertTrue(stat.S_ISSOCK(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        with patch("flow_control._same_user", wraps=control._same_user) as authenticated:
            status = await self.call("get_status")
        authenticated.assert_called_once()
        self.assertEqual(status["host_id"], STATE["host_id"])
        self.assertEqual(status["local_channel"], 2)
        self.assertEqual(status["daemon_pid"], os.getpid())
        self.assertIsNone(status["settings"])
        self.assertEqual(status["preferences"], control.DEFAULTS)
        self.assertEqual(set(status["mouse"]), {"name", "channel", "device_id", "serial_number", "slot"})
        self.assertEqual(set(status["keyboard"]), set(status["mouse"]))
        for secret in ("random", "password", STATE["mouse"]["random"], self.daemon.device_key.hex(),
                       self.daemon.device_key_id.hex()):
            self.assertFalse(secret in json.dumps(status), "secret leaked")

    async def test_peer_credentials_reject_other_uid(self):
        sock = Mock()
        sock.getsockopt.return_value = struct.pack("3i", 1, os.geteuid()+1, 1)
        self.assertFalse(control._same_user(sock))
        sock.getsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        with patch("flow_control._same_user", return_value=False):
            with self.assertRaises((OSError, control.ControlError)):
                await self.call("update_settings", on=False)
        self.assertIsNone(self.daemon.settings)

    async def test_partial_settings_all_tunnels_and_removal(self):
        a, b = self.connect_peers()
        b.send_settings.side_effect = OSError("unavailable")
        status = await self.call("update_settings", ctrl_key=True, hot_corners=True,
                                 keyboard_link=True, copy_paste=True)
        self.assertEqual(status["delivery_errors"], [{"host_id": "remote-1", "error": "OSError"}])
        s = status["settings"]
        self.assertEqual(s["counter"], 1)
        self.assertEqual(s["keyboard_id"], STATE["keyboard"]["device_id"])
        self.assertTrue(all(s[k] for k in control.FLAGS))
        self.assertEqual(status["monitors"][0]["routes"], {"LEFT": "remote-1"})
        self.assertEqual(status["monitors"][1]["routes"], {})
        self.assertEqual(s["peers"][0]["peer_ip"], "127.0.0.2")
        rows = control.move_peer_slot(s["peers"], 2, 0)
        rows = control.toggle_peer_enabled(rows, 1)
        s = (await self.call("update_settings", **control.build_settings_update(
            s, peers=rows, layout="left-bottom")))["settings"]
        self.assertEqual(s["counter"], 2)
        self.assertEqual([p["channel"] for p in s["peers"]], [2, 0, 1])
        self.assertFalse(s["peers"][1]["enabled"])
        self.assertEqual(s["peers"][1]["keyboard_channel"], 0xffffffff)
        rows = control.remove_peer_slot(s["peers"], 2)
        s = (await self.call("update_settings", **control.build_settings_update(s, peers=rows)))["settings"]
        self.assertEqual(s["peers"][2]["host_id"], "")
        self.assertEqual(s["counter"], 3)
        self.assertEqual(a.send_settings.await_count, 3)
        self.assertEqual(b.send_settings.await_count, 3)
        a.send_settings.assert_awaited_with(self.daemon.settings)
        self.daemon.settings = replace(self.daemon.settings, counter=0xffffffff)
        self.assertEqual((await self.call("update_settings", on=False))["settings"]["counter"], 0)

    async def test_clipboard_status_is_measurements_only(self):
        self.connect_peers()
        status = await self.call("update_settings", copy_paste=True)
        self.assertEqual(status["clipboard"], {"enabled": True, "busy": False, "last_summary": None})
        self.daemon.clipboard.last_summary = control.clipboard_summary("IN", "image", 120, 45)
        clip = (await self.call("get_status"))["clipboard"]
        self.assertEqual(clip["last_summary"], "Clipboard IN · image (120x45)")
        with self.assertRaises(ValueError):
            control.clipboard_summary("IN", "private filename", 12)
        self.assertFalse((await self.call("reset_flow"))["clipboard"]["enabled"])

    async def test_invalid_mutations_are_atomic(self):
        self.connect_peers()
        s = (await self.call("update_settings", ctrl_key=False))["settings"]
        rows = control.build_settings_update(s, peers=s["peers"])["peers"]
        for args in (dict(on=1), dict(layout="diagonal"), dict(expected_counter=0),
                     dict(peers=rows[:2]), dict(peers=[rows[0], rows[0], rows[2]]),
                     dict(peers=[*rows[:2], dict(rows[2], enabled=False)]),
                     dict(peers=[*rows[:2], dict(rows[2], host_id="")]),
                     dict(peers=[dict(rows[0], host_id="impostor"), *rows[1:]]),
                     dict(peers=[dict(rows[0], host_id=""), *rows[1:]]),
                     dict(password="private-test-password")):
            with self.subTest(args=list(args)), self.assertRaises(control.ControlError):
                await self.call("update_settings", **args)
        self.assertEqual((await self.call("get_status"))["settings"], s)

    async def test_status_shaped_reorder_and_partial_peer_rows(self):
        self.connect_peers()
        s = (await self.call("update_settings", on=True))["settings"]
        rows = list(reversed(s["peers"]))
        self.assertEqual([r["channel"] for r in (await self.call("update_settings", peers=rows))
                          ["settings"]["peers"]], [2, 1, 0])
        rows = [{"channel": 2}, {"channel": 1, "enabled": False}, {"channel": 0, "host_id": ""}]
        s = (await self.call("update_settings", peers=rows))["settings"]
        self.assertFalse(s["peers"][1]["enabled"])
        self.assertEqual(s["peers"][1]["host_id"], "remote-1")
        self.assertFalse(s["peers"][2]["enabled"])
        self.assertEqual(s["peers"][2]["host_id"], "")

    async def test_preferences_apply_live_and_on_reload(self):
        self.daemon.edges = MouseEdges("mouse", 40, self.daemon.edge_push)
        update = dict(edge_cooldown=1.3, edge_threshold=100, modifier_key="super")
        self.assertEqual((await self.call("update_preferences", **update))["preferences"], update)
        self.assertEqual((self.daemon.cooldown, self.daemon.edges.threshold, self.daemon.modifier_key),
                         (1.3, 100, "super"))
        self.assertEqual(stat.S_IMODE(self.prefs.stat().st_mode), 0o600)
        self.assertEqual(json.loads(self.prefs.read_text()), update)
        for bad in ({"modifier_key": "win"}, {"edge_threshold": False}, {"edge_threshold": 501},
                    {"edge_threshold": 4}, {"edge_cooldown": .01}, {"edge_cooldown": 5.01},
                    {"random": "secret"}):
            with self.assertRaises(control.ControlError):
                await self.call("update_preferences", **bad)
        self.assertEqual(control.load_preferences(self.prefs, {}), update)

    async def test_discovery_targets_and_parameters(self):
        with patch.object(self.daemon, "send_udp") as send:
            for bad in ({"peer_ip": "::1"}, {"peer_ip": 123}, {"force": "false"}):
                with self.assertRaises(control.ControlError):
                    await self.call("discover_peers", **bad)
            send.assert_not_called()
            for force in (True, False):
                send.reset_mock()
                params = {} if force else {"force": False}
                result = await self.call("discover_peers", peer_ip="127.0.0.2", **params)
                packets = [call.args[0] for call in send.call_args_list]
                self.assertEqual(list(map(type, packets)), [InitiateDiscoveryPacket, BeaconPacket])
                self.assertTrue(all(p.force == force for p in packets))
                for call in send.call_args_list:
                    self.assertEqual(set(call.args[1]), {("127.0.0.1", self.daemon.discovery_port),
                                                          ("127.0.0.2", self.daemon.discovery_port)})
                self.assertIn("Discovery", result["events"][-1])
            self.assertEqual(self.daemon.peers, ())
            self.daemon.advertise_once()
            self.assertEqual(send.call_args.args[1], [("127.0.0.1", self.daemon.discovery_port)])

    async def test_reset_survives_peer_echo_then_discovery_rejoins(self):
        a, b = self.connect_peers()
        await self.call("update_settings", ctrl_key=True)
        s = (await self.call("reset_flow"))["settings"]
        local = s["peers"][2]
        self.assertEqual((s["counter"], local["host_id"], local["enabled"]), (2, "", False))
        self.assertEqual([a.send_settings.await_count, b.send_settings.await_count], [2, 2])
        t = Tunnel(self.daemon, None, None, True)
        t.peer_channel = 1
        await t.merge_settings(SettingsPacket(*self.daemon.identity[:2], 1, self.daemon.settings))
        self.assertEqual(self.daemon.settings.peers[2], Peer(2, 0xffffffff, b"", False))
        with patch.object(self.daemon, "send_udp"):
            result = await self.call("discover_peers")
        self.assertTrue(result["settings"]["peers"][2]["enabled"])

    async def test_rescan_safe_inventory_and_new_keyboard(self):
        self.daemon.devices.pop("keyboard")
        self.daemon.keyboard = (0, 0, 0xffffffff)
        row = dict(STATE["keyboard"], slot=1, name="K865", kind="keyboard", random="excluded")
        mouse = dict(STATE["mouse"], name="MX", slot=2, kind="mouse")
        self.inventory.return_value = [row, mouse]
        status = await self.call("rescan_devices")
        self.assertEqual(len(status["devices"]), 2)
        self.assertEqual(status["mouse"]["name"], "MX")
        self.assertEqual(status["keyboard"]["name"], "K865")
        self.assertFalse("random" in json.dumps(status), "secret leaked")
        self.assertFalse("excluded" in json.dumps(status), "secret leaked")
        self.assertFalse(self.prefs.exists())
        self.assertEqual(self.daemon.keyboard[0], 0)
        linked = await self.call("update_settings", keyboard_link=True)
        self.assertEqual(linked["settings"]["keyboard_id"], row["device_id"])
        self.assertEqual(self.daemon.keyboard[2], row["channel"])

    async def test_socket_cleanup_stays_with_pinned_parent(self):
        path = self.path.parent.parent / "test-runtime/sock"
        server = control.ControlServer(path, self.daemon.rpc)
        await server.start()
        original = path.parent.with_name("moved")
        try:
            path.parent.rename(original)
            path.parent.mkdir(mode=0o700)
            path.write_text("replacement")
        finally:
            await server.close()
        self.assertTrue(path.is_file())
        self.assertFalse((original / "sock").exists())

    async def test_concurrent_rescans_share_worker_after_waiter_timeout(self):
        await self.daemon.rescan_devices()
        started, release = threading.Event(), threading.Event()
        def inventory(_):
            started.set()
            release.wait(2)
            return []
        self.inventory.reset_mock()
        self.inventory.side_effect = inventory
        first = asyncio.create_task(self.daemon.rescan_devices())
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 1))
            second = asyncio.create_task(self.daemon.rescan_devices())
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
        finally:
            release.set()
        self.assertEqual(await second, [])
        self.inventory.assert_called_once()

    async def test_dispatch_deadlines_report_timeout_and_cancel_dispatch(self):
        for method, limit in (("get_status", "RPC_TIMEOUT"), ("rescan_devices", "RESCAN_TIMEOUT")):
            cancelled = asyncio.Event()
            async def slow(*args):
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()
            with patch.object(control, limit, .03), patch.object(self.daemon.control, "dispatch", slow):
                with self.assertRaisesRegex(control.ControlError, "timed out"):
                    await asyncio.wait_for(self.call(method), 1)
                self.assertTrue(cancelled.is_set())

    async def test_client_close_wakes_inflight_read(self):
        started, finished = asyncio.Event(), asyncio.Event()
        async def wait_for_close(reader, writer):
            await reader.readline()
            started.set()
            try:
                await reader.read()
            finally:
                writer.close()
                finished.set()
        path = self.path.with_name("blocked")
        async with await asyncio.start_unix_server(wait_for_close, path) as server:
            client = control.ControlClient(path, timeout=10)
            task = asyncio.create_task(asyncio.to_thread(client.call, "rescan_devices"))
            await asyncio.wait_for(started.wait(), 1)
            client.close()
            with self.assertRaises((control.ControlError, OSError)):
                await asyncio.wait_for(task, .5)
            await asyncio.wait_for(finished.wait(), .5)
            with self.assertRaises(OSError):
                client.call("get_status")

    async def test_event_ring_and_frame_bounds(self):
        for i in range(20):
            self.daemon.event(f"Discovery · {i}")
        status = await self.call("get_status")
        self.assertEqual(len(status["events"]), 15)
        self.assertTrue(status["events"][0].endswith(" · 5"))
        with self.assertRaises(control.ControlError):
            control._frame({"data": "x" * control.LIMIT})
        for frame in (b"x\n", b"[]\n", b"x" * (control.LIMIT+1) + b"\n"):
            r, w = await asyncio.open_unix_connection(self.path)
            w.write(frame)
            await w.drain()
            self.assertIn("error", json.loads(await r.readline()))
            w.close()
            await w.wait_closed()
        with patch.object(self.daemon.control, "dispatch", AsyncMock(return_value={"x": "a"*control.LIMIT})):
            with self.assertRaises(control.ControlError):
                await self.call("get_status")

    async def test_socket_recovery_only_for_refused_sockets(self):
        async def start(path):
            s = control.ControlServer(path, self.daemon.rpc)
            await s.start()
            self.addAsyncCleanup(s.close)
            return s
        with self.assertRaises(control.ControlError):
            await start(self.path)
        self.assertEqual((await self.call("get_status"))["daemon_pid"], os.getpid())
        p = self.path.with_name("candidate")
        p.write_text("keep")
        with self.assertRaises(control.ControlError):
            await start(p)
        self.assertEqual(p.read_text(), "keep")
        link = p.with_suffix(".link")
        link.symlink_to(p)
        with self.assertRaises(control.ControlError):
            await start(link)
        self.assertTrue(link.is_symlink())
        dir_link = self.path.parent.with_name("alias")
        dir_link.symlink_to(self.path.parent)
        with self.assertRaises(control.ControlError):
            await start(dir_link / "new.sock")
        dead = p.with_suffix(".sock")
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(dead))
        server = await start(dead)
        self.assertTrue(dead.is_socket())
        await server.close()
        self.assertFalse(dead.exists())
