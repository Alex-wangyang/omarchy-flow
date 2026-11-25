import asyncio
from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from flow_daemon import resolve_peer_for_edge
from hyprland_edges import Edge, EVENT, Hyprland, Monitor, MouseEdges, flow_in_point, flow_out_info
from marconi_packets import Peer, Settings


class GeometryTests(unittest.TestCase):
    monitors = [Monitor("eDP-1", 0, 1000, 1368, 912), Monitor("HDMI-A-2", 1368, 0, 2560, 1440)]

    def test_seam_and_exposed_spans(self):
        for y in (1000, 1200, 1439):
            for x, edge in ((1367, Edge.RIGHT), (1368, Edge.LEFT)):
                self.assertIsNone(flow_out_info(self.monitors, x, y, edge))
        for y, position in ((1440, 0.), (1911, 1.)):
            self.assertEqual(flow_out_info(self.monitors, 1367, y, Edge.RIGHT), (Edge.RIGHT, position))
            self.assertIsNone(flow_out_info(self.monitors, 1367, y, Edge.RIGHT, True))
        self.assertEqual(flow_out_info(self.monitors, 1368, 500, Edge.LEFT), (Edge.LEFT, 500/999))

    def test_entries(self):
        for edge, point in ((Edge.RIGHT, (3, 1456)), (Edge.LEFT, (3924, 720)),
                            (Edge.BOTTOM, (2648, 3)), (Edge.TOP, (684, 1908))):
            self.assertEqual(flow_in_point(self.monitors, edge, .5), point)

    def test_six_layouts(self):
        peers = tuple(Peer(c, c, bytes([c]), True) for c in (2, 0, 1))
        for layout, a, b in [(b"horizontal", 1, 1), (b"vertical", 3, 3), (b"left-top", 0, 3),
                              (b"right-top", 1, 3), (b"left-bottom", 3, 1), (b"right-bottom", 3, 0)]:
            s = Settings(0, layout, True, False, False, False, False, False, 0, 0, peers)
            connected = {p.host_id for p in peers}
            for slot, routes in enumerate(({a: 0}, {a^1: 2, b: 1}, {b^1: 0})):
                for edge in Edge:
                    self.assertEqual(resolve_peer_for_edge(s, peers[slot].channel, edge, connected),
                                     routes.get(edge))
            self.assertEqual(resolve_peer_for_edge(s, 2, a, connected-{peers[1].host_id}), 1)
            disabled = replace(s, peers=(peers[0], replace(peers[1], enabled=False), peers[2]))
            self.assertEqual(resolve_peer_for_edge(disabled, 1, b^1, connected), 2)
            self.assertIsNone(resolve_peer_for_edge(disabled, 0, b, connected))


class InputTests(unittest.IsolatedAsyncioTestCase):
    def test_modifier_keysyms_and_release_marker(self):
        desktop = Hyprland()
        for modifier, keysym in (("ctrl", "Control"), ("super", "Super"), ("alt", "Alt")):
            for reply, held in ((b"ok", True), (b"error: OMARCHY_FLOW_MOD_UP", False)):
                with self.subTest(modifier=modifier, reply=reply), patch.object(
                        desktop, "command", return_value=reply) as command:
                    self.assertIs(desktop.is_modifier_down(modifier), held)
                    command.assert_called_once_with(
                        f'eval if not (hl.is_key_down("{keysym}_L") or hl.is_key_down("{keysym}_R")) '
                        'then error("OMARCHY_FLOW_MOD_UP") end')

    def test_modifier_rejects_invalid_and_ipc_failure(self):
        desktop = Hyprland()
        with patch.object(desktop, "command", return_value=b"error: unknown IPC") as command:
            with self.assertRaises(ValueError):
                desktop.is_modifier_down('"; invalid')
            command.assert_not_called()
            with self.assertRaises(OSError):
                desktop.is_modifier_down("ctrl")
            command.side_effect = ConnectionResetError()
            with self.assertRaises(OSError):
                desktop.is_modifier_down("super")

    def test_keyboard_alias_is_rejected_before_open(self):
        from hyprland_edges import open_mouse
        from types import SimpleNamespace
        import stat
        with patch("pathlib.Path.resolve", return_value=Path("/dev/input/event7")), \
             patch("pathlib.Path.stat", return_value=SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=123)), \
             patch("pathlib.Path.read_text", return_value="E:ID_INPUT_MOUSE=1\nE:ID_INPUT_KEYBOARD=1"), \
             patch("os.open") as op:
            with self.assertRaises(OSError):
                open_mouse("/dev/input/by-id/alias")
            op.assert_not_called()

    def test_untrusted_symlink_targets_never_open(self):
        from hyprland_edges import open_mouse, DEFAULT_MOUSE
        with patch("os.readlink") as link, self.assertRaises(OSError):
            open_mouse("/dev/input/by-id/keyboard-event-mouse")
        link.assert_not_called()
        for target in ("../event3/../event2", "../../other/event2", "../by-id/receiver-event-kbd"):
            with patch("os.readlink", return_value=target), patch("os.open") as opened:
                with self.assertRaises(OSError):
                    open_mouse(DEFAULT_MOUSE)
                opened.assert_not_called()

    def test_mouse_capabilities_and_udev_must_agree(self):
        from types import SimpleNamespace
        import stat
        from hyprland_edges import _verify_mouse
        info = SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(13, 67))
        node = Path("/dev/input/event3")
        for rel, key, props, accepted in (
                ("1943", "ffff0000 0 0 0 0", "E:ID_INPUT_MOUSE=1", True),
                ("3", "2", "E:ID_INPUT_MOUSE=1", False),
                ("3", "80000 0", "E:ID_INPUT_MOUSE=1", False),
                ("1", "0", "E:ID_INPUT_MOUSE=1", False),
                ("3", "0", "", False),
                ("3", "0", "E:ID_INPUT_MOUSE=1\nE:ID_INPUT_MOUSE=0", False),
                ("3", "0", "E:ID_INPUT_MOUSE=1\nE:ID_INPUT_KEYBOARD=1", False)):
            def content(path):
                return {"dev": "13:67", "rel": rel, "key": key, "c13:67": props}[path.name]
            with self.subTest(rel=rel, key=key, props=props), patch.object(Path, "resolve",
                    side_effect=[Path("/sys/devices/input3/event3"), Path("/sys/class/input")]), \
                    patch.object(Path, "read_text", content), patch.object(Path, "stat"):
                if accepted:
                    _verify_mouse(info, node)
                else:
                    with self.assertRaises(OSError):
                        _verify_mouse(info, node)

    @unittest.skipUnless(hasattr(os, "O_PATH"), "Linux O_PATH")
    def test_hotplug_rechecks_pinned_inode_sysfs_and_open_fd(self):
        from types import SimpleNamespace
        from hyprland_edges import open_mouse
        def identity(ino):
            return SimpleNamespace(st_rdev=123, st_ino=ino, st_dev=7)
        for inode, sys_inode, keys in ((2, 3, 0), (1, 4, 0), (1, 3, 2)):
            with patch("os.open", side_effect=[10, 11]) as op, patch("os.close") as close, \
                    patch("os.fstat", side_effect=[identity(1), identity(inode)]), \
                    patch("hyprland_edges._verify_mouse", side_effect=[identity(3), identity(sys_inode)]), \
                    patch("hyprland_edges._fd_capabilities", side_effect=[3, keys]), patch("os.read") as read:
                with self.assertRaises(OSError):
                    open_mouse("/dev/input/event3")
                self.assertEqual([c.args for c in op.call_args_list], [
                    (Path("/dev/input/event3"), os.O_PATH | os.O_NOFOLLOW),
                    ("/proc/self/fd/10", os.O_RDONLY | os.O_NONBLOCK)])
                self.assertEqual([c.args for c in close.call_args_list], [(11,), (10,)])
                read.assert_not_called()

    def test_hyprland_ipc_bounds_total_time_and_size(self):
        with patch.dict(os.environ, HYPRLAND_INSTANCE_SIGNATURE="test"), \
                patch.object(Path, "glob", return_value=[]), patch("socket.socket") as factory:
            sock = factory.return_value.__enter__.return_value
            sock.recv.return_value = b"ab"
            with patch("hyprland_edges.IPC_MAX_RESPONSE", 3):
                with self.assertRaisesRegex(OSError, "too large"):
                    Hyprland().command("j/monitors")
            with patch("hyprland_edges.time") as clock:
                clock.monotonic.side_effect = [1, 1.1, 1.2, 1.7, 1.81]
                with self.assertRaises(TimeoutError):
                    Hyprland().command("j/monitors")

    async def test_socket_commands_and_transform(self):
        rows = [dict(name=n, x=x, y=y, width=w, height=h, scale=s, transform=t)
                for n,x,y,w,h,s,t in (("eDP-1",0,1000,2736,1824,2,0),
                                       ("HDMI-A-2",1368,0,2560,1440,1,0),("rot",0,0,300,200,2,1))]
        rows.append(dict(disabled=True))
        replies = {"j/monitors": json.dumps(rows), "j/cursorpos": '{"x":4,"y":7}',
                   "dispatch hl.dsp.cursor.move({ x = 3, y = 12 })": "ok"}
        async def respond(r, w):
            cmd = (await r.read(200)).decode()
            w.write(replies.get(cmd, "error: unsupported").encode())
            await w.drain()
            w.close()
            await w.wait_closed()
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, XDG_RUNTIME_DIR=root,
                                                               HYPRLAND_INSTANCE_SIGNATURE="stale"):
            path = Path(root)/"hypr/current/.socket.sock"
            path.parent.mkdir(parents=True)
            async with await asyncio.start_unix_server(respond, str(path)):
                ipc = Hyprland()
                self.assertEqual(await asyncio.to_thread(ipc.get_monitors), GeometryTests.monitors +
                                 [Monitor("rot",0,0,100,150)])
                self.assertEqual(await asyncio.to_thread(ipc.get_cursor_pos), (4,7))
                await asyncio.to_thread(ipc.move_cursor,3,12)
                self.assertIs(ipc._lua_dispatch, True)

    async def test_legacy_movecursor_fallback(self):
        seen = []
        async def respond(r, w):
            cmd = (await r.read(200)).decode()
            seen.append(cmd)
            w.write(b"ok" if cmd == "dispatch movecursor 9 15" else b"unknown request")
            await w.drain()
            w.close()
            await w.wait_closed()
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, XDG_RUNTIME_DIR=root):
            path = Path(root)/"hypr/current/.socket.sock"
            path.parent.mkdir(parents=True)
            async with await asyncio.start_unix_server(respond, str(path)):
                ipc = Hyprland()
                await asyncio.to_thread(ipc.move_cursor, 9, 15)
                self.assertIs(ipc._lua_dispatch, False)
                await asyncio.to_thread(ipc.move_cursor, 9, 15)
                self.assertEqual(seen, [
                    "dispatch hl.dsp.cursor.move({ x = 9, y = 15 })",
                    "dispatch movecursor 9 15",
                    "dispatch movecursor 9 15",
                ])

    async def test_motion_reset_threshold_and_rate(self):
        hit = AsyncMock()
        mouse = MouseEdges("mouse",40,hit)
        def move(n,t):
            mouse.feed(EVENT.pack(0,0,2,0,n)+EVENT.pack(0,0,0,0,0),t)
        for n,t in ((30,1),(-20,1.1),(-25,2),(-15,2.1)):
            move(n,t)
        await mouse.task
        move(50,2.12)
        hit.assert_awaited_once_with(Edge.LEFT)
        move(1,2.16)
        await mouse.task
        self.assertEqual(hit.await_args.args,(Edge.RIGHT,))

    async def test_reopen(self):
        mouse = MouseEdges("mouse",40,AsyncMock())
        loop = asyncio.get_running_loop()
        with patch("hyprland_edges.open_mouse",side_effect=[12,13]), patch("os.close"), patch.object(loop,"add_reader"), \
             patch.object(loop,"remove_reader") as remove, patch.object(loop,"call_later") as timer, \
             patch("os.read",side_effect=OSError(errno.ENODEV,"gone")):
            mouse.start()
            mouse.read()
            remove.assert_called_once_with(12)
            timer.call_args.args[1]()
            self.assertEqual(mouse.fd,13)
            await mouse.close()
