import asyncio
from contextlib import suppress
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import socket
import sys
import threading
import tempfile
import struct
import unittest
from unittest.mock import AsyncMock, Mock, patch

from flow_daemon import FlowDaemon, Tunnel
from marconi_crypto import DHEKeyExchange, derive_device_key
import marconi_packets as p


LOCAL_IP = "127.0.0.1"
MAC_IP = "127.0.0.2"
MAC = b"mock-mac"
LINUX = b"linux"
IDENTITY = (0x020123, 321)
STATE = {"host_id": LINUX.decode(), "mouse": {"device_id": IDENTITY[0], "serial_number": IDENTITY[1],
         "channel": 2, "random": bytes(range(32)).hex()}, "keyboard": {"device_id": 567,
         "serial_number": 432, "channel": 1}}
MAC_SETTINGS = p.Settings(15, b"horizontal", True, True, False, True, False, True, 567, 432,
    (p.Peer(0, 0, b"another-host", True), p.Peer(1, 2, MAC, True), p.Peer(2, 0xffffffff, b"", False)))


class MockPeer:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.device_key_id, self.device_key = derive_device_key(*IDENTITY, STATE["mouse"]["random"])
        self.key_id, self.key = self.device_key_id, self.device_key
        self.session = None

    def frame(self, packet):
        return p.seal_packet(self.key, self.key_id, packet.encode(), self.session)

    def wrap_device(self, channel, packet):
        return p.wrap_device_packet(*IDENTITY, channel, packet.encode(),
                                    self.device_key, self.device_key_id)

    async def send(self, packet):
        self.writer.write(self.frame(packet))
        await self.writer.drain()

    async def send_device(self, channel, packet):
        await self.send(self.wrap_device(channel, packet))

    async def receive(self):
        frame = await asyncio.wait_for(p.read_frame(self.reader), 2)
        return p.decode_packet(p.open_packet(self.key, self.key_id, frame, self.session))

    async def receive_device(self):
        async def next_payload():
            while True:
                outer = await self.receive()
                if not isinstance(outer, p.HeartbeatPacket):
                    return outer
        outer = await asyncio.wait_for(next_payload(), 2)
        assert isinstance(outer, p.DeviceDataPacket), f"expected DeviceDataPacket, got {type(outer)}"
        return p.decode_packet(p.unwrap_device_packet(outer, self.device_key, self.device_key_id))

    async def close(self):
        self.writer.close()
        with suppress(ConnectionResetError):
            await self.writer.wait_closed()


class DaemonTests(unittest.IsolatedAsyncioTestCase):
    async def start(self, *, state=STATE, **kwargs):
        self.flows, self.switches = asyncio.Queue(), asyncio.Queue()
        options = {"udp_discovery_port": 0, "udp_nodestore_port": 0, "tcp_port": 0, **kwargs}
        options.setdefault("clipboard", MemoryWayland().backend)
        self.daemon = FlowDaemon(state, bind=LOCAL_IP, broadcast=LOCAL_IP, on_initiate_flow=self.flows.put,
            on_set_current_host=self.switches.put_nowait, **options)
        await self.daemon.start()
        self.addAsyncCleanup(self.daemon.close)
        self.kid, self.key = derive_device_key(*IDENTITY, state["mouse"]["random"])

    def udp(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind((MAC_IP, port))
        sock.setblocking(False)
        return sock

    async def datagram(self, sock, packet, port):
        data = p.seal_packet(self.key, self.kid, p.encode_discovery(packet))
        await asyncio.get_running_loop().sock_sendto(sock, data, (LOCAL_IP, port))

    async def recv_udp(self, sock):
        data = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(sock, 65535), 2)
        return p.decode_packet(p.open_packet(self.key, self.kid, data))

    async def connect(self):
        reader, writer = await asyncio.open_connection(LOCAL_IP, self.daemon.tcp_port)
        peer = MockPeer(reader, writer)
        self.addAsyncCleanup(peer.close)
        return peer

    async def inbound(self, host=MAC, channel=1):
        peer = await self.connect()
        client = DHEKeyExchange()
        # Exercise TCP segmentation during the first handshake frame.
        wire = peer.frame(p.ClientHelloPacket(host, p.CIPHER_SUITE, client.params))
        peer.writer.write(wire[:17])
        await peer.writer.drain()
        await asyncio.sleep(0)
        peer.writer.write(wire[17:])
        hello = await peer.receive()
        self.assertIsInstance(hello, p.ServerHelloPacket)
        self.assertEqual((hello.host_id, hello.cipher_suite), (LINUX, p.CIPHER_SUITE))
        promote = peer.frame(p.PromoteConnectionPacket(host))
        peer.key, peer.key_id = client.derive_session_key(hello.params), hello.params.key_id
        peer.session = hello.session
        # Two different key contexts in a coalesced TCP write, with ClientDeviceConnect wrapped.
        connect_outer = peer.wrap_device(channel, p.ClientDeviceConnectPacket(*IDENTITY, channel, host))
        peer.writer.write(promote + peer.frame(connect_outer))
        self.assertEqual(await peer.receive_device(), p.ServerDeviceConnectPacket(*IDENTITY, 2, LINUX))
        return peer

    async def silence(self, peer):
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(peer.reader.read(1), 0.1)

    async def test_inbound_udp_tunnel_merge_heartbeat_owner_and_hooks(self):
        interval = patch("flow_daemon.HEARTBEAT_INTERVAL", 0.3)
        interval.start()
        self.addCleanup(interval.stop)
        await self.start()
        discovery = self.udp(self.daemon.discovery_port)
        await self.datagram(discovery, p.InitiateDiscoveryPacket(*IDENTITY, 1, True),
                            self.daemon.discovery_port)
        beacon = p.BeaconPacket(*IDENTITY, 2, LINUX, True, self.daemon.discovery_port)
        self.assertEqual(await self.recv_udp(discovery), beacon)
        # Responding to peer BeaconPacket sends PingPacket carrying our TCP port.
        await self.datagram(discovery, p.BeaconPacket(*IDENTITY, 1, MAC, True, self.daemon.discovery_port),
                            self.daemon.discovery_port)
        ping = p.PingPacket(*IDENTITY, 2, LINUX, True, self.daemon.tcp_port)
        self.assertEqual(await self.recv_udp(discovery), ping)

        peer = await self.inbound()
        settings = p.SettingsPacket(*IDENTITY, 1, MAC_SETTINGS)
        await peer.send_device(1, settings)
        merged = await peer.receive_device()
        expected = replace(MAC_SETTINGS, counter=16, peers=(*MAC_SETTINGS.peers[:2], p.Peer(2, 1, LINUX, True)))
        self.assertEqual(merged, p.SettingsPacket(*IDENTITY, 2, expected))
        self.assertEqual(self.daemon.settings, expected)
        await peer.send_device(1, settings)
        await peer.send_device(1, replace(settings, settings=expected))

        # Periodic Unix-second heartbeat fires on inbound (server) tunnels too.
        heartbeat = await peer.receive()
        self.assertIs(type(heartbeat), p.HeartbeatPacket)
        self.assertGreater(heartbeat.current_time, 1_700_000_000)
        self.assertLess(heartbeat.current_time, 10_000_000_000)
        self.assertGreater(heartbeat.last_received_packet_time, 1_700_000_000)
        # Receiving peer heartbeat updates timestamp without echoing a ping-pong reply.
        await peer.send(p.HeartbeatPacket(heartbeat.current_time, heartbeat.current_time + 1))

        owner = p.wrap_global_packet(MAC, p.SetOwnerPacket(b"another-host", 1, MAC, 1).encode())
        flow = p.InitiateFlowPacket(p.Edge.BOTTOM, 0.25)
        switch = p.SetCurrentHostPacket(2)
        for packet in [owner, *(p.wrap_device_packet(*IDENTITY, 1, event.encode(), self.key, self.kid)
                                for event in (flow, switch))]:
            # Each inner object spans two separately authenticated outer frames (1-based chunks).
            data = packet.buffer.storage
            for i, piece in enumerate((data[:3], data[3:]), start=1):
                buf = replace(packet.buffer, write_offset=len(piece), storage=piece)
                await peer.send(replace(packet, chunk_number=i, chunk_count=2, buffer=buf))
        self.assertEqual(await asyncio.wait_for(self.flows.get(), 2), flow)
        self.assertEqual(await asyncio.wait_for(self.switches.get(), 2), switch)
        self.assertEqual(self.daemon.active_owner, MAC)

    async def test_outbound_ping_handshake_nested_settings_and_heartbeat(self):
        # Local channel 0 (< peer channel 1) initiates TCP upon receiving PingPacket.
        low_state = {**STATE, "mouse": {**STATE["mouse"], "channel": 0}}
        accepted = asyncio.Queue()
        server = await asyncio.start_server(lambda r, w: accepted.put_nowait((r, w)), MAC_IP, 0)
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        tcp_port = server.sockets[0].getsockname()[1]
        interval = patch("flow_daemon.HEARTBEAT_INTERVAL", 0.35)
        interval.start()
        self.addCleanup(interval.stop)
        discovery = self.udp(0)
        disc_port = discovery.getsockname()[1]
        await self.start(state=low_state, advertise=True, force=True, peers=[MAC_IP],
                         udp_discovery_port=disc_port)
        init_pkt = await self.recv_udp(discovery)
        self.assertIs(type(init_pkt), p.InitiateDiscoveryPacket)
        self.assertTrue(init_pkt.force)
        bcn_pkt = await self.recv_udp(discovery)
        self.assertIs(type(bcn_pkt), p.BeaconPacket)
        self.assertEqual(bcn_pkt.port, self.daemon.discovery_port)
        self.assertTrue(bcn_pkt.force)
        # Peer sends BeaconPacket (carrying peer UDP port), daemon replies PingPacket,
        # then peer sends PingPacket (carrying peer TCP port) -> daemon dials TCP.
        beacon = p.BeaconPacket(*IDENTITY, 1, MAC, True, disc_port)
        await self.datagram(discovery, beacon, self.daemon.discovery_port)
        our_ping = await self.recv_udp(discovery)
        self.assertIs(type(our_ping), p.PingPacket)
        self.assertEqual(our_ping.port, self.daemon.tcp_port)
        self.assertTrue(accepted.empty())
        await self.datagram(discovery, p.PingPacket(*IDENTITY, 1, MAC, True, tcp_port),
                            self.daemon.discovery_port)
        peer = MockPeer(*await asyncio.wait_for(accepted.get(), 2))
        self.addAsyncCleanup(peer.close)
        hello = await peer.receive()
        self.assertIs(type(hello), p.ClientHelloPacket)
        self.assertEqual((hello.host_id, hello.cipher_suite), (LINUX, p.CIPHER_SUITE))
        exchange = DHEKeyExchange(hello.params)
        session = p.Session(bytes(range(16)), 12, 4000)
        await peer.send(p.ServerHelloPacket(MAC, session.inverted(), p.CIPHER_SUITE, exchange.params))
        self.assertEqual(await peer.receive(), p.PromoteConnectionPacket(LINUX))
        peer.key, peer.key_id = exchange.derive_session_key(hello.params), hello.params.key_id
        peer.session = session
        self.assertEqual(await peer.receive_device(), p.ClientDeviceConnectPacket(*IDENTITY, 0, LINUX))
        await peer.send_device(1, p.ServerDeviceConnectPacket(*IDENTITY, 1, MAC))
        mac_settings_0 = replace(MAC_SETTINGS, peers=(
            p.Peer(0, 0xffffffff, b"", False),
            p.Peer(1, 2, MAC, True),
            p.Peer(2, 0xffffffff, b"third-host", True),
        ))
        await peer.send_device(1, p.SettingsPacket(*IDENTITY, 1, mac_settings_0))
        merged = await peer.receive_device()
        self.assertEqual(merged.settings.peers, (p.Peer(0, 1, LINUX, True), *mac_settings_0.peers[1:]))
        pulse = await peer.receive()
        self.assertIs(type(pulse), p.HeartbeatPacket)
        self.assertGreater(pulse.current_time, 1_700_000_000)
        self.assertTrue(accepted.empty())

    async def test_waiting_peer_gets_one_cold_snapshot_then_preserves_native_rows(self):
        with patch("flow_daemon.SETTINGS_GRACE", 0.02):
            await self.start()
            peer = await self.inbound()
            initial = await peer.receive_device()
            self.assertEqual(initial.settings.counter, 0)
            self.assertEqual(initial.settings.layout, b"horizontal")
            self.assertEqual(initial.settings.peers[1].host_id, MAC)
            self.assertEqual(initial.settings.peers[2].host_id, LINUX)
            await self.silence(peer)
            request = p.SettingsPacket(*IDENTITY, 1, MAC_SETTINGS)
            await peer.send_device(1, request)
            update = await peer.receive_device()
            self.assertEqual(update.settings.peers[:2], MAC_SETTINGS.peers[:2])
            self.assertEqual(update.settings.counter, MAC_SETTINGS.counter + 1)
            # Even a contradictory repeat with a higher counter gets no reply burst.
            await peer.send_device(1, replace(request, settings=replace(MAC_SETTINGS, counter=99)))
            await self.silence(peer)

    async def test_h1_oversize_header_rejected_before_body(self):
        await self.start()
        peer = await self.connect()
        peer.writer.write(self.kid + struct.pack(">I", 16385))
        await peer.writer.drain()
        self.assertEqual(await asyncio.wait_for(peer.reader.read(1), 1), b"")
        self.assertEqual(self.daemon.budget.used, 0)

    async def test_live_initial_bolt_owner_sent_after_authenticated_connect(self):
        await self.start()
        mouse = {**STATE["mouse"], "kind": "mouse", "name": "fixture", "slot": 2}
        with patch("flow_daemon.inventory_bolt_devices", return_value=[mouse]):
            await self.daemon.rescan_devices()
        peer = await self.inbound()
        packet = p.decode_packet(p.unwrap_global_packet(await peer.receive()))
        self.assertEqual(packet, p.SetOwnerPacket(LINUX, 2, LINUX, 2))

    async def test_reject_bad_frames_sequences_and_recover(self):
        await self.start()
        malformed = bytes(32) + struct.pack(">I", 0xffffffff)
        wrong_key = p.seal_packet(bytes(32), self.kid, p.PromoteConnectionPacket(MAC).encode())
        wrong_phase = p.seal_packet(self.key, self.kid, p.PromoteConnectionPacket(MAC).encode())
        for wire in (malformed, wrong_key, wrong_phase):
            peer = await self.connect()
            peer.writer.write(wire)
            self.assertEqual(await asyncio.wait_for(peer.reader.read(1), 2), b"")
        for fault in ("replay", "skip", "no-session"):
            peer = await self.inbound()
            if fault == "skip":
                peer.session.next_outbound_header()
            if fault == "no-session":
                peer.session = None
            wire = peer.frame(p.HeartbeatPacket(0, 111))
            peer.writer.write(wire)
            if fault == "replay":
                await asyncio.sleep(0.05)
                peer.writer.write(wire)
            self.assertEqual(await asyncio.wait_for(peer.reader.read(1), 2), b"")
        peer = await self.inbound()
        await peer.send_device(1, p.SettingsPacket(*IDENTITY, 1, MAC_SETTINGS))
        merged = await peer.receive_device()
        self.assertEqual(merged.settings.counter, 16)

    async def crossing_sequence(self, linked):
        from flow_switcher import Switcher
        from hyprland_edges import Monitor

        desktop = Mock()
        desktop.get_monitors.return_value = [Monitor("mock", 0, 0, 201, 101)]
        desktop.get_cursor_pos.return_value = (0, 50)
        switcher = Switcher(STATE)
        release = threading.Event()
        keyboard_started = threading.Event()
        def hardware(role, channel, generation):
            if role == "keyboard":
                keyboard_started.set()
                release.wait(2)
                raise TimeoutError
            return True
        switcher.switch = Mock(side_effect=hardware)
        with patch("flow_daemon.HEARTBEAT_INTERVAL", .25):
            await self.start(desktop=desktop, switcher=switcher)
            peer = await self.inbound()
            await peer.send_device(1, p.SettingsPacket(*IDENTITY, 1, replace(
                MAC_SETTINGS, keyboard_link=linked, layout=b"horizontal")))
            self.assertEqual((await peer.receive_device()).settings.peers[2].keyboard_channel, 1)
            await peer.send_device(1, p.InitiateFlowPacket(p.Edge.RIGHT, .5))
            self.assertEqual(await peer.receive_device(), p.SetCurrentHostPacket(2))
            owner = p.decode_packet(p.unwrap_global_packet(await peer.receive()))
            self.assertEqual(owner, p.SetOwnerPacket(b"", 0, LINUX, 2))
            # The ownership frame can arrive before the handler installs its cooldown.
            self.assertEqual(await asyncio.wait_for(self.flows.get(), 2), p.InitiateFlowPacket(p.Edge.RIGHT, .5))
            desktop.move_cursor.assert_called_once_with(3, 50)
            await self.daemon.edge_push(p.Edge.LEFT)
            desktop.get_cursor_pos.assert_not_called()
            self.daemon.until = 0
            await self.daemon.edge_push(p.Edge.LEFT)
            self.assertEqual(await peer.receive_device(), p.InitiateFlowPacket(p.Edge.LEFT, .5))
            switcher.switch.assert_not_called()
            for _ in range(2):
                await peer.send_device(1, p.SetCurrentHostPacket(1))
            try:
                if linked:
                    self.assertTrue(await asyncio.to_thread(keyboard_started.wait, 1))
                self.assertIsInstance(await peer.receive(), p.HeartbeatPacket)
            finally:
                release.set()
            await switcher.task
            calls = [c.args[:2] for c in switcher.switch.call_args_list]
            self.assertEqual(calls, [("mouse",1)] + ([("keyboard",2)] * 2 if linked else []))
            self.assertIn(MAC, self.daemon.tunnels)

    async def test_connected_beacon_requires_force(self):
        await self.start()
        await self.inbound()
        node = self.udp(0)
        port = node.getsockname()[1]
        beacon = p.BeaconPacket(*IDENTITY, 1, MAC, False, port)
        await self.datagram(node, beacon, self.daemon.discovery_port)
        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(asyncio.get_running_loop().sock_recv(node, 65535), .05)
        await self.datagram(node, replace(beacon, force=True), self.daemon.discovery_port)
        self.assertTrue((await self.recv_udp(node)).force)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux peer credentials")
    async def test_control_broadcast_over_two_authenticated_sessions(self):
        from flow_control import ControlClient
        with tempfile.TemporaryDirectory() as temp, patch("flow_daemon.inventory_bolt_devices", return_value=[]):
            path = Path(temp) / "private/control.sock"
            await self.start(control_sock=path)
            mac = await self.inbound()
            other = await self.inbound(b"other", 0)
            client = ControlClient(path)
            for method in ("update_settings", "reset_flow"):
                args = {"layout": "right-top", "ctrl_key": True} if method == "update_settings" else {}
                status = await asyncio.to_thread(client.call, method, **args)
                for peer in (mac, other):
                    packet = await peer.receive_device()
                    self.assertIsInstance(packet, p.SettingsPacket)
                    self.assertEqual(packet.settings.counter, status["settings"]["counter"])
                    self.assertEqual(packet.settings.layout, b"right-top")
                    self.assertTrue(packet.settings.ctrl_key)
                    self.assertEqual(packet.settings.peers[2].enabled, method != "reset_flow")
            await self.daemon.close()

    async def test_expired_and_unsolicited_host_replies(self):
        await self.start()
        peer = await self.inbound()
        await peer.send_device(1, p.SettingsPacket(*IDENTITY, 1, replace(MAC_SETTINGS, layout=b"horizontal")))
        await peer.receive_device()
        from flow_switcher import Switcher
        self.daemon.switcher = Switcher(STATE, dry_run=True)
        self.daemon.switcher.submit_crossing = Mock()
        for pending in (False, True):
            if pending:
                await self.daemon.send_initiate_flow(1, p.Edge.LEFT, .3)
                await peer.receive_device()
                self.daemon.until = 0
            await peer.send_device(1, p.SetCurrentHostPacket(1))
            await asyncio.wait_for(self.switches.get(), 1)
        self.daemon.switcher.submit_crossing.assert_not_called()
        await self.daemon.send_initiate_flow(1, p.Edge.LEFT, .3)
        self.assertIsInstance(await peer.receive_device(), p.InitiateFlowPacket)

    async def test_edge_modifier_gate(self):
        from hyprland_edges import Monitor
        desktop = Mock()
        desktop.get_monitors.return_value = [Monitor("screen", 0, 0, 100, 100)]
        await self.start(desktop=desktop)
        tunnel = await self.inbound()
        await tunnel.send_device(1, p.SettingsPacket(*IDENTITY, 1,
            replace(MAC_SETTINGS, layout=b"horizontal")))
        await tunnel.receive_device()
        desktop.get_cursor_pos.return_value = (50, 50)
        await self.daemon.edge_push(p.Edge.LEFT)
        desktop.is_modifier_down.assert_not_called()
        desktop.get_cursor_pos.return_value = (0, 50)
        for enabled, held, modifier in ((True, False, "ctrl"), (True, True, "ctrl"),
                                       (True, True, "super"), (False, False, "alt")):
            with self.subTest(enabled=enabled, held=held, modifier=modifier):
                self.daemon.settings = replace(self.daemon.settings, ctrl_key=enabled)
                self.daemon.modifier_key = modifier
                self.daemon.until = 0
                desktop.is_modifier_down.reset_mock()
                desktop.is_modifier_down.return_value = held
                await self.daemon.edge_push(p.Edge.LEFT)
                if enabled:
                    desktop.is_modifier_down.assert_called_once_with(modifier)
                else:
                    desktop.is_modifier_down.assert_not_called()
                if held or not enabled:
                    self.assertIsInstance(await tunnel.receive_device(), p.InitiateFlowPacket)
                else:
                    self.assertIsNone(self.daemon.awaiting)
                    with self.assertRaises(TimeoutError):
                        await asyncio.wait_for(tunnel.receive_device(), .05)

    async def test_linked_crossing(self):
        await self.crossing_sequence(True)

    async def test_mouse_only_crossing(self):
        await self.crossing_sequence(False)

    async def test_optional_clipboard_and_key_packets_do_not_drop_crossing(self):
        from fars import BinHeader
        desktop = Mock()
        desktop.get_monitors.return_value = [Mock(name="eDP-1", x=0, y=1000, width=1368, height=912)]
        await self.start(desktop=desktop)
        peer = await self.inbound()
        await peer.send_device(1, p.SettingsPacket(*IDENTITY, 1, replace(MAC_SETTINGS, copy_paste=True)))
        await peer.receive_device()
        clip_dev = p.ClipboardUpdatePacket(MAC, b"provider", (b"text/plain",)).encode()
        clip_glob = p.ClipboardUpdatePacket(MAC, b"provider", (b"image",)).encode()
        key_dev = BinHeader(b"KeyPacket", 1, 1).encode() + b"\x00"
        await peer.send(p.wrap_device_packet(*IDENTITY, 1, clip_dev, self.key, self.kid))
        await peer.send(p.wrap_global_packet(MAC, clip_glob))
        await peer.send(p.wrap_device_packet(*IDENTITY, 1, key_dev, self.key, self.kid))
        await peer.send_device(1, p.InitiateFlowPacket(p.Edge.LEFT, 0.5))
        reply = await peer.receive_device()
        self.assertEqual(reply, p.SetCurrentHostPacket(2))
        desktop.move_cursor.assert_called_once()
        self.assertIsInstance(p.decode_packet(p.unwrap_global_packet(await peer.receive())), p.SetOwnerPacket)
        # Truncated optional FARS payload must still be rejected.
        bad_clip = BinHeader(b"ClipboardUpdatePacket", 1, 10).encode() + b"\x01\x02"
        await peer.send(p.wrap_device_packet(*IDENTITY, 1, bad_clip, self.key, self.kid))
        self.assertEqual(await asyncio.wait_for(peer.reader.read(1), 2), b"")

    async def test_shutdown_releases_incomplete_handshake_and_listeners(self):
        await self.start()
        peer = await self.connect()
        peer.writer.write(b"partial")
        await asyncio.wait_for(self.daemon.close(), 2)
        # Linux may send RST if our partial frame is still in its receive queue.
        with suppress(ConnectionResetError):
            self.assertEqual(await asyncio.wait_for(peer.reader.read(1), 2), b"")
        self.assertFalse(self.daemon.tasks)
        self.assertFalse(self.daemon.tunnels)
        for port in (self.daemon.discovery_port, self.daemon.nodestore_port):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((LOCAL_IP, port))
        with self.assertRaises(OSError):
            await asyncio.open_connection(LOCAL_IP, self.daemon.tcp_port)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux peer credentials")
    async def test_foreground_preferences_and_control_path_across_restarts(self):
        from flow_control import ControlClient
        entrypoint = (
            "from functools import partial\n"
            "import flow_daemon as d\n"
            "d.inventory_bolt_devices = lambda _: []\n"
            "d.FlowDaemon = partial(d.FlowDaemon, bind='127.0.0.1', broadcast='127.0.0.1')\n"
            "d.main()"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state.json"
            with os.fdopen(os.open(state, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
                json.dump(STATE, out)
            path = root / "runtime/control.sock"
            client = ControlClient(path)
            for flags, expected in [
                    ([], dict(modifier_key="ctrl", edge_threshold=40, edge_cooldown=.6)),
                    (["--edge-threshold", "125"], dict(modifier_key="alt", edge_threshold=125, edge_cooldown=.4)),
                    (["--edge-cooldown", "1", "--modifier-key", "super"],
                     dict(modifier_key="super", edge_threshold=125, edge_cooldown=1.0))]:
                proc = await asyncio.create_subprocess_exec(
                    sys.executable, "-B", "-c", entrypoint, "run", "--no-edges", "--config", str(state),
                    "--control-sock", str(path), "--tcp-port", "0", "--udp-discovery-port", "0",
                    "--udp-nodestore-port", "0", *flags, cwd=Path(__file__).resolve().parents[1] / "src",
                    stderr=asyncio.subprocess.PIPE)
                try:
                    self.assertIn(b"Listening on UDP", await asyncio.wait_for(proc.stderr.readline(), 3))
                    status = await asyncio.to_thread(client.call, "get_status")
                    self.assertEqual(status["preferences"], expected)
                    if not flags:
                        await asyncio.to_thread(client.call, "update_preferences",
                                                modifier_key="alt", edge_cooldown=.4)
                finally:
                    if proc.returncode is None:
                        proc.terminate()
                    await asyncio.wait_for(proc.wait(), 3)
                self.assertFalse(path.exists())
            self.assertTrue(json.loads(state.read_text()) == STATE, "state changed")

    async def test_foreground_cli_sigint_and_sigterm(self):
        # Inject only the bind address so the real CLI lifecycle stays on loopback.
        entrypoint = (
            "from functools import partial\n"
            "import flow_daemon as d\n"
            "d.FlowDaemon = partial(d.FlowDaemon, bind='127.0.0.1', broadcast='127.0.0.1')\n"
            "d.main()"
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.json"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(STATE, stream)
            for sig in (signal.SIGINT, signal.SIGTERM):
                proc = await asyncio.create_subprocess_exec(sys.executable, "-B", "-c", entrypoint,
                    "run", "--no-edges", "--no-control-sock", "--config", str(path), "--tcp-port", "0", "--udp-discovery-port", "0",
                    "--udp-nodestore-port", "0", cwd=Path(__file__).resolve().parents[1] / "src",
                    stderr=asyncio.subprocess.PIPE)
                try:
                    ready = await asyncio.wait_for(proc.stderr.readline(), 5)
                    self.assertIn(b"Listening on UDP", ready)
                    proc.send_signal(sig)
                    self.assertEqual(await asyncio.wait_for(proc.wait(), 2), 0)
                finally:
                    if proc.returncode is None:
                        proc.kill()
                        await proc.wait()

    async def test_udp_suppresses_self_unrelated_devices_and_ping_replies(self):
        await self.start()
        node = self.udp(self.daemon.nodestore_port)
        ping = p.PingPacket(*IDENTITY, 1, MAC, False, 1234)
        for packet in (replace(ping, host_id=LINUX), replace(ping, device_id=7),
                       replace(ping, channel=2)):
            await self.datagram(node, packet, self.daemon.nodestore_port)
        await self.datagram(node, ping, self.daemon.nodestore_port)
        await self.datagram(node, ping, self.daemon.nodestore_port)
        # Peer on lower channel (1 < 2) gets one PingPacket carrying our TCP port.
        reply = await self.recv_udp(node)
        self.assertEqual(reply, p.PingPacket(*IDENTITY, 2, LINUX, False, self.daemon.tcp_port))
        loop = asyncio.get_running_loop()
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(loop.sock_recv(node, 65535), 0.1)
        self.daemon.recent[(MAC_IP, p.PingPacket, 1)] -= 30
        await self.datagram(node, ping, self.daemon.nodestore_port)
        self.assertEqual(await self.recv_udp(node), reply)


class RemediationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.daemon = d = FlowDaemon(STATE, switcher=Mock())
        self.tunnel = t = Tunnel(d, None, Mock(), True)
        t.host, t.peer_channel = MAC, 1
        t.writer.get_extra_info.return_value = (MAC_IP, 10001)
        d.tunnels[MAC] = t
        t.send_device = AsyncMock()
        d.settings = d.seed_settings()

    def packet(self, settings):
        return p.SettingsPacket(*IDENTITY, 1, settings)

    async def test_peer_log_string_is_one_bounded_line(self):
        t = self.tunnel
        t.host = b"peer\n\r\x1b" + b"z" * 100
        with self.assertLogs("omarchy-flow", level="DEBUG") as output:
            await t.dispatch(p.HeartbeatPacket(1, 1))
        message = output.records[0].getMessage()
        self.assertEqual(message, "Heartbeat from peer" + "z" * 60 + " (1, 1)")

    async def test_handshake_and_session_read_limits_use_daemon_budget(self):
        d, t = self.daemon, self.tunnel
        with patch("flow_daemon.read_frame", AsyncMock(side_effect=EOFError)) as read:
            for session, limit in ((None, p.HANDSHAKE_MAX_BLOCK), (p.Session(bytes(16), 1, 2), p.MAX_BLOCK)):
                t.session = session
                with self.assertRaises(EOFError):
                    await t.receive()
                read.assert_awaited_with(t.reader, max_block=limit, expected_key_id=t.key_id, budget=d.budget)

    async def test_wire_disable_removal_and_rejoin_change_crossing_generation(self):
        d, t = self.daemon, self.tunnel
        local = d.local_peer
        for peer in (replace(local, enabled=False), p.Peer(2, 0xffffffff, b"", False), local):
            previous = d.generation
            s = d.settings
            incoming = replace(s, counter=s.counter + 1, peers=(*s.peers[:2], peer))
            await t.merge_settings(self.packet(incoming))
            self.assertEqual(d.settings.peers[2], peer)
            self.assertGreater(d.generation, previous)
            self.assertEqual(d.ready_peer(1) is not None, peer.enabled)

    async def test_ping_retries_after_failed_dial_and_explicit_discovery(self):
        from flow_daemon import PING_BACKOFF
        d = FlowDaemon({**STATE, "mouse": {**STATE["mouse"], "channel": 0}})
        d.udp = [Mock(), Mock()]
        packet = p.PingPacket(*IDENTITY, 1, MAC, False, 59869)
        frame = p.seal_packet(d.device_key, d.device_key_id, p.encode_discovery(packet))
        with patch("flow_daemon.asyncio.open_connection", AsyncMock(side_effect=ConnectionRefusedError)) as dial:
            for expected in (1, 1, 2, 3):
                if expected == 2:
                    d.recent[(MAC_IP, p.PingPacket, 1)] -= PING_BACKOFF
                elif expected == 3:
                    await d.rpc("discover_peers", {})
                d.discovery(frame, MAC_IP)
                await asyncio.gather(*d.tasks)
                self.assertEqual(dial.await_count, expected)
                self.assertFalse(d.pending)

    async def test_wire_validation_sender_binding_and_reset_fallback(self):
        d, t = self.daemon, self.tunnel
        initial = d.settings
        a, b, c = initial.peers
        for rows in ((b, b, c), (a, b, replace(c, host_id=b.host_id)),
                     (replace(a, enabled=True), b, c), (a, replace(b, keyboard_channel=3), c)):
            with self.assertRaises(p.DecodeError):
                await t.merge_settings(self.packet(replace(initial, peers=rows)))
        with self.assertRaises(p.DecodeError):
            await t.merge_settings(self.packet(replace(initial, layout=b"unknown")))
        with self.assertRaises(p.DecodeError):
            await t.merge_settings(replace(self.packet(initial), channel=2))
        outer = p.wrap_device_packet(*IDENTITY, 2, self.packet(initial).encode(),
                                     d.device_key, d.device_key_id)
        with self.assertRaises(p.DecodeError):
            await t.dispatch(outer)
        self.assertIs(d.settings, initial)
        d.settings = replace(initial, layout=b"unknown")
        await d.update_settings({}, reset=True)
        self.assertEqual(d.settings.layout, b"horizontal")
        self.assertFalse(d.settings.peers[2].enabled)

    async def test_equal_local_edit_is_published_once_and_echo_is_idempotent(self):
        d, t = self.daemon, self.tunnel
        await d.update_settings({"ctrl_key": True})
        original = d.settings
        await t.merge_settings(self.packet(original))
        t.send_device.assert_awaited_once()
        conflict = replace(original, ctrl_key=False)
        await t.merge_settings(self.packet(conflict))
        self.assertEqual(d.settings, replace(original, counter=original.counter + 1))
        for snapshot in (conflict, d.settings, d.settings):
            await t.merge_settings(self.packet(snapshot))
        self.assertEqual(t.send_device.await_count, 2)

    async def test_equal_wire_conflicts_converge_in_both_orders(self):
        d, t = self.daemon, self.tunnel
        a = d.settings
        b = replace(a, ctrl_key=True)
        for initial, incoming in ((a, b), (b, a)):
            d.settings = initial
            await t.merge_settings(self.packet(incoming))
            self.assertEqual(d.settings, b)
        await t.merge_settings(self.packet(a))
        t.send_device.assert_awaited_once()

    async def test_reset_or_disable_during_monitor_lookup_or_warp(self):
        from hyprland_edges import Monitor
        for wait_at in ("get_monitors", "move_cursor"):
            d, t = self.daemon, self.tunnel
            d.settings = d.seed_settings()
            d.desktop = Mock()
            d.desktop.get_monitors.return_value = [Monitor("display", 0, 0, 100, 100)]
            started, release = threading.Event(), threading.Event()
            def pause(*args):
                started.set()
                if not release.wait(2):
                    raise TimeoutError()
                return [Monitor("display", 0, 0, 100, 100)]
            getattr(d.desktop, wait_at).side_effect = pause
            task = asyncio.create_task(d.crossing(t, p.InitiateFlowPacket(p.Edge.LEFT, .5)))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 1))
                if wait_at == "get_monitors":
                    await d.update_settings({}, reset=True)
                else:
                    await d.update_settings({"on": False})
            finally:
                release.set()
                await task
            if wait_at == "get_monitors":
                d.desktop.move_cursor.assert_not_called()
            self.assertFalse(any(isinstance(c.args[0], p.SetCurrentHostPacket)
                                 for c in t.send_device.call_args_list))

    async def test_failed_send_expiry_and_replacement_revoke_authorization(self):
        d, t = self.daemon, self.tunnel
        t.send_device.side_effect = OSError()
        with self.assertRaises(OSError):
            await d.send_initiate_flow(1, p.Edge.LEFT, .5)
        self.assertIsNone(d.awaiting)
        t.send_device.side_effect = None
        await d.send_initiate_flow(1, p.Edge.LEFT, .5)
        self.assertIs(d.awaiting, t)
        d.expire_crossing(d.generation)
        self.assertIsNone(d.awaiting)
        await d.send_initiate_flow(1, p.Edge.LEFT, .5)
        replacement = Tunnel(d, None, Mock(), False)
        replacement.host, replacement.peer_channel = MAC, 1
        d.claim(replacement)
        self.assertIsNone(d.awaiting)
        await d.crossing(t, p.SetCurrentHostPacket(1))
        d.switcher.submit_crossing.assert_not_called()

    async def test_discovery_drops_work_before_decrypt_and_caps_global_broadcasts(self):
        from flow_daemon import DISCOVERY_MAX_FRAME, TokenBucket
        d = self.daemon
        d.udp = [Mock(), Mock()]
        packet = p.InitiateDiscoveryPacket(*IDENTITY, 1, True)
        with patch("flow_daemon.open_packet") as decrypt, patch("flow_daemon.decode_discovery",
                return_value=packet), patch.object(d, "send_udp") as send:
            d.discovery(bytes(DISCOVERY_MAX_FRAME + 1), LOCAL_IP)
            decrypt.assert_not_called()
            d.ingress = TokenBucket(3)
            d.broadcast_replies = TokenBucket(1)
            for idx in range(4):
                d.discovery(b"x", f"192.0.2.{idx + 1}")
            self.assertEqual(decrypt.call_count, 3)
            broadcasts = sum((d.broadcast, d.discovery_port) in c.args[1] for c in send.call_args_list)
            self.assertEqual(broadcasts, 1)
            d.recent[(LOCAL_IP, p.PingPacket, 1)] = 0
            await d.rpc("discover_peers", {"peer_ip": "192.0.2.10"})
            self.assertFalse(d.recent)
            self.assertFalse(d.peers)

    async def test_disconnect_releases_chunks_and_invalidates_pending_work(self):
        d = self.daemon
        writer = Mock()
        writer.wait_closed = AsyncMock()
        async def incomplete(t, expected):
            t.host, t.peer_channel = b"other", 0
            d.claim(t)
            d.awaiting, d.awaiting_generation = t, d.generation
            part = replace(p.wrap_global_packet(b"other", b"piece"), chunk_count=2)
            t.global_chunks.add(part)
            self.assertEqual(d.budget.used, 5)
            raise ConnectionResetError()
        with patch.object(Tunnel, "serve", incomplete):
            await d.connection(None, writer)
        self.assertIsNone(d.awaiting)
        self.assertEqual(d.budget.used, 0)
        d.switcher.invalidate.assert_called_once()

    async def test_pulse_expires_incomplete_transfer_on_active_peer(self):
        t = self.tunnel
        t.global_chunks.add(replace(p.wrap_global_packet(MAC, b"part"), chunk_count=2))
        t.global_chunks.started -= p.CHUNK_TIMEOUT
        with patch("flow_daemon.HEARTBEAT_INTERVAL", 0), self.assertRaisesRegex(p.DecodeError, "timed out"):
            await t.pulse()
        self.assertEqual(self.daemon.budget.used, 0)


class MemoryWayland:
    """Exercise the real adapter's MIME parsing and fingerprint logic with memory I/O."""
    def __init__(self):
        from flow_clipboard import WaylandClipboard
        self.backend = WaylandClipboard()
        self.backend._snapshot = self.read
        self.backend._install = self.write
        self.owned = None
        self.backend.owns_selection = lambda: self.owned is not None and self.selection is self.owned
        self.selection = None
        self.published = asyncio.Queue()

    async def read(self):
        return self.selection

    async def write(self, mime, data):
        from flow_clipboard import FILES_MIME, TEXT, local_roots, snapshot, png_to_marconi_image
        if mime == FILES_MIME:
            self.selection = snapshot(roots=local_roots(data, mime))
        elif mime == "image/png":
            image = p.ClipboardImage(*png_to_marconi_image(data))
            self.selection = snapshot(((b"image", image.encode()),))
        else:
            wire = next(w for w, aliases in TEXT.items() if mime in aliases)
            self.selection = snapshot(((wire, data),))
        self.owned = self.selection
        self.published.put_nowait((mime, data))


class ClipboardLoopback(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.wayland_a, self.wayland_b = MemoryWayland(), MemoryWayland()
        opts = dict(bind=LOCAL_IP, broadcast=LOCAL_IP, tcp_port=0, udp_discovery_port=0, udp_nodestore_port=0)
        self.a = FlowDaemon(STATE, clipboard=self.wayland_a.backend, transfer_cache=self.base/"a", **opts)
        from hyprland_edges import Monitor
        desk = Mock()
        desk.get_monitors.return_value = [Monitor("screen", 0, 0, 300, 200)]
        self.b = FlowDaemon({**STATE, "host_id":MAC.decode(), "mouse":{**STATE["mouse"], "channel":1}},
                            clipboard=self.wayland_b.backend, transfer_cache=self.base/"b", desktop=desk, **opts)
        self.settings = replace(MAC_SETTINGS, layout=b"horizontal", copy_paste=True,
                                peers=(p.Peer(0, 0xffffffff, b"", False), self.b.local_peer, self.a.local_peer))
        for daemon in (self.a, self.b):
            daemon.settings = self.settings
            await daemon.start()
            self.addAsyncCleanup(daemon.close)
        reader, writer = await asyncio.open_connection(LOCAL_IP, self.a.tcp_port)
        self.b.spawn(self.b.connection(reader, writer, True, LINUX))
        await self.until(lambda: MAC in self.a.tunnels and LINUX in self.b.tunnels and
                         (self.a.tunnels[MAC].received_settings or self.b.tunnels[LINUX].received_settings))
        self.ab = self.a.tunnels[MAC]
        self.ba = self.b.tunnels[LINUX]

    async def until(self, predicate):
        async def wait():
            while not predicate():
                await asyncio.sleep(.01)
        await asyncio.wait_for(wait(), 8)

    async def offer(self, snapshot):
        self.wayland_a.selection = snapshot
        await self.a.clipboard.announce((self.ab,), crossing=True)

    async def pasted(self):
        return await asyncio.wait_for(self.wayland_b.published.get(), 8)

    async def test_crossing_text_retention_echo_prevention_and_owner_disconnect(self):
        from flow_clipboard import snapshot
        data = b"private-loopback-text-12345"
        self.a.set_owner(LINUX, 2)
        self.wayland_a.selection = snapshot(((b"text/plain", data),))
        with self.assertLogs("omarchy-flow", level="DEBUG") as logs:
            # Record actual wire order. The receiving daemon materializes only after its crossing.
            order = []
            send_outer = self.ab._send
            async def record(packet):
                if isinstance(packet, p.GlobalDataPacket):
                    order.append(type(p.decode_packet(p.unwrap_global_packet(packet))))
                elif isinstance(packet, p.DeviceDataPacket):
                    order.append(type(p.decode_packet(p.unwrap_device_packet(packet, self.b.device_key,
                                                                              self.b.device_key_id))))
                await send_outer(packet)
            with patch.object(self.ab, "_send", record):
                await self.a.send_initiate_flow(1, p.Edge.LEFT, .5)
                self.assertEqual((await self.pasted())[1], data)
            self.assertLess(order.index(p.ClipboardUpdatePacket), order.index(p.InitiateFlowPacket))
            self.assertEqual(self.b.active_owner, MAC)
            await self.until(lambda: self.a.active_owner == MAC)
            with patch.object(self.ba, "send_global", wraps=self.ba.send_global) as send:
                await self.b.clipboard.announce((self.ba,), crossing=True)
                send.assert_not_awaited()
            status = await self.b.rpc("get_status", {})
            self.assertEqual(status["clipboard"], dict(enabled=True, busy=False,
                             last_summary=f"Clipboard IN · text ({len(data)} B)"))
            self.assertNotIn(data.decode(), json.dumps(status) + str(logs.output))
            await self.b.close()
            await self.until(lambda: self.a.active_owner is None)
            self.assertEqual(self.a.active_owner_os, 0)

    async def test_owner_monitor_and_while_owner_text(self):
        from flow_clipboard import snapshot
        self.a.set_owner(LINUX, 2)
        self.wayland_a.selection = snapshot(((b"text/plain", b"sampled"),))
        await self.until(lambda: self.b.clipboard.remote)
        self.assertTrue(self.wayland_b.published.empty())
        await self.b.take_ownership()
        self.assertEqual((await self.pasted())[1], b"sampled")
        await self.offer(snapshot(((b"text/plain", b"second"),)))
        self.assertEqual((await self.pasted())[1], b"second")

    async def test_reverse_direction_after_local_copy(self):
        from flow_clipboard import snapshot
        self.b.set_owner(MAC, 2)
        await self.offer(snapshot(((b"text/plain", b"first"),)))
        await self.pasted()
        self.a.set_owner(LINUX, 2)
        self.wayland_b.selection = snapshot(((b"text/html", b"<p>reverse</p>"),))
        await self.b.clipboard.announce((self.ba,), crossing=True)
        self.assertEqual(await asyncio.wait_for(self.wayland_a.published.get(), 2),
                         ("text/html", b"<p>reverse</p>"))

    async def test_retina_image_multichunk(self):
        import random
        from flow_clipboard import snapshot, png_to_marconi_image
        self.b.set_owner(MAC, 2)
        # 2880 x 1800 incompressible RGBA exceeds both default chunk size and 16 MiB after deflate.
        w, h = 2880, 1800
        pixels = random.Random(1).randbytes(w * h * 4)
        image = p.ClipboardImage(w,h,pixels)
        with patch.object(self.ab, "_send", wraps=self.ab._send) as send:
            await self.offer(snapshot(((b"image", image.encode()),)))
            mime, png = await self.pasted()
            self.assertEqual(mime, "image/png")
            self.assertEqual(png_to_marconi_image(png), (w,h,pixels))
            chunks = [c.args[0] for c in send.await_args_list if isinstance(c.args[0], p.GlobalDataPacket)
                      and c.args[0].chunk_count > 1]
            self.assertEqual([c.chunk_number for c in chunks], list(range(1, chunks[0].chunk_count + 1)))
        self.assertEqual(self.b.budget.used, 0)

    async def test_tree_and_multiple_ranges(self):
        from flow_clipboard import snapshot
        from flow_transfer import OfferedRoot, MAX_RANGE
        self.b.set_owner(MAC, 2)
        root = self.base / "private-fixture-folder"
        nested = root/"nested"
        nested.mkdir(parents=True)
        large = nested/"file"
        data = b"x"*MAX_RANGE + b"tail"
        large.write_bytes(data)
        empty = self.base/"empty"
        empty.touch()
        link = root/"excluded"
        link.symlink_to(self.base)
        with patch.object(self.b.clipboard, "request", wraps=self.b.clipboard.request) as requests:
            await self.offer(snapshot(roots=tuple(OfferedRoot.capture(i) for i in (root, empty))))
            await self.pasted()
            ranges = [c.args[5:] for c in requests.await_args_list if c.args[2] is p.GetFileDataPacket]
            self.assertEqual(ranges, [(0, MAX_RANGE), (MAX_RANGE, 4)])
        dst, zero = (x.path for x in self.wayland_b.selection.roots)
        self.assertEqual((dst/"nested"/"file").read_bytes(), data)
        self.assertFalse((dst/"excluded").exists())
        self.assertEqual(zero.stat().st_size, 0)
        await self.until(lambda: self.b.clipboard.job is None)
        status = json.dumps(await self.b.rpc("get_status", {}))
        self.assertNotIn(root.name, status)
        self.assertNotIn(str(self.base), status)
        self.assertIn("2 files (8.0 MiB)", status)

    async def test_disabled_denied_and_unauthorized_path_and_link(self):
        from flow_clipboard import snapshot
        from flow_transfer import OfferedRoot, TransferError
        folder = self.base/"offered"
        folder.mkdir()
        outside = self.base/"private"
        outside.write_bytes(b"synthetic")
        (folder/"link").symlink_to(outside)
        selection = snapshot(roots=(OfferedRoot.capture(folder),))
        await self.offer(selection)
        await self.until(lambda: self.b.clipboard.remote)
        errors = []
        dispatch = self.b.clipboard.dispatch
        async def capture(t, packet):
            if type(packet) is p.ErrorPacket:
                errors.append(packet)
            await dispatch(t, packet)
        with patch.object(self.b.clipboard, "dispatch", capture):
            for path in (outside, folder/"link"):
                desc = p.FileDescriptor(bytes(path), p.DirectoryEntry(1, 1, b"x", 0o600, 0, 0, 0, 1))
                with self.assertRaises(TransferError):
                    await self.b.clipboard.request(self.ba, selection.provider_id, p.GetFileDataPacket,
                                                   p.FileDataPacket, desc, 0, 1)
            await self.a.update_settings({"copy_paste":False})
            await self.until(lambda: not self.b.clipboard.enabled())
            self.b.set_owner(MAC, 2)
            await self.ab.send_global(p.ClipboardUpdatePacket(LINUX, selection.provider_id,(b"file",)))
            with self.assertRaises(TransferError):
                await self.b.clipboard.request(self.ba, selection.provider_id, p.GetFileDescriptorsPacket,
                                               p.FileDescriptorsPacket, True)
            self.assertTrue(self.wayland_b.published.empty())
            self.assertFalse(self.a.clipboard.local or self.b.clipboard.remote or self.b.clipboard.waiters)
        self.assertEqual([e.error.code for e in errors], [-1]*3)
        self.assertTrue(all(e.error.message == b"Unavailable" for e in errors))

    async def test_hostile_descriptors_never_published(self):
        from flow_clipboard import snapshot
        from flow_transfer import OfferedRoot
        self.b.set_owner(MAC, 2)
        root = self.base/"source"
        root.mkdir()
        for name, kind in [(b"../escape", 1), (b"/etc/passwd", 1), (b"a/b", 1), (b"a\\b", 1),
                           (b"nul\x00name", 1), (b"link", 3)]:
            selection = snapshot(roots=(OfferedRoot.capture(root),))
            entry = p.DirectoryEntry(1, kind, name, 0, 0, 0, 0, 0)
            served = asyncio.Event()
            async def fake(t, req, local):
                await t.send_global(p.FileDescriptorsPacket(self.a.host, req.provider_id, req.request_id,
                                    (p.FileDescriptor(b"/opaque", entry),), 3))
                served.set()
            with patch.object(self.a.clipboard, "serve", fake):
                self.a.clipboard.revoke_local()
                await self.offer(selection)
                await asyncio.wait_for(served.wait(), 2)
                await self.until(lambda: self.b.clipboard.job is None)
            self.assertTrue(self.wayland_b.published.empty())
            self.assertFalse(list(self.b.clipboard.cache.glob("*/*")))

    async def test_setting_revocation_aborts_materialization(self):
        from flow_clipboard import snapshot
        self.b.set_owner(MAC, 2)
        for changes in ({"copy_paste":False}, {"on":False}, {}):
            await self.b.update_settings({"on":True, "copy_paste":True})
            await self.until(lambda: self.a.settings == self.b.settings and self.a.clipboard.allowed(self.ab))
            with patch.object(self.a.clipboard, "serve", AsyncMock()):
                await self.offer(snapshot(((b"text/plain", b"pending"),)))
                await self.until(lambda: bool(self.b.clipboard.waiters))
                await self.b.update_settings(changes, reset=not changes)
                self.assertFalse(self.b.clipboard.remote or self.b.clipboard.waiters)
                self.assertFalse(self.b.clipboard.job)
            self.assertTrue(self.wayland_b.published.empty())

    async def test_overlapping_requests_match_distinct_ids_and_formats(self):
        from flow_clipboard import snapshot
        values = ((b"text/plain", b"first representation"), (b"text/html", b"<b>second</b>"))
        selection = snapshot(values)
        await self.offer(selection)
        await self.until(lambda: self.b.clipboard.remote)
        replies = await asyncio.gather(*(self.b.clipboard.request(self.ba, selection.provider_id,
                                         p.GetFormatDataPacket, p.FormatDataPacket, fmt) for fmt, _ in values))
        self.assertNotEqual(replies[0].request_id, replies[1].request_id)
        self.assertEqual(tuple((r.mime_type, r.data.storage) for r in replies), values)
        self.assertFalse(self.b.clipboard.waiters)

    async def test_disconnect_cancels_waiting_import(self):
        from flow_clipboard import snapshot
        self.b.set_owner(MAC, 2)
        with patch.object(self.a.clipboard, "serve", AsyncMock()):
            await self.offer(snapshot(((b"text/plain", b"unpublished"),)))
            await self.until(lambda: self.b.clipboard.waiters)
            await self.a.close()
            await self.until(lambda: not self.b.tunnels)
        self.assertFalse(self.b.clipboard.job or self.b.clipboard.waiters or self.b.clipboard.remote)
        self.assertTrue(self.wayland_b.published.empty())

    async def test_correlation_timeout_and_stray_reply(self):
        from flow_clipboard import snapshot
        selection = snapshot(((b"text/plain", b"fixture"),))
        await self.offer(selection)
        await self.until(lambda: self.b.clipboard.remote)
        async def stray(t, req, local):
            await t.send_global(p.ErrorPacket(LINUX, req.provider_id, b"0"*32,
                                              p.WireException(-1, b"private error", ())))
        with patch.object(self.a.clipboard, "serve", stray), patch.object(p, "TRANSFER_TIMEOUT", .1):
            with self.assertRaises(TimeoutError):
                await self.b.clipboard.request(self.ba, selection.provider_id, p.GetFormatDataPacket,
                                               p.FormatDataPacket, b"text/plain")
        self.assertFalse(self.b.clipboard.waiters)

    async def test_heartbeat_interleaves_and_global_message_reassembles(self):
        import random
        waiting, release = asyncio.Event(), asyncio.Event()
        order = []
        original = self.ab._send
        async def pause(outer):
            await original(outer)
            order.append(type(outer))
            if len(order) == 1:
                waiting.set()
                await release.wait()
        packet = p.FormatDataPacket(LINUX, b"a"*32, b"b"*32, b"text/plain",
                                    p._buffer(random.Random(2).randbytes(3 << 20)))
        later = replace(packet, request_id=b"c"*32)
        delivered = []
        dispatch = self.b.clipboard.dispatch
        async def readback(tunnel, inner):
            if inner in (packet, later):
                delivered.append(inner)
            await dispatch(tunnel, inner)
        with patch.object(self.ab, "_send", pause), patch.object(self.b.clipboard, "dispatch", readback):
            sender = asyncio.create_task(self.ab.send_global(packet))
            await asyncio.wait_for(waiting.wait(), 2)
            second = asyncio.create_task(self.ab.send_global(later))
            pulse = asyncio.create_task(self.ab.heartbeat())
            await asyncio.sleep(0)
            release.set()
            await asyncio.gather(sender, second, pulse)
            await self.until(lambda: len(delivered) == 2)
        self.assertEqual(delivered, [packet, later])
        self.assertEqual(order, [p.GlobalDataPacket, p.HeartbeatPacket, p.GlobalDataPacket,
                                 p.GlobalDataPacket, p.GlobalDataPacket])

    async def test_large_clipboard_compression_runs_off_event_loop_and_preserves_checks(self):
        import threading
        loop_thread = threading.get_ident()
        encode_threads = []
        entered, release = threading.Event(), threading.Event()
        original_deflate = p._deflate_buffer

        def blocking_deflate(buf):
            encode_threads.append(threading.get_ident())
            entered.set()
            release.wait(2)
            return original_deflate(buf)

        packet = p.FormatDataPacket(LINUX, b"a" * 32, b"b" * 32, b"text/plain", p._buffer(b"x" * 1024))
        allow = True
        started_calls = []
        sent_chunks = []
        original_send = self.ab._send

        async def record_send(outer):
            sent_chunks.append(type(outer))
            await original_send(outer)

        with patch.object(p, "_deflate_buffer", blocking_deflate), \
             patch.object(self.ab, "_send", record_send):
            task = asyncio.create_task(self.ab.send_global(
                packet, allowed=lambda: allow, started=lambda: started_calls.append(True)))
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            # While compression blocks on the worker thread, the event loop and global lock stay free.
            await asyncio.wait_for(self.ab.heartbeat(), 1)
            await asyncio.wait_for(self.ab.send_global(p.SetOwnerPacket(LINUX, 1, LINUX, 1)), 1)
            self.assertEqual(sent_chunks, [p.HeartbeatPacket, p.GlobalDataPacket])
            # Revoking authorization before compression completes aborts before started()/send.
            allow = False
            release.set()
            self.assertFalse(await asyncio.wait_for(task, 2))
            self.assertEqual(started_calls, [])
            self.assertEqual(sent_chunks, [p.HeartbeatPacket, p.GlobalDataPacket])
            self.assertEqual(len(encode_threads), 1)
            self.assertNotEqual(encode_threads[0], loop_thread)

            # Cancelling while compressing sets ENCODE_STOP cleanly without closing the tunnel.
            entered.clear()
            saw_stop = threading.Event()

            def cancel_deflate(buf):
                stop = p.ENCODE_STOP.get()
                entered.set()
                if stop is not None and stop.wait(2):
                    saw_stop.set()
                    raise p.EncodeCancelled()
                return original_deflate(buf)

            with patch.object(p, "_deflate_buffer", cancel_deflate):
                task2 = asyncio.create_task(self.ab.send_global(packet, allowed=lambda: True))
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                task2.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task2, 2)
                self.assertTrue(saw_stop.is_set())
                self.assertFalse(self.ab.writer.is_closing())

    async def test_frozen_offer_range_errors_and_private_summaries(self):
        from flow_clipboard import snapshot
        from flow_transfer import OfferedRoot, TransferError
        folder = self.base/"offered-folder"
        folder.mkdir()
        file = folder/"selected"
        file.write_bytes(b"original")
        selection = snapshot(roots=(OfferedRoot.capture(folder),))
        await self.offer(selection)
        await self.until(lambda: self.b.clipboard.remote)

        async def request(cls, response, *args):
            return await self.b.clipboard.request(self.ba, selection.provider_id, cls, response, *args)

        (folder/"later").write_bytes(b"x")
        await request(p.GetFileDescriptorsPacket, p.FileDescriptorsPacket, True)
        await self.until(lambda: self.a.clipboard.last_summary == "Clipboard OUT · 1 files offered")
        listing = await request(p.GetFolderFileDescriptorsPacket, p.FileDescriptorsPacket, bytes(folder), True)
        desc, = listing.descriptors
        self.assertEqual(desc.entry.name, b"selected")
        first = await request(p.GetFileDataPacket, p.FileDataPacket, desc, 0, 2)
        self.assertEqual(first.data.storage, b"or")
        await self.until(lambda: self.a.clipboard.last_summary == "Clipboard OUT · file data served")
        # The client converts only a correlated error for this ID into TransferError.
        with file.open("ab") as out:
            out.write(b"more")
        for wanted in (desc, replace(desc, path=bytes(folder/"later"))):
            with self.assertRaises(TransferError):
                await request(p.GetFileDataPacket, p.FileDataPacket, wanted, 2, 2)

    async def test_reannouncing_same_file_provider_pastes_twice(self):
        from flow_clipboard import snapshot
        from flow_transfer import OfferedRoot
        source = self.base/"selected"
        source.write_bytes(b"copy twice")
        self.b.set_owner(MAC, 2)
        offer = snapshot(roots=(OfferedRoot.capture(source),))
        paths = []
        for _ in range(2):
            await self.offer(offer)
            await self.pasted()
            await self.until(lambda: self.b.clipboard.job is None)
            self.assertEqual(self.a.clipboard.local.provider_id, offer.provider_id)
            paths.append(self.wayland_b.selection.roots[0].path)
        self.assertNotEqual(*paths)
        self.assertEqual([p.read_bytes() for p in paths], [b"copy twice"] * 2)

    async def test_new_local_copy_mid_file_download_wins(self):
        from flow_clipboard import snapshot
        from flow_transfer import OfferedRoot
        self.b.set_owner(MAC, 2)
        source = self.base/"offered"
        source.write_bytes(b"ab")
        newer = snapshot(((b"text/plain", b"new local copy"),))
        request = self.b.clipboard.request
        async def interpose(tunnel, provider, cls, response, *args):
            reply = await request(tunnel, provider, cls, response, *args)
            if cls is p.GetFileDataPacket:
                self.wayland_b.selection = newer
            return reply
        with patch.object(self.b.clipboard, "request", interpose):
            await self.offer(snapshot(roots=(OfferedRoot.capture(source),)))
            await self.until(lambda: self.wayland_b.selection is newer)
            await self.until(lambda: self.b.clipboard.job is None)
        self.assertIs(self.wayland_b.selection, newer)
        self.assertTrue(self.wayland_b.published.empty())
        self.assertFalse(list(self.b.clipboard.cache.glob("*/*")))

    async def test_nonowner_clear_and_replacement_revoke_text_and_files(self):
        from flow_clipboard import snapshot
        from flow_transfer import OfferedRoot, TransferError
        source = self.base/"offered"
        source.write_bytes(b"x")
        root = OfferedRoot.capture(source)
        self.a.set_owner(MAC, 2)
        for replacement in (None, snapshot(((b"text/plain", b"new"),))):
            old = snapshot(((b"text/plain", b"old"),), (root,))
            await self.offer(old)
            await self.until(lambda: self.b.clipboard.remote and self.b.clipboard.remote[1].provider_id == old.provider_id)
            self.wayland_a.selection = replacement
            if replacement is None:
                await self.until(lambda: self.a.clipboard.local is None)
            for cls, response, args in (
                    (p.GetFormatDataPacket, p.FormatDataPacket, (b"text/plain",)),
                    (p.GetFileDataPacket, p.FileDataPacket, (root.entries[source].descriptor, 0, 1))):
                with self.assertRaises(TransferError):
                    await self.b.clipboard.request(self.ba, old.provider_id, cls, response, *args)
            self.assertIsNone(self.a.clipboard.local)

    async def test_identical_plain_text_after_owner_exit_is_announced(self):
        from flow_clipboard import snapshot
        self.b.set_owner(MAC, 2)
        text = ((b"text/plain", b"same"),)
        await self.offer(snapshot(text))
        await self.pasted()
        await self.until(lambda: self.b.clipboard.job is None)
        self.wayland_b.selection = snapshot(text)
        await self.b.clipboard.announce((self.ba,), crossing=True)
        await self.until(lambda: self.a.clipboard.remote is not None)
        self.assertEqual(self.a.clipboard.remote[1].provider_id, self.wayland_b.selection.provider_id)

    async def test_slow_or_failed_capture_and_slow_peer_do_not_block_crossing(self):
        from flow_clipboard import snapshot
        started, release = asyncio.Event(), asyncio.Event()
        async def slow(*args, **kwargs):
            started.set()
            await release.wait()

        try:
            for capture in (slow, AsyncMock(side_effect=OSError())):
                self.a.invalidate_crossings()
                with patch.object(self.a.clipboard.backend, "snapshot_local", capture), patch.object(
                        self.ab, "send_device", AsyncMock()) as device:
                    await asyncio.wait_for(self.a.send_initiate_flow(1, p.Edge.LEFT, .5), .6)
                    self.assertIsInstance(device.await_args.args[0], p.InitiateFlowPacket)
            self.a.invalidate_crossings()
            self.wayland_a.selection = snapshot(((b"text/plain", b"ready"),))
            other = Mock(host=b"another", peer_channel=0, send_global=slow)
            self.a.settings = replace(self.settings, peers=(p.Peer(0, 0, other.host, True),
                                                           *self.settings.peers[1:]))
            started.clear()
            with patch.dict(self.a.tunnels, {other.host: other}), patch.object(
                    self.ab, "send_device", AsyncMock()) as device:
                await asyncio.wait_for(self.a.send_initiate_flow(1, p.Edge.LEFT, .5), .2)
                self.assertTrue(started.is_set())
                self.assertIsInstance(device.await_args.args[0], p.InitiateFlowPacket)
                self.assertIn(self.ab, self.a.clipboard.recipients)
                self.assertNotIn(other, self.a.clipboard.recipients)
        finally:
            release.set()

    async def test_revocation_while_announce_waits_under_each_send_lock(self):
        from flow_clipboard import snapshot
        self.wayland_a.selection = snapshot(((b"text/plain", b"pending"),))
        for lock in (self.ab._global_send_lock, self.ab._frame_send_lock):
            self.a.clipboard.revoke_local()
            async with lock:
                task = asyncio.create_task(self.a.clipboard.announce((self.ab,), crossing=True))
                await self.until(lambda: lock._waiters)
                self.assertNotIn(self.ab, self.a.clipboard.recipients)
                self.a.clipboard.invalidate()
            await task
            self.assertNotIn(self.ab, self.a.clipboard.recipients)
            self.assertIsNone(self.b.clipboard.remote)

    async def test_unrelated_teardown_preserves_inflight_import(self):
        from flow_clipboard import snapshot
        self.b.set_owner(MAC, 2)
        got, release = asyncio.Event(), asyncio.Event()
        serve = self.a.clipboard.serve
        async def pause(*args):
            got.set()
            await release.wait()
            await serve(*args)
        with patch.object(self.a.clipboard, "serve", pause):
            await self.offer(snapshot(((b"text/plain", b"survives"),)))
            await asyncio.wait_for(got.wait(), 2)
            manager = self.b.clipboard
            epoch, job = manager.epoch, manager.job
            _, writer = await asyncio.open_connection(LOCAL_IP, self.b.tcp_port)
            await self.until(lambda: len(self.b.writers) > 1)
            writer.close()
            await writer.wait_closed()
            await self.until(lambda: len(self.b.writers) == 1)
            self.assertEqual(manager.epoch, epoch)
            self.assertIs(manager.job, job)
            self.assertFalse(job.done())
            release.set()
            self.assertEqual((await self.pasted())[1], b"survives")

    async def test_transient_wayland_publication_retries_at_most_twice(self):
        from flow_clipboard import snapshot
        self.b.set_owner(MAC, 2)
        write = self.wayland_b.write
        count = 0
        async def transient(*args):
            nonlocal count
            count += 1
            if count < 3:
                raise OSError()
            await write(*args)
        with patch.object(self.wayland_b.backend, "_install", transient):
            await self.offer(snapshot(((b"text/plain", b"retry"),)))
            self.assertEqual((await self.pasted())[1], b"retry")
        self.assertEqual(count, 3)
        with patch.object(self.wayland_b.backend, "_install", AsyncMock(side_effect=OSError())) as failed:
            await self.offer(snapshot(((b"text/plain", b"fail"),)))
            await self.until(lambda: failed.await_count > 0)
            await self.until(lambda: self.b.clipboard.job is None)
            self.assertEqual(failed.await_count, 3)
            self.assertIsNone(self.b.clipboard.remote)

    async def test_new_offer_cancels_partial_and_clears_waiters(self):
        from flow_clipboard import snapshot
        from flow_transfer import OfferedRoot
        large = self.base/"large"
        large.write_bytes(b"start")
        self.b.set_owner(MAC, 2)
        waiting = asyncio.Event()
        original = self.a.clipboard.serve
        async def pause_data(t, req, local):
            if type(req) is p.GetFileDataPacket:
                waiting.set()
                await asyncio.Event().wait()
            else:
                await original(t, req, local)
        with patch.object(self.a.clipboard, "serve", pause_data):
            first = snapshot(roots=(OfferedRoot.capture(large),))
            await self.offer(first)
            await asyncio.wait_for(waiting.wait(), 2)
            self.assertEqual(len(list(self.b.clipboard.cache.glob(f"staging/{first.provider_id.decode()}-*/large"))), 1)
            await self.offer(snapshot(((b"text/plain", b"replacement"),)))
            self.assertEqual((await self.pasted())[1], b"replacement")
        self.assertFalse(list(self.b.clipboard.cache.glob("*/*")))
        self.assertFalse(self.b.clipboard.waiters)
        self.assertTrue(self.wayland_b.published.empty())


if __name__ == "__main__":
    unittest.main()
