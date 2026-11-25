"""Foreground Linux Marconi peer. Flow hooks receive authenticated packets on the event loop."""
import argparse
import asyncio
from collections import OrderedDict, deque
from dataclasses import asdict, replace
import hashlib
import inspect
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import signal
import socket
import threading
import time

from cryptography.exceptions import InvalidTag

from bolt_hidpp import default_state_path, inventory_bolt_devices, load_state, provision_local_devices
from flow_control import (ControlServer, DEFAULTS, FLAGS, default_socket, load_preferences,
                          require, save_preferences, validate_preferences)
from hyprland_edges import DEFAULT_MOUSE, Hyprland, MouseEdges, flow_in_point, flow_out_info, segments
from flow_switcher import Switcher
from flow_clipboard_manager import ClipboardManager, REQUESTS, RESPONSES
from flow_transfer import LINUX_OS, TransferError, recover_cache
from marconi_packets import Edge
from fars import DecodeError
from marconi_crypto import DHEKeyExchange, derive_device_key
from marconi_packets import (
    HANDSHAKE_MAX_BLOCK, MAX_BLOCK, MAX_CLIPBOARD_BODY, BASE_INFLIGHT_BYTES, MAX_INFLIGHT_BYTES,
    CHUNK_TIMEOUT, TRANSFER_TIMEOUT, ENCODE_STOP, ByteBudget, _safe_text,
    CIPHER_SUITE, BeaconPacket, ChunkAssembler, ClientDeviceConnectPacket, ClientHelloPacket,
    DeviceDataPacket, FileDataPacket, FormatDataPacket, GlobalDataPacket, HeartbeatPacket,
    IgnoredPacket, InitiateDiscoveryPacket, InitiateFlowPacket, Peer, PingPacket,
    PromoteConnectionPacket, ServerDeviceConnectPacket, ServerHelloPacket, Session,
    SetCurrentHostPacket, SetOwnerPacket, Settings, SettingsPacket, decode_discovery,
    decode_inner_packet, decode_packet, encode_discovery, open_packet, read_frame, seal_packet,
    wrap_device_packet, wrap_global_packets, ClipboardUpdatePacket,
)


LOG = logging.getLogger("omarchy-flow")
HANDSHAKE_TIMEOUT = 10
HEARTBEAT_INTERVAL = 8
HEARTBEAT_TIMEOUT = 30
DEVICE_FIELDS = ("name", "device_id", "serial_number", "channel", "slot")
SETTINGS_GRACE = 3.0
CLIPBOARD_GLOBALS = frozenset(cls.wire_name() for cls in (ClipboardUpdatePacket, *REQUESTS, *RESPONSES))
# Disabled peers can receive a correlated denial; large data replies stay opaque.
DISABLED_GLOBALS = frozenset(cls.wire_name() for cls in REQUESTS) | {b"ErrorPacket"}


# Direction of each successive link along the three ordered layout slots.
LAYOUTS = {
    b"horizontal": (Edge.RIGHT, Edge.RIGHT), b"vertical": (Edge.BOTTOM, Edge.BOTTOM),
    b"left-top": (Edge.LEFT, Edge.BOTTOM), b"right-top": (Edge.RIGHT, Edge.BOTTOM),
    b"left-bottom": (Edge.BOTTOM, Edge.RIGHT), b"right-bottom": (Edge.BOTTOM, Edge.LEFT),
}


def resolve_peer_for_edge(settings, local_channel, edge, connected_hosts):
    if not settings or not settings.on or settings.layout not in LAYOUTS:
        return None
    first, second = LAYOUTS[settings.layout]
    routes = ({first: (1, 2)}, {first ^ 1: (0,), second: (2,)}, {second ^ 1: (1, 0)})
    for slot, peer in enumerate(settings.peers):
        if peer.channel == local_channel and peer.enabled:
            for index in routes[slot].get(edge, ()):
                candidate = settings.peers[index]
                if candidate.enabled and candidate.host_id in connected_hosts:
                    return candidate.channel
    return None


DISCOVERY_MAX_FRAME = 4096
PING_BACKOFF = 8.0


class TokenBucket:
    def __init__(self, rate):
        self.rate = self.tokens = rate
        self.updated = time.monotonic()

    def take(self):
        now = time.monotonic()
        self.tokens = min(self.rate, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


def validate_wire_settings(settings):
    peers = settings.peers
    hosts = [row.host_id for row in peers if row.host_id]
    if (settings.layout not in LAYOUTS or sorted(p.channel for p in peers) != [0, 1, 2]
            or len(set(hosts)) != len(hosts)
            or any((row.enabled and not row.host_id) or
                   row.keyboard_channel not in (0, 1, 2, 0xffffffff) for row in peers)):
        raise DecodeError("invalid wire settings")


def _identity(device):
    fields = tuple(device[key] for key in ("device_id", "serial_number", "channel"))
    if (any(type(n) is not int or not 0 <= n < 1 << 32 for n in fields)
            or fields[2] > 2):
        raise ValueError("invalid configured device identity or channel")
    return fields


def display_text(value):
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    return "".join(c if c.isprintable() else " " for c in value[:192])


async def _encode_global(packet):
    if not isinstance(packet, (FormatDataPacket, FileDataPacket)):
        return packet.encode()
    stop = threading.Event()
    def encode():
        token = ENCODE_STOP.set(stop)
        try:
            return packet.encode()
        finally:
            ENCODE_STOP.reset(token)
    worker = asyncio.create_task(asyncio.to_thread(encode))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        stop.set()
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not worker.cancelled():
            worker.exception()
        raise


class Tunnel:
    def __init__(self, daemon, reader, writer, client):
        self.daemon = daemon
        self.reader, self.writer = reader, writer
        self.client = client
        self._frame_send_lock = asyncio.Lock()
        self._global_send_lock = asyncio.Lock()
        self.key, self.key_id = daemon.device_key, daemon.device_key_id
        self.session = None
        self.host = None
        self.last_sent_settings = None
        self.received_settings = False
        self.peer_channel = None
        self.initial_owner_os = None
        self.device_chunks = ChunkAssembler(daemon.budget)
        self.global_chunks = ChunkAssembler(daemon.budget)
        self.discard_global_tail = False
        self.last_received_time = int(time.time())
        self.last_received_mono = time.monotonic()

    async def send(self, packet):
        async with self._frame_send_lock:
            await self._send(packet)

    async def _send(self, packet):
        frame = seal_packet(self.key, self.key_id, packet.encode(), self.session)
        self.writer.write(frame)
        await asyncio.wait_for(self.writer.drain(), HANDSHAKE_TIMEOUT)

    async def send_global(self, packet, *, allowed=None, started=None, committed=None):
        if allowed and not allowed():
            return False
        payload = await _encode_global(packet)
        async with self._global_send_lock:
            partial = False
            try:
                for chunk in wrap_global_packets(self.daemon.host, payload):
                    async with self._frame_send_lock:
                        if allowed and not allowed():
                            if partial:
                                self.writer.close()
                            return False
                        if started and chunk.chunk_number == 1:
                            started()
                        partial = chunk.chunk_number < chunk.chunk_count
                        await self._send(chunk)
                        if committed and not partial and (allowed is None or allowed()):
                            committed()
                return True
            except asyncio.CancelledError:
                if partial:
                    self.writer.close()
                raise
            except (OSError, TimeoutError):
                self.writer.close()
                raise

    async def send_device(self, packet):
        d = self.daemon
        outer = wrap_device_packet(*d.identity, packet.encode(), d.device_key, d.device_key_id)
        await self.send(outer)

    async def receive(self, expected=None):
        limit = MAX_BLOCK if self.session else HANDSHAKE_MAX_BLOCK
        if self.session and self.daemon.clipboard.allowed(self):
            limit = MAX_CLIPBOARD_BODY + 1024
        frame = await read_frame(self.reader, max_block=limit, expected_key_id=self.key_id,
                                 budget=self.daemon.budget)
        self.device_chunks.check_deadline()
        self.global_chunks.check_deadline()
        packet = decode_packet(open_packet(self.key, self.key_id, frame, self.session,
                                           max_body=min(limit, MAX_CLIPBOARD_BODY if limit > MAX_BLOCK else 16 * 1024 * 1024)))
        self.last_received_time = int(time.time())
        self.last_received_mono = time.monotonic()
        if expected is not None and type(packet) is not expected:
            raise DecodeError(f"unexpected packet {type(packet).__name__} for handshake phase")
        return packet

    async def receive_device(self, expected):
        d = self.daemon
        while True:
            packet = await self.receive()
            if isinstance(packet, HeartbeatPacket):
                continue
            if isinstance(packet, GlobalDataPacket):
                data = self.global_chunks.add(packet)
                if data is not None:
                    inner = decode_inner_packet(data, decode_optional=False)
                    if isinstance(inner, SetOwnerPacket) and inner.new_owner == packet.host_id == self.host:
                        # Apply only after the device handshake and enabled layout are confirmed.
                        self.initial_owner_os = (inner.new_flag, d.owner_revision)
                    elif isinstance(inner, IgnoredPacket):
                        LOG.debug("Ignoring optional inner global packet %s (v%d, %d bytes)",
                                  _safe_text(inner.type_name), inner.version,
                                  inner.payload_size)
                continue
            if not isinstance(packet, DeviceDataPacket):
                raise DecodeError(f"expected DeviceDataPacket, got {type(packet).__name__}")
            d.check_device(packet)
            frame = self.device_chunks.add(packet)
            if frame is None:
                continue
            inner = decode_inner_packet(open_packet(d.device_key, d.device_key_id, frame), decode_optional=False)
            if isinstance(inner, IgnoredPacket):
                LOG.debug("Ignoring optional inner device packet %s (v%d, %d bytes)",
                          _safe_text(inner.type_name), inner.version,
                          inner.payload_size)
                continue
            if type(inner) is not expected:
                raise DecodeError(f"expected {expected.__name__}, got {type(inner).__name__}")
            return inner

    def accept_hello(self, hello, expected_host):
        if (not hello.host_id or hello.host_id == self.daemon.host or hello.cipher_suite != CIPHER_SUITE
                or expected_host is not None and hello.host_id != expected_host):
            raise DecodeError("unexpected peer identity or cipher suite")
        self.host = hello.host_id

    async def handshake(self, expected_host):
        d = self.daemon
        if self.client:
            exchange = DHEKeyExchange()
            await self.send(ClientHelloPacket(d.host, CIPHER_SUITE, exchange.params))
            hello = await self.receive(ServerHelloPacket)
            self.accept_hello(hello, expected_host)
            key = exchange.derive_session_key(hello.params)
            session = hello.session
            await self.send(PromoteConnectionPacket(d.host))
        else:
            hello = await self.receive(ClientHelloPacket)
            self.accept_hello(hello, None)
            exchange = DHEKeyExchange(hello.params)
            key = exchange.derive_session_key(hello.params)
            session = Session(secrets.token_bytes(16), secrets.randbits(64), secrets.randbits(64))
            await self.send(ServerHelloPacket(d.host, session.inverted(), CIPHER_SUITE, exchange.params))
            promote = await self.receive(PromoteConnectionPacket)
            if promote.host_id != self.host:
                raise DecodeError("promotion host changed")
        self.key, self.key_id, self.session = key, exchange.params.key_id, session
        if self.client:
            await self.send_device(ClientDeviceConnectPacket(*d.identity, d.host))
            connect = await self.receive_device(ServerDeviceConnectPacket)
        else:
            connect = await self.receive_device(ClientDeviceConnectPacket)
        d.check_device(connect)
        if connect.host_id != self.host or connect.channel == d.identity[2]:
            raise DecodeError("invalid device connection identity")
        self.peer_channel = connect.channel
        d.claim(self)
        if not self.client:
            await self.send_device(ServerDeviceConnectPacket(*d.identity, d.host))

    async def initial_settings(self):
        d = self.daemon
        if d.settings is None:
            # Prefer the peer's existing layout. Options+ broadcasts its SettingsPacket
            # immediately upon OnDevicePeerHandshakeCompleted.
            await asyncio.sleep(SETTINGS_GRACE * (1 if self.client else 2))
        if self.received_settings:
            return
        snapshot = d.settings
        if snapshot is None:
            peers = [Peer(i, 0xffffffff, b"", False) for i in range(3)]
            peers[d.identity[2]] = Peer(d.identity[2], 0xffffffff, d.host, True)
            peers[self.peer_channel] = Peer(self.peer_channel, 0xffffffff, self.host, True)
            snapshot = Settings(0, b"horizontal", True, False, False, False, False, False,
                                0, 0, tuple(peers))
        await self.send_settings(snapshot)

    async def send_settings(self, settings):
        stamp = (settings.counter, hashlib.sha256(settings.encode()).digest())
        if stamp == self.last_sent_settings:
            return
        await self.send_device(SettingsPacket(*self.daemon.identity, settings))
        self.last_sent_settings = stamp

    def _local_peer_for(self, incoming):
        d = self.daemon
        kbd_channel = 0xffffffff
        if d.keyboard[0] and (
                incoming.keyboard_id, incoming.keyboard_serial_number) in ((0, 0), d.keyboard[:2]):
            kbd_channel = d.keyboard[2]
        return Peer(d.identity[2], kbd_channel, d.host, True)

    async def merge_settings(self, packet):
        d = self.daemon
        d.check_device(packet)
        if packet.channel != self.peer_channel:
            raise DecodeError("unexpected settings sender channel")
        incoming = packet.settings
        validate_wire_settings(incoming)
        peers = list(incoming.peers)
        slot = next(i for i, p in enumerate(peers) if p.channel == d.identity[2])
        previous = peers[slot]
        if previous.host_id and previous.host_id != d.host and previous.enabled:
            raise DecodeError("local channel is occupied by another enabled peer")
        self.received_settings = True
        current = d.settings
        if current is not None:
            delta = (incoming.counter - current.counter) % (1 << 32)
            if incoming == current:
                return
            if delta >= (1 << 31):
                await self.send_settings(current)
                return
            if delta == 0:
                if d.local_edit == current.counter:
                    # Publish the accepted local edit once at the next serial.
                    d.local_edit = None
                    d.settings = replace(current, counter=(current.counter + 1) % (1 << 32))
                    await d.broadcast_settings()
                    return
                if current.encode() > incoming.encode():
                    await self.send_settings(current)
                    return
        if d.reset_local:
            local_peer = Peer(d.identity[2], 0xffffffff, b"", False)
        elif not previous.enabled and (previous.host_id == d.host or
                                       (not previous.host_id and current is not None)):
            # A native peer can disable or remove an existing member. Only
            # initial pairing fills an empty local slot automatically.
            local_peer = previous
        else:
            local_peer = self._local_peer_for(incoming)
        peers[slot] = local_peer
        corrected = previous != local_peer
        snapshot = replace(incoming, peers=tuple(peers),
                           counter=(incoming.counter + int(corrected)) % (1 << 32))
        validate_wire_settings(snapshot)
        d.settings = snapshot
        d.clipboard_settings_changed()
        d.local_edit = None
        d.invalidate_crossings()
        d.event(f"Settings sync · {snapshot.counter}")
        LOG.info("Settings sync counter=%d layout=%s kbd_link=%s ctrl_key=%s peers=%s",
                 snapshot.counter, _safe_text(snapshot.layout), snapshot.keyboard_link, snapshot.ctrl_key,
                 [(p.channel, _safe_text(p.host_id), p.enabled) for p in peers])
        if corrected:
            await d.broadcast_settings()
        elif current is not None and current.counter == incoming.counter:
            await d.broadcast_settings(exclude=self)

    async def heartbeat(self):
        now = int(time.time())
        await self.send(HeartbeatPacket(self.last_received_time, now))

    async def pulse(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            self.device_chunks.check_deadline()
            self.global_chunks.check_deadline()
            if time.monotonic() - self.last_received_mono > HEARTBEAT_TIMEOUT:
                raise TimeoutError("peer heartbeat timeout")
            await self.heartbeat()

    async def dispatch(self, packet):
        d = self.daemon
        if isinstance(packet, DeviceDataPacket):
            d.check_device(packet)
            if packet.channel != self.peer_channel:
                raise DecodeError("unexpected device sender channel")
            frame = self.device_chunks.add(packet)
            if frame is None:
                return
            inner = decode_inner_packet(open_packet(d.device_key, d.device_key_id, frame), decode_optional=False)
            if isinstance(inner, IgnoredPacket):
                LOG.debug("Ignoring optional inner device packet %s (v%d, %d bytes)",
                          _safe_text(inner.type_name), inner.version,
                          inner.payload_size)
                return
            if isinstance(inner, SettingsPacket):
                await self.merge_settings(inner)
                if self.initial_owner_os is not None:
                    if d.ready_peer(self.peer_channel) and self.initial_owner_os[1] == d.owner_revision:
                        d.set_owner(self.host, self.initial_owner_os[0])
                    self.initial_owner_os = None
                return
            if isinstance(inner, (InitiateFlowPacket, SetCurrentHostPacket)):
                if isinstance(inner, SetCurrentHostPacket) and inner.channel > 2:
                    raise DecodeError("invalid Flow host channel")
                await d.crossing(self, inner)
                hook = d.on_initiate_flow if isinstance(inner, InitiateFlowPacket) else d.on_set_current_host
                if hook:
                    result = hook(inner)
                    if inspect.isawaitable(result):
                        await result
                return
            raise DecodeError(f"unexpected inner device packet {type(inner).__name__}")
        if isinstance(packet, GlobalDataPacket):
            if packet.host_id != self.host:
                raise DecodeError("unexpected global sender")
            if self.discard_global_tail:
                if packet.chunk_number != 1:
                    return
                self.discard_global_tail = False
            allowed = d.clipboard.allowed(self)
            self.global_chunks.limit = MAX_CLIPBOARD_BODY if allowed else MAX_BLOCK + 36
            self.global_chunks.lifetime = TRANSFER_TIMEOUT if allowed else CHUNK_TIMEOUT
            data = self.global_chunks.add(packet)
            if data is None:
                return
            decode_optional = CLIPBOARD_GLOBALS if allowed else DISABLED_GLOBALS
            if len(data) >= 65536:
                inner = await asyncio.to_thread(decode_inner_packet, data, decode_optional=decode_optional)
            else:
                inner = decode_inner_packet(data, decode_optional=decode_optional)
            if isinstance(inner, (ClipboardUpdatePacket, *REQUESTS, *RESPONSES)):
                await d.clipboard.dispatch(self, inner)
                return
            if isinstance(inner, IgnoredPacket):
                LOG.debug("Ignoring optional inner global packet %s (v%d, %d bytes)",
                          _safe_text(inner.type_name), inner.version,
                          inner.payload_size)
                return
            if isinstance(inner, SetOwnerPacket):
                if inner.new_owner == self.host:
                    if d.ready_peer(self.peer_channel):
                        d.set_owner(self.host, inner.new_flag)
                    elif not self.received_settings:
                        self.initial_owner_os = (inner.new_flag, d.owner_revision)
                return
            raise DecodeError(f"unexpected inner global packet {type(inner).__name__}")
        if isinstance(packet, HeartbeatPacket):
            LOG.debug("Heartbeat from %s (%d, %d)", _safe_text(self.host),
                      packet.last_received_packet_time, packet.current_time)
            return
        raise DecodeError(f"unexpected established-session packet {type(packet).__name__}")

    async def serve(self, expected_host):
        await asyncio.wait_for(self.handshake(expected_host), HANDSHAKE_TIMEOUT)
        LOG.info("Device session established with %s (%s, peer=%s ch=%d)",
                 self.writer.get_extra_info("peername")[0],
                 "outbound" if self.client else "inbound",
                 _safe_text(self.host), self.peer_channel)

        d = self.daemon
        if d.active_owner == d.host:
            await self.send_global(SetOwnerPacket(d.host, LINUX_OS, d.host, LINUX_OS))

        async def consume():
            while True:
                await self.dispatch(await self.receive())
        tasks = [
            asyncio.create_task(consume()),
            asyncio.create_task(self.initial_settings()),
            asyncio.create_task(self.pulse()),
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


class DiscoveryTransport(asyncio.DatagramProtocol):
    def __init__(self, daemon, nodestore=False):
        self.daemon = daemon
        self.nodestore = nodestore

    def datagram_received(self, data, addr):
        try:
            self.daemon.discovery(data, addr[0], nodestore=self.nodestore)
        except (ValueError, InvalidTag):
            LOG.debug("Rejected UDP discovery frame from %s", addr[0])


class FlowDaemon:
    def __init__(self, state, *, host_id=None, bind="0.0.0.0", peers=(), advertise=False,
                 force=False, udp_discovery_port=59870, udp_nodestore_port=59871, tcp_port=59869,
                 broadcast="255.255.255.255", on_initiate_flow=None, on_set_current_host=None,
                 desktop=None, switcher=None, edge_cooldown=.6, preferences=None,
                 preferences_path=None, control_sock=None, hidraw=None, clipboard=None, transfer_cache=None):
        name = host_id or state["host_id"]
        if not isinstance(name, str) or not name:
            raise ValueError("host ID must be a nonempty string")
        self.host = name.encode()
        mouse = state["mouse"]
        self.identity = _identity(mouse)
        self.device_key_id, self.device_key = derive_device_key(*self.identity[:2], mouse["random"],
                                                              state.get("password", ""))
        self.keyboard = _identity(state["keyboard"]) if "keyboard" in state else (0, 0, 0xffffffff)
        self.local_peer = Peer(self.identity[2], self.keyboard[2], self.host, True)
        self.bind, self.broadcast = bind, broadcast
        self.peers = tuple(str(ipaddress.IPv4Address(ip)) for ip in peers)
        self.advertise = advertise
        self.force = force
        self.discovery_port, self.nodestore_port = udp_discovery_port, udp_nodestore_port
        self.tcp_port = tcp_port
        self.on_initiate_flow, self.on_set_current_host = on_initiate_flow, on_set_current_host
        self.active_owner = self.settings = None
        self.active_owner_os = 0
        self.owner_revision = 0
        self.clipboard = ClipboardManager(self, clipboard, transfer_cache)
        self.tunnels, self.pending, self.tasks = {}, set(), set()
        self.recent = OrderedDict()
        self.ingress = TokenBucket(64)
        self.broadcast_replies = TokenBucket(8)
        self.budget = ByteBudget(BASE_INFLIGHT_BYTES)
        self.writers = set()
        self.udp = []
        self.server = None
        self.closing = False
        self.desktop, self.switcher = desktop, switcher
        self.edges = self.awaiting = None
        self.until = 0.
        self.preferences = validate_preferences(preferences if preferences is not None else
                                                {"edge_cooldown": edge_cooldown})
        self.preferences_path = preferences_path
        self.modifier_key = self.preferences["modifier_key"]
        self.cooldown = self.preferences["edge_cooldown"]
        self.control = ControlServer(control_sock, self.rpc) if control_sock else None
        self.events = deque(maxlen=15)
        self.reset_local = False
        self.hidraw = hidraw
        self.scan_task = None
        self.generation = 0
        self.awaiting_generation = self.awaiting_timer = self.local_edit = None
        self.devices = {role: {key: state[role].get(key) for key in DEVICE_FIELDS}
                        for role in ("mouse", "keyboard") if role in state}
        for role, row in self.devices.items():
            row["name"] = row["name"] or f"Bolt {role}"

    def event(self, message):
        self.events.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {message}")

    def seed_settings(self):
        peers = [Peer(i, 0xffffffff, b"", False) for i in range(3)]
        peers[self.identity[2]] = self.local_peer
        for host, tunnel in self.tunnels.items():
            peers[tunnel.peer_channel] = Peer(tunnel.peer_channel, 0xffffffff, host, True)
        return Settings(0, b"horizontal", True, False, False, False, False, False,
                        0, 0, tuple(peers))

    def status_settings(self):
        if self.settings is None:
            return None
        s = self.settings
        peers = []
        for slot, row in enumerate(s.peers):
            tunnel = self.tunnels.get(row.host_id)
            local = row.channel == self.identity[2]
            address = tunnel.writer.get_extra_info("peername") if tunnel else None
            peers.append(dict(slot=slot, channel=row.channel, keyboard_channel=row.keyboard_channel,
                              host_id=display_text(row.host_id), enabled=row.enabled, is_local=local,
                              connected=bool(tunnel or (local and row.host_id == self.host)),
                              peer_ip=address[0] if address else None))
        return {**{k: getattr(s, k) for k in FLAGS}, "drag_drop": s.drag_drop, "counter": s.counter,
                "layout": display_text(s.layout), "keyboard_id": s.keyboard_id,
                "keyboard_serial_number": s.keyboard_serial_number, "peers": peers}

    async def get_status(self):
        monitors = []
        if self.desktop:
            try:
                monitors = await asyncio.to_thread(self.desktop.get_monitors)
            except (OSError, ValueError, KeyError):
                pass
        displays = []
        for monitor in monitors:
            routes = {}
            for edge in Edge:
                target = resolve_peer_for_edge(self.settings, self.identity[2], edge, self.tunnels)
                if target is None:
                    continue
                peer = self.ready_peer(target)
                if not peer or self.tunnels[peer.host_id].peer_channel != target:
                    continue
                if any(end - start >= (48 if self.settings.hot_corners else 0)
                       for _, start, end in segments(monitors, edge, monitor)):
                    routes[edge.name] = display_text(peer.host_id)
            displays.append({**asdict(monitor), "routes": routes})
        return dict(host_id=display_text(self.host), local_channel=self.identity[2],
                    active_owner=display_text(self.active_owner) if self.active_owner else None,
                    daemon_pid=os.getpid(), mouse=self.devices["mouse"], keyboard=self.devices.get("keyboard"),
                    preferences=dict(self.preferences), settings=self.status_settings(),
                    monitors=displays, events=list(self.events), clipboard=self.clipboard.status())

    def edit_peers(self, current, rows):
        require(isinstance(rows, list) and len(rows) == 3, "three peer slots required")
        by_channel = {p.channel: p for p in current}
        ordered = []
        for row in rows:
            require(isinstance(row, dict) and "channel" in row and not row.keys() -
                    {"channel", "host_id", "enabled", "slot", "keyboard_channel", "is_local",
                     "connected", "peer_ip"}, "invalid peer fields")
            ch = row["channel"]
            require(type(ch) is int and ch in by_channel, "expected three unique peer channels")
            peer = by_channel.pop(ch)
            host = row.get("host_id", display_text(peer.host_id))
            enabled = row.get("enabled", peer.enabled if host else False)
            require(isinstance(host, str) and type(enabled) is bool, "invalid peer values")
            if ch == self.identity[2]:
                require(peer.host_id == self.host and host == display_text(self.host) and enabled,
                        "local peer must remain active")
            require(host == display_text(peer.host_id) or not host, "unknown host for channel")
            require(host or not enabled, "empty slot cannot be enabled")
            ordered.append(replace(peer, enabled=enabled) if host else Peer(ch, 0xffffffff, b"", False))
        return tuple(ordered)

    async def broadcast_settings(self, *, exclude=None):
        snapshot = self.settings
        peers = [(host, t) for host, t in self.tunnels.items() if t is not exclude]
        results = await asyncio.gather(*(t.send_settings(snapshot) for _, t in peers),
                                       return_exceptions=True)
        errors = []
        for (host, _), result in zip(peers, results):
            if isinstance(result, BaseException):
                name = _safe_text(host)
                errors.append({"host_id": name, "error": type(result).__name__})
                LOG.warning("Settings delivery to %s failed (%s)", name, type(result).__name__)
        return errors

    async def update_settings(self, changes, *, reset=False):
        require(not changes.keys() - (FLAGS | {"layout", "peers", "expected_counter"}),
                "unknown setting")
        current = self.settings or self.seed_settings()
        if "expected_counter" in changes:
            counter = changes["expected_counter"]
            require(type(counter) is int and counter == current.counter, "settings changed; retry")
        updates = {k: changes[k] for k in FLAGS & changes.keys()}
        require(all(type(v) is bool for v in updates.values()), "settings flags must be booleans")
        layout = changes.get("layout", "horizontal" if reset and current.layout not in LAYOUTS
                             else display_text(current.layout))
        require(isinstance(layout, str) and layout.encode() in LAYOUTS, "unknown layout")
        updates["layout"] = layout.encode()
        rows = list(self.edit_peers(current.peers, changes["peers"])
                    if "peers" in changes else current.peers)
        local = next(i for i, row in enumerate(rows) if row.channel == self.identity[2])
        reset_local = self.reset_local
        if reset:
            rows[local] = Peer(self.identity[2], 0xffffffff, b"", False)
            reset_local = True
        elif changes.get("on") is True and (self.reset_local or not rows[local].enabled):
            rows[local] = self.local_peer
            reset_local = False
        keyboard = self.devices.get("keyboard")
        if changes.get("keyboard_link") and keyboard:
            require(keyboard["channel"] in (0, 1, 2), "activate keyboard locally and rescan")
            identity = _identity(keyboard)
            require((current.keyboard_id, current.keyboard_serial_number) in
                    ((0, 0), identity[:2]), "different keyboard linked by peer")
            updates["keyboard_id"], updates["keyboard_serial_number"] = identity[:2]
            if rows[local].enabled:
                rows[local] = replace(rows[local], keyboard_channel=identity[2])
            if not self.keyboard[0]:
                self.keyboard = identity
                self.local_peer = replace(self.local_peer, keyboard_channel=identity[2])
                if self.switcher:
                    self.switcher.devices["keyboard"] = dict(keyboard)
        self.reset_local = reset_local
        self.settings = replace(current, **updates, peers=tuple(rows),
                                counter=(current.counter + 1) % (1 << 32))
        self.clipboard_settings_changed()
        self.invalidate_crossings()
        self.local_edit = self.settings.counter
        self.event(f"Settings sync · {self.settings.counter}")
        return await self.broadcast_settings()

    def update_preferences(self, changes):
        prefs = validate_preferences(changes, self.preferences)
        require(self.preferences_path is not None, "preferences path unavailable")
        save_preferences(self.preferences_path, prefs)
        self.preferences = prefs
        self.modifier_key, self.cooldown = prefs["modifier_key"], prefs["edge_cooldown"]
        if self.edges:
            self.edges.threshold = prefs["edge_threshold"]

    async def rescan_devices(self):
        if self.scan_task is None or self.scan_task.done():
            self.scan_task = self.spawn(self._scan_devices())
        return await asyncio.shield(self.scan_task)

    async def _scan_devices(self):
        owner_revision = self.owner_revision
        devices = await asyncio.to_thread(inventory_bolt_devices, self.hidraw)
        keyboards = [d for d in devices if d["kind"] == "keyboard"]
        for role in ("mouse", "keyboard"):
            known = self.devices.get(role)
            match = None
            if known is not None:
                match = next((d for d in devices if (d["device_id"], d["serial_number"]) ==
                              (known["device_id"], known["serial_number"])), None)
            elif role == "keyboard" and len(keyboards) == 1:
                match = keyboards[0]
            if match is None:
                continue
            row = {k: match[k] for k in DEVICE_FIELDS}
            row["name"] = display_text(row["name"])
            # The provisioned local channel remains authoritative if the device sleeps.
            if role == "mouse":
                if (match.get("channel") == self.identity[2] and owner_revision == self.owner_revision
                        and self.active_owner != self.host):
                    await self.take_ownership()
                row["channel"] = self.identity[2]
            elif self.keyboard[0]:
                row["channel"] = self.keyboard[2]
            self.devices[role] = row
        return [{**{k: d[k] for k in DEVICE_FIELDS}, "name": display_text(d["name"])} for d in devices]

    async def initial_inventory(self):
        try:
            await self.rescan_devices()
        except (OSError, ValueError) as exc:
            LOG.info("Bolt inventory unavailable (%s)", type(exc).__name__)

    async def rpc(self, method, params):
        if method in ("get_status", "reset_flow", "rescan_devices"):
            require(not params, "unexpected parameters")
        if method == "update_settings":
            errors = await self.update_settings(params)
            return {**await self.get_status(), "delivery_errors": errors}
        elif method == "reset_flow":
            await self.update_settings({}, reset=True)
        elif method == "update_preferences":
            self.update_preferences(params)
        elif method == "rescan_devices":
            devices = await self.rescan_devices()
            return {**await self.get_status(), "devices": devices}
        elif method == "discover_peers":
            require(not params.keys() - {"peer_ip", "force"}, "unknown discovery field")
            force = params.get("force", True)
            require(type(force) is bool, "force must be boolean")
            targets = ()
            if "peer_ip" in params:
                require(isinstance(params["peer_ip"], str), "expected IPv4 address")
                ip = str(ipaddress.IPv4Address(params["peer_ip"]))
                targets = (ip,)
            if self.reset_local or (self.settings and any(
                    p.channel == self.identity[2] and not p.enabled for p in self.settings.peers)):
                await self.update_settings({"on": True})
            self.recent.clear()
            self.advertise_once(force, targets)
            self.event("Discovery · search")
        else:
            require(method == "get_status", "unknown control method")
        return await self.get_status()

    def invalidate_crossings(self):
        self.generation += 1
        self.awaiting = self.awaiting_generation = None
        self.until = 0.
        if self.awaiting_timer:
            self.awaiting_timer.cancel()
            self.awaiting_timer = None
        if self.switcher:
            self.switcher.invalidate()
        return self.generation

    def expire_crossing(self, generation):
        if generation == self.awaiting_generation:
            self.invalidate_crossings()

    def ready_peer(self, channel):
        if not self.settings or not self.settings.on:
            return None
        peers = self.settings.peers
        if not any(p.enabled and p.channel == self.identity[2] and p.host_id == self.host for p in peers):
            return None
        return next((p for p in peers if p.enabled and p.channel == channel
                     and p.host_id in self.tunnels), None)

    async def edge_push(self, edge):
        if time.monotonic() < self.until:
            return
        channel = resolve_peer_for_edge(self.settings, self.identity[2], edge, self.tunnels)
        if channel is None:
            return
        generation = self.generation
        monitors = await asyncio.to_thread(self.desktop.get_monitors)
        if generation != self.generation:
            return
        pos = await asyncio.to_thread(self.desktop.get_cursor_pos)
        if generation != self.generation:
            return
        hit = flow_out_info(monitors, *pos, edge, self.settings.hot_corners)
        if not hit:
            return
        snapshot = self.settings
        modifier = self.modifier_key
        if snapshot.ctrl_key and not await asyncio.to_thread(self.desktop.is_modifier_down, modifier):
            return
        if generation == self.generation and snapshot is self.settings and modifier == self.modifier_key:
            await self.send_initiate_flow(channel, *hit)

    def clipboard_settings_changed(self):
        self.clipboard.invalidate()
        self.budget.limit = MAX_INFLIGHT_BYTES if self.clipboard.enabled() else BASE_INFLIGHT_BYTES
        for tunnel in self.tunnels.values():
            if (not self.clipboard.allowed(tunnel) and tunnel.global_chunks.parts
                    and tunnel.global_chunks.lifetime == TRANSFER_TIMEOUT):
                tunnel.global_chunks.reset()
                tunnel.discard_global_tail = True

    def set_owner(self, host, os_code):
        self.active_owner, self.active_owner_os = host, os_code
        self.owner_revision += 1
        self.clipboard.owner_changed()

    async def take_ownership(self):
        packet = SetOwnerPacket(self.active_owner or b"", self.active_owner_os, self.host, LINUX_OS)
        self.set_owner(self.host, LINUX_OS)
        await asyncio.gather(*(t.send_global(packet) for t in self.tunnels.values()),
                             return_exceptions=True)

    async def send_initiate_flow(self, target_channel, edge, position):
        peer = self.ready_peer(target_channel)
        if (not peer or time.monotonic() < self.until or target_channel !=
                resolve_peer_for_edge(self.settings, self.identity[2], edge, self.tunnels)):
            return
        tunnel = self.tunnels[peer.host_id]
        if tunnel.peer_channel != target_channel:
            return
        generation = self.invalidate_crossings()
        if self.clipboard.allowed(tunnel):
            self.until = float("inf")
            try:
                preflight = self.spawn(self.clipboard.announce(tuple(self.tunnels.values()), crossing=True,
                                                            crossing_target=tunnel))
                try:
                    done, _ = await asyncio.wait((preflight,), timeout=.25)
                    if done and not preflight.cancelled():
                        preflight.result()
                except Exception:
                    LOG.debug("Clipboard pre-announcement unavailable")
                finally:
                    preflight.cancel()
            finally:
                if generation == self.generation:
                    self.until = 0.
            if generation != self.generation:
                return
        self.awaiting_generation = generation
        self.awaiting_timer = asyncio.get_running_loop().call_later(1.5, self.expire_crossing, generation)
        self.awaiting = tunnel
        self.until = time.monotonic() + 1.5
        self.event(f"Flow OUT · {edge.name} · Ch {target_channel + 1}")
        LOG.info("Flow OUT edge=%s pos=%.2f -> peer=%s ch=%d",
                 edge.name, position, _safe_text(peer.host_id), target_channel)
        try:
            await tunnel.send_device(InitiateFlowPacket(edge, position))
        except BaseException:
            self.expire_crossing(generation)
            raise

    async def send_set_current_host(self, tunnel, channel):
        await tunnel.send_device(SetCurrentHostPacket(channel))

    async def crossing(self, tunnel, packet):
        peer = self.ready_peer(tunnel.peer_channel)
        if not peer or self.tunnels.get(peer.host_id) is not tunnel:
            return
        now = time.monotonic()
        if isinstance(packet, InitiateFlowPacket):
            if self.desktop is None or now < self.until:
                return
            generation = self.invalidate_crossings()
            self.until = float("inf")
            try:
                monitors = await asyncio.to_thread(self.desktop.get_monitors)
                if generation != self.generation:
                    return
                point = flow_in_point(monitors, packet.edge, packet.position)
                self.event(f"Flow IN · {packet.edge.name} · Ch {tunnel.peer_channel + 1}")
                LOG.info("Flow IN from=%s edge=%s pos=%.2f -> warp=(%d,%d) reply ch=%d",
                         _safe_text(peer.host_id), packet.edge.name, packet.position,
                         point[0], point[1], self.identity[2])
                await asyncio.to_thread(self.desktop.move_cursor, *point)
                if generation != self.generation:
                    return
                await self.send_set_current_host(tunnel, self.identity[2])
                if generation == self.generation:
                    await self.take_ownership()
            except (ValueError, KeyError, OSError) as exc:
                LOG.warning("Inbound crossing failed (%s: %s)", type(exc).__name__, exc)
            finally:
                if generation == self.generation:
                    self.until = time.monotonic() + self.cooldown
        elif (self.switcher and self.awaiting is tunnel and self.awaiting_generation == self.generation
              and now < self.until
              and packet.channel == peer.channel and packet.channel != self.identity[2]):
            self.invalidate_crossings()
            self.until = now + self.cooldown
            kbd_target = (peer.keyboard_channel if self.settings.keyboard_link and self.keyboard[0]
                          and (self.settings.keyboard_id, self.settings.keyboard_serial_number) in
                          ((0, 0), self.keyboard[:2])
                          and 0 <= peer.keyboard_channel <= 2 else None)
            self.event(f"Flow SWITCH · Ch {packet.channel + 1}")
            LOG.info("Flow SWITCH -> peer=%s mouse_ch=%d keyboard_ch=%s",
                     _safe_text(peer.host_id), packet.channel, kbd_target)
            if self.active_owner == self.host:
                self.set_owner(None, 0)
            self.switcher.submit_crossing(packet.channel, kbd_target)


    def check_device(self, packet):
        if (packet.device_id, packet.serial_number) != self.identity[:2] or packet.channel > 2:
            raise DecodeError("unexpected device identity")

    def claim(self, tunnel):
        other = self.tunnels.get(tunnel.host)
        if other:
            # Lower device channel initiates TCP (matching BroadcastDiscovery::HandlePingPacket).
            preferred = self.identity[2] < tunnel.peer_channel
            if other.client == tunnel.client or tunnel.client != preferred:
                raise DecodeError("duplicate peer connection")
            self.invalidate_crossings()
            self.clipboard.disconnect(other)
            other.writer.close()
        self.tunnels[tunnel.host] = tunnel

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def connection(self, reader, writer, client=False, expected_host=None):
        self.writers.add(writer)
        tunnel = Tunnel(self, reader, writer, client)
        try:
            await tunnel.serve(expected_host)
        except DecodeError as exc:
            LOG.info("Peer tunnel rejected (%s: %s)", type(exc).__name__, exc)
        except (asyncio.IncompleteReadError, TimeoutError, OSError, ValueError, InvalidTag) as exc:
            LOG.info("Peer tunnel closed (%s)", type(exc).__name__)
        finally:
            tunnel.device_chunks.reset()
            tunnel.global_chunks.reset()
            self.clipboard.disconnect(tunnel)
            if self.tunnels.get(tunnel.host) is tunnel:
                self.invalidate_crossings()
                del self.tunnels[tunnel.host]
                if self.active_owner == tunnel.host:
                    self.set_owner(None, 0)
            self.writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    def accept(self, reader, writer):
        if self.closing or len(self.tasks) >= 64:
            writer.close()
        else:
            self.writers.add(writer)
            self.spawn(self.connection(reader, writer))

    async def dial(self, ip, port, host):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), HANDSHAKE_TIMEOUT)
            await self.connection(reader, writer, True, host)
        except (OSError, TimeoutError):
            LOG.debug("Outbound peer unavailable at %s:%d", ip, port)
        finally:
            self.pending.discard(host)

    def send_udp(self, packet, addresses):
        frame = seal_packet(self.device_key, self.device_key_id, encode_discovery(packet))
        for ip, port in set(addresses):
            transport = self.udp[1 if port == self.nodestore_port else 0]
            transport.sendto(frame, (ip, port))

    def beacon(self, *, force=False):
        return BeaconPacket(*self.identity, self.host, force, self.discovery_port)

    def ping(self, *, force=False):
        return PingPacket(*self.identity, self.host, force, self.tcp_port)

    def advertise_once(self, force=None, extra_peers=()):
        force = self.force if force is None else force
        targets = [(ip, self.discovery_port) for ip in (self.broadcast, *self.peers, *extra_peers)]
        self.send_udp(InitiateDiscoveryPacket(*self.identity, force), targets)
        self.send_udp(self.beacon(force=force), targets)

    async def advertise_periodically(self):
        while True:
            self.advertise_once()
            await asyncio.sleep(15)

    def discovery(self, data, ip, *, nodestore=False):
        if (self.closing or len(self.udp) != 2 or len(data) > DISCOVERY_MAX_FRAME
                or not self.ingress.take()):
            return
        packet = decode_discovery(open_packet(self.device_key, self.device_key_id, data, max_body=DISCOVERY_MAX_FRAME))
        self.check_device(packet)
        if packet.channel == self.identity[2] or getattr(packet, "host_id", None) == self.host:
            return
        if type(packet) is BeaconPacket and packet.host_id in self.tunnels and not packet.force:
            return
        token = (ip, type(packet), packet.channel)
        now = asyncio.get_running_loop().time()
        if token in self.recent:
            if now - self.recent[token] < (PING_BACKOFF if type(packet) is PingPacket else 2):
                return
        if type(packet) is InitiateDiscoveryPacket:
            # An explicit search can retry before the ordinary dial backoff expires.
            self.recent.pop((ip, PingPacket, packet.channel), None)
        self.recent[token] = now
        self.recent.move_to_end(token)
        if len(self.recent) > 512:
            self.recent.popitem(last=False)
        self.event(f"Discovery · {ip} · Ch {packet.channel + 1}")
        reply_port = self.nodestore_port if nodestore else self.discovery_port
        force = packet.force or self.force
        if type(packet) is InitiateDiscoveryPacket:
            LOG.info("Received InitiateDiscovery from %s ch=%d force=%s", ip, packet.channel, packet.force)
            targets = [(ip, reply_port)]
            if self.broadcast_replies.take():
                targets.append((self.broadcast, self.discovery_port))
            self.send_udp(self.beacon(force=force), targets)
        elif type(packet) is BeaconPacket:
            LOG.info("Received Beacon from %s host=%s ch=%d force=%s ping_port=%d",
                     ip, _safe_text(packet.host_id), packet.channel, packet.force, packet.port)
            target_port = packet.port or reply_port
            self.send_udp(self.ping(force=force), [(ip, target_port)])
        else:
            LOG.info("Received Ping from %s host=%s ch=%d force=%s tcp_port=%d",
                     ip, _safe_text(packet.host_id), packet.channel, packet.force, packet.port)
            if packet.channel > self.identity[2]:
                # Lower channel initiates TCP (matching Options+ HandlePingPacket).
                if (packet.port and packet.host_id and packet.host_id not in self.tunnels
                        and packet.host_id not in self.pending and len(self.tasks) < 64):
                    self.pending.add(packet.host_id)
                    self.spawn(self.dial(ip, packet.port, packet.host_id))
            elif packet.host_id not in self.tunnels:
                # Peer has lower channel and initiates TCP once it receives our PingPacket.
                self.send_udp(self.ping(force=force), [(ip, reply_port)])

    async def start(self):
        self.clipboard_settings_changed()
        loop = asyncio.get_running_loop()
        try:
            self.server = await asyncio.start_server(self.accept, self.bind, self.tcp_port,
                                                     family=socket.AF_INET)
            self.tcp_port = self.server.sockets[0].getsockname()[1]
            for idx, port in enumerate((self.discovery_port, self.nodestore_port)):
                transport, _ = await loop.create_datagram_endpoint(
                    lambda is_ns=(idx == 1): DiscoveryTransport(self, nodestore=is_ns),
                    local_addr=(self.bind, port), family=socket.AF_INET, allow_broadcast=True)
                self.udp.append(transport)
            self.discovery_port, self.nodestore_port = (t.get_extra_info("sockname")[1] for t in self.udp)
            if self.control:
                await self.control.start()
                self.spawn(self.initial_inventory())
            try:
                await asyncio.to_thread(recover_cache, self.clipboard.cache)
            except TransferError:
                LOG.debug("Clipboard cache unavailable")
            self.spawn(self.clipboard.monitor())
            if self.edges:
                self.edges.start()
            if self.advertise:
                self.spawn(self.advertise_periodically())
        except BaseException:
            await self.close()
            raise

    async def close(self):
        self.closing = True
        self.clipboard.invalidate()
        self.invalidate_crossings()
        if self.control:
            await self.control.close()
        if self.edges:
            await self.edges.close()
        if self.server:
            self.server.close()
        for transport in self.udp:
            transport.close()
        # Close client sockets before waiting for the server on newer asyncio.
        for writer in self.writers:
            writer.close()
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.clipboard.backend.close()
        self.writers.clear()
        if self.switcher:
            await self.switcher.close()
        if self.server:
            await self.server.wait_closed()


async def run(args):
    state = load_state(args.config)
    preferences_path = args.config.expanduser().with_name("preferences.json")
    require(preferences_path != args.config.expanduser(), "preferences path conflicts with state")
    overrides = {k: getattr(args, k) for k in DEFAULTS if getattr(args, k) is not None}
    prefs = load_preferences(preferences_path, overrides)
    daemon = FlowDaemon(state, desktop=None if args.no_edges else Hyprland(),
                        switcher=Switcher(state, args.hidraw, args.dry_run_switch),
                        preferences=prefs, preferences_path=preferences_path, hidraw=args.hidraw,
                        control_sock=None if args.no_control_sock else args.control_sock, host_id=args.host_id, peers=args.peer,
                        advertise=args.advertise, force=args.force,
                        udp_discovery_port=args.udp_discovery_port,
                        udp_nodestore_port=args.udp_nodestore_port, tcp_port=args.tcp_port)
    if not args.no_edges:
        daemon.edges = MouseEdges(args.mouse_evdev, prefs["edge_threshold"], daemon.edge_push)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    try:
        await daemon.start()
        LOG.info("Listening on UDP %d/%d and TCP %d", daemon.discovery_port, daemon.nodestore_port,
                 daemon.tcp_port)
        await stop.wait()
    finally:
        await daemon.close()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    provision = commands.add_parser("provision", help="read active devices from the local Bolt receiver")
    serve = commands.add_parser("run", help="run the foreground Flow peer")
    for command in (provision, serve):
        command.add_argument("--config", type=Path, default=default_state_path())
        command.add_argument("--host-id")
    provision.add_argument("--clear-password", action="store_true")
    serve.add_argument("--peer", action="extend", nargs="+", type=ipaddress.IPv4Address, default=[])
    serve.add_argument("--advertise", action="store_true")
    serve.add_argument("--force", action="store_true",
                       help="set force=true on discovery packets (needed when pairing an unassigned slot)")
    serve.add_argument("--udp-discovery-port", type=int, default=59870)
    serve.add_argument("--udp-nodestore-port", type=int, default=59871)
    serve.add_argument("--tcp-port", type=int, default=59869)
    serve.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    serve.add_argument("--mouse-evdev", default=DEFAULT_MOUSE)
    serve.add_argument("--hidraw")
    serve.add_argument("--edge-threshold", type=int)
    serve.add_argument("--edge-cooldown", type=float)
    serve.add_argument("--modifier-key", choices=("ctrl", "super", "alt"))
    control = serve.add_mutually_exclusive_group()
    control.add_argument("--control-sock", type=Path, default=default_socket())
    control.add_argument("--no-control-sock", action="store_true")
    serve.add_argument("--no-edges", action="store_true")
    serve.add_argument("--dry-run-switch", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "provision":
            print(json.dumps(provision_local_devices(args.config, args.host_id, clear_password=args.clear_password), indent=2))
        else:
            logging.basicConfig(level=args.log_level)
            asyncio.run(run(args))
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "Flow could not start or provision; check receiver access, state and ports.\n")


if __name__ == "__main__":
    main()
