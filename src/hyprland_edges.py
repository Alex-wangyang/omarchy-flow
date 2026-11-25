"""Logical monitor geometry, Hyprland command socket and mouse-only edge input."""
import asyncio
from dataclasses import dataclass
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time

from marconi_packets import Edge

DEFAULT_MOUSE = "/dev/input/by-id/usb-Logitech_USB_Receiver-if01-event-mouse"
MODIFIER_KEYSYMS = {"ctrl": ("Control_L", "Control_R"), "super": ("Super_L", "Super_R"),
                    "alt": ("Alt_L", "Alt_R")}
EVENT = struct.Struct("llHHi")
LOG = logging.getLogger("omarchy-flow")


@dataclass(frozen=True)
class Monitor:
    name: str
    x: int
    y: int
    width: int
    height: int


IPC_TIMEOUT = 0.8
IPC_MAX_RESPONSE = 1024 * 1024


def _ipc_timeout(sock, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Hyprland command timed out")
    sock.settimeout(remaining)


class Hyprland:
    def __init__(self):
        self._lua_dispatch = None

    def command(self, command):
        deadline = time.monotonic() + IPC_TIMEOUT
        root = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "hypr"
        signature = os.environ.get("HYPRLAND_INSTANCE_SIGNATURE")
        candidates = []
        for path in root.glob("*/.socket.sock"):
            try:
                candidates.append((path.stat().st_mtime_ns, path))
            except FileNotFoundError:
                continue
        paths = [path for _, path in sorted(candidates, reverse=True)]
        if signature:
            paths.insert(0, root / signature / ".socket.sock")
        for path in dict.fromkeys(paths):
            with socket.socket(socket.AF_UNIX) as sock:
                _ipc_timeout(sock, deadline)
                try:
                    sock.connect(str(path))
                except OSError:
                    continue
                _ipc_timeout(sock, deadline)
                sock.sendall(command.encode())
                response = bytearray()
                while len(response) <= IPC_MAX_RESPONSE:
                    _ipc_timeout(sock, deadline)
                    chunk = sock.recv(min(8192, IPC_MAX_RESPONSE + 1 - len(response)))
                    if not chunk:
                        return bytes(response)
                    response.extend(chunk)
                raise OSError("Hyprland response too large")
        raise OSError("Hyprland command socket unavailable")

    def is_modifier_down(self, modifier: str) -> bool:
        if not isinstance(modifier, str) or modifier not in MODIFIER_KEYSYMS:
            raise ValueError("unknown modifier")
        left, right = MODIFIER_KEYSYMS[modifier]
        reply = self.command(f'eval if not (hl.is_key_down("{left}") or hl.is_key_down("{right}")) '
                             'then error("OMARCHY_FLOW_MOD_UP") end').strip()
        if reply == b"ok":
            return True
        if b"OMARCHY_FLOW_MOD_UP" in reply:
            return False
        raise OSError("Hyprland modifier query failed")

    def get_monitors(self):
        result = []
        for m in json.loads(self.command("j/monitors")):
            if m.get("disabled"):
                continue
            w, h = m["width"], m["height"]
            if m["transform"] % 2:
                w, h = h, w
            result.append(Monitor(m["name"], m["x"], m["y"], round(w/m["scale"]), round(h/m["scale"])))
        return result

    def get_cursor_pos(self):
        p = json.loads(self.command("j/cursorpos"))
        return p["x"], p["y"]

    def move_cursor(self, x, y):
        x, y = int(x), int(y)
        commands = (
            (True, f"dispatch hl.dsp.cursor.move({{ x = {x}, y = {y} }})"),
            (False, f"dispatch movecursor {x} {y}"),
        )
        if self._lua_dispatch is False:
            commands = (commands[1], commands[0])
        last = b""
        for is_lua, cmd in commands:
            last = self.command(cmd).strip()
            if last == b"ok":
                self._lua_dispatch = is_lua
                return
        raise OSError(f"Hyprland rejected cursor warp: {last.decode(errors='replace')[:200]}")


def bounds(m, edge):
    if edge in (Edge.LEFT, Edge.RIGHT):
        return m.x, m.x + m.width, m.y, m.y + m.height
    return m.y, m.y + m.height, m.x, m.x + m.width


def segments(monitors, edge, monitor=None):
    """Yield (edge pixel, first pixel, last pixel) for exposed monitor sides."""
    positive = edge in (Edge.RIGHT, Edge.BOTTOM)
    for m in monitors:
        if monitor is not None and monitor is not m:
            continue
        a, b, start, end = bounds(m, edge)
        boundary = b if positive else a
        spans = [(start, end)]
        for other in monitors:
            if other is m:
                continue
            c, d, lo, hi = bounds(other, edge)
            if abs(boundary - (c if positive else d)) > 2:
                continue
            spans = [(s, t) for left, right in spans
                     for s, t in ((left, min(lo, right)), (max(hi, left), right)) if s < t]
        for left, right in spans:
            yield boundary - int(positive), left, right - 1


def flow_out_info(monitors, cursor_x, cursor_y, push_edge, hot_corners=False, corner_margin=24):
    axis, along = ((cursor_x, cursor_y) if push_edge in (Edge.LEFT, Edge.RIGHT)
                   else (cursor_y, cursor_x))
    for line, start, end in segments(monitors, push_edge):
        inward = line - axis if push_edge in (Edge.RIGHT, Edge.BOTTOM) else axis - line
        if -1 <= inward <= 2 and start <= along <= end:
            if hot_corners and min(along-start, end-along) < corner_margin:
                continue
            return push_edge, (along-start) / max(1, end-start)
    return None


def flow_in_point(monitors, exit_edge, position, inset=3):
    edge = Edge(exit_edge ^ 1)
    positive = edge in (Edge.RIGHT, Edge.BOTTOM)
    sides = list(segments(monitors, edge))
    if not sides:
        raise ValueError("no usable monitor")
    # Prefer the outermost side, then the longest contiguous landing span.
    line, start, end = max(sides, key=lambda s: (s[0] if positive else -s[0], s[2]-s[1], -s[1]))
    along = start + round(position * (end-start))
    axis = line + (-inset if positive else inset)
    return (axis, along) if edge in (Edge.LEFT, Edge.RIGHT) else (along, axis)


_INPUT = Path("/dev/input")
_KEYBOARD_BITS = (1 << 84) - 2


def _bitmap(path):
    # Linux sysfs prints most-significant unsigned longs first, without padding.
    width = struct.calcsize("L") * 8
    words = path.read_text().split()
    if not words or any(not re.fullmatch(r"[0-9a-fA-F]{1,%d}" % (width // 4), w) for w in words):
        raise OSError("invalid input capability bitmap")
    return sum(int(word, 16) << (i * width) for i, word in enumerate(reversed(words)))


def _verify_mouse(info, node):
    if not stat.S_ISCHR(info.st_mode):
        raise OSError("expected a character device")
    number = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    event = Path("/sys/dev/char", number).resolve(strict=True)
    if (event.name != node.name or (event / "subsystem").resolve(strict=True) != Path("/sys/class/input")
            or (event / "dev").read_text().strip() != number):
        raise OSError("expected an input event device")
    caps = event / "device/capabilities"
    props = Path(f"/run/udev/data/c{number}").read_text().splitlines()
    mouse_labels = [v for v in props if v.startswith("E:ID_INPUT_MOUSE=")]
    keyboard_labels = [v for v in props if v.startswith("E:ID_INPUT_KEYBOARD=")]
    if (_bitmap(caps / "rel") & 3 != 3 or _bitmap(caps / "key") & _KEYBOARD_BITS
            or mouse_labels != ["E:ID_INPUT_MOUSE=1"] or keyboard_labels not in ([], ["E:ID_INPUT_KEYBOARD=0"])
            or "E:ID_INPUT_KEY=1" in props):
        raise OSError("expected a dedicated mouse event device")
    return event.stat()


def _fd_capabilities(fd, event_type, nbytes):
    # Linux EVIOCGBIT verifies the evdev instance attached to this descriptor.
    request = (2 << 30) | (nbytes << 16) | (ord("E") << 8) | (0x20 + event_type)
    return int.from_bytes(fcntl.ioctl(fd, request, bytes(nbytes)), sys.byteorder)


def open_mouse(path):
    node = Path(path)
    if "kbd" in node.name.lower() or "keyboard" in node.name.lower():
        raise OSError("expected a mouse event node")
    if node.parent == _INPUT / "by-id" and node.name.endswith("-event-mouse"):
        target = Path(os.readlink(node))
        if target.parent == Path(".."):
            node = _INPUT / target.name
        else:
            node = target
    if node.parent != _INPUT or not re.fullmatch(r"event[0-9]+", node.name):
        raise OSError("expected a mouse event node")
    pinned = os.open(node, os.O_PATH | os.O_NOFOLLOW)
    try:
        original = os.fstat(pinned)
        event = _verify_mouse(original, node)
        fd = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            if (opened.st_rdev != original.st_rdev or not os.path.samestat(opened, original)
                    or not os.path.samestat(event, _verify_mouse(opened, node))
                    or _fd_capabilities(fd, 2, 8) & 3 != 3
                    or _fd_capabilities(fd, 1, 16) & _KEYBOARD_BITS):
                raise OSError("mouse event device changed")
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(pinned)


class MouseEdges:
    def __init__(self, path, threshold, callback):
        if threshold < 1 or "kbd" in str(path).lower():
            raise ValueError("expected a mouse event path and positive threshold")
        self.path, self.threshold, self.callback = path, threshold, callback
        self.fd = self.retry = self.task = None
        self.reset()

    def reset(self):
        self.motion = [0, 0]
        self.last = [0., 0.]
        self.next_query = 0.

    def start(self):
        loop = asyncio.get_running_loop()
        self.retry = None
        try:
            self.fd = open_mouse(self.path)
            loop.add_reader(self.fd, self.read)
        except OSError:
            self.detach()
            self.retry = loop.call_later(2, self.start)

    def detach(self):
        if self.fd is not None:
            asyncio.get_running_loop().remove_reader(self.fd)
            os.close(self.fd)
            self.fd = None
        self.reset()

    def feed(self, data, now):
        for _, _, kind, code, value in EVENT.iter_unpack(data):
            if kind == 2 and code in (0, 1):
                if now-self.last[code] > .25 or self.motion[code]*value < 0:
                    self.motion[code] = 0
                self.motion[code] += value
                self.last[code] = now
            elif kind == 0 and code == 0:
                for i in range(2):
                    if now-self.last[i] > .25:
                        self.motion[i] = 0
                axis = max(range(2), key=lambda i: abs(self.motion[i]))
                value = self.motion[axis]
                if abs(value) >= self.threshold and now >= self.next_query and (
                        self.task is None or self.task.done()):
                    self.motion = [0, 0]
                    self.next_query = now + .04
                    self.task = asyncio.create_task(self.check(Edge(axis*2 + int(value > 0))))

    async def check(self, edge):
        try:
            await self.callback(edge)
        except (ValueError, OSError, KeyError) as exc:
            LOG.warning("Edge query failed (%s: %s)", type(exc).__name__, exc)

    def read(self):
        try:
            data = os.read(self.fd, EVENT.size*128)
            if not data:
                raise OSError("mouse detached")
            self.feed(data, time.monotonic())
        except BlockingIOError:
            pass
        except OSError:
            self.detach()
            self.retry = asyncio.get_running_loop().call_later(2, self.start)

    async def close(self):
        if self.retry:
            self.retry.cancel()
        self.detach()
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
