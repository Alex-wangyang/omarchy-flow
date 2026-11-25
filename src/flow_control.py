"""Local Flow control protocol and UI arrangement model (standard library only)."""
import asyncio
from contextlib import contextmanager
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import struct
import secrets
import threading

RPC_TIMEOUT = 15
RESCAN_TIMEOUT = 20
LIMIT = 64 * 1024
LAYOUT_GRID = {
    "horizontal": ((0, 0), (1, 0), (2, 0)),
    "vertical": ((0, 0), (0, 1), (0, 2)),
    "left-top": ((1, 0), (0, 0), (0, 1)),
    "right-top": ((0, 0), (1, 0), (1, 1)),
    "left-bottom": ((0, 0), (0, 1), (1, 1)),
    "right-bottom": ((1, 0), (1, 1), (0, 1)),
}
FLAGS = {"on", "ctrl_key", "copy_paste", "hot_corners", "keyboard_link"}
DEFAULTS = {"modifier_key": "ctrl", "edge_threshold": 40, "edge_cooldown": 0.6}


def clipboard_summary(direction, kind, count, size=0):
    """Build status solely from fixed categories and numeric measurements."""
    if direction not in ("IN", "OUT") or kind not in ("text", "image", "files"):
        raise ValueError("unknown clipboard summary")
    if any(type(n) is not int or n < 0 for n in (count, size)):
        raise ValueError("invalid clipboard measurement")
    if kind == "image":
        detail = f"image ({count}x{size})"
    elif kind == "text":
        detail = f"text ({count} B)"
    else:
        amount = f"{size} B" if size < 1048576 else f"{size / 1048576:.1f} MiB"
        detail = f"{count} files ({amount})"
    return f"Clipboard {direction} · {detail}"


class ControlError(ValueError):
    """Public, fixed validation messages suitable for the control UI."""


def require(condition, message):
    if not condition:
        raise ControlError(message)


def _rows(peers, *slots):
    require(len(peers) == 3 and all(type(i) is int and 0 <= i < 3 for i in slots),
            "invalid peer slot")
    return [dict(peer) for peer in peers]


def _number(rows):
    return [dict(row, slot=i) for i, row in enumerate(rows)]


def swap_peer_slots(peers, first, second):
    rows = _rows(peers, first, second)
    rows[first], rows[second] = rows[second], rows[first]
    return _number(rows)


def move_peer_slot(peers, source, target):
    rows = _rows(peers, source, target)
    rows.insert(target, rows.pop(source))
    return _number(rows)


def toggle_peer_enabled(peers, slot):
    rows = _rows(peers, slot)
    row = rows[slot]
    require(row["host_id"] and not row["is_local"], "select an occupied remote slot")
    row["enabled"] = not row["enabled"]
    return rows


def remove_peer_slot(peers, slot):
    rows = _rows(peers, slot)
    require(rows[slot]["host_id"] and not rows[slot]["is_local"], "select an occupied remote slot")
    rows[slot].update(host_id="", enabled=False, keyboard_channel=0xffffffff,
                      connected=False, peer_ip=None)
    return rows


def build_settings_update(settings, *, peers=None, **changes):
    require(not changes.keys() - (FLAGS | {"layout"}), "unknown setting")
    if settings is not None:
        changes["expected_counter"] = settings["counter"]
    if peers is not None:
        changes["peers"] = [{key: row[key] for key in ("channel", "host_id", "enabled")}
                            for row in peers]
    return changes


def validate_preferences(changes, base=None):
    require(type(changes) is dict and not changes.keys() - DEFAULTS.keys(), "unknown preference")
    prefs = {**(DEFAULTS if base is None else base), **changes}
    require(prefs["modifier_key"] in ("ctrl", "super", "alt"), "invalid modifier key")
    n, t = prefs["edge_threshold"], prefs["edge_cooldown"]
    require(type(n) is int and 5 <= n <= 500, "edge threshold must be 5..500")
    require(type(t) in (int, float) and .1 <= t <= 5, "edge cooldown must be 0.1..5")
    prefs["edge_cooldown"] = float(t)
    return prefs


@contextmanager
def private_dir(path, *, create=True):
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except NotADirectoryError:
        raise ControlError("expected a private directory") from None
    try:
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700, "expected an owned private 0700 directory")
        yield fd
    finally:
        os.close(fd)


def check_file(info):
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600, "expected an owned private 0600 file")


def read_private_json(directory, name, *, limit=LIMIT):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        check_file(os.fstat(fd))
        body = stream.read() if limit is None else stream.read(limit + 1)
        require(limit is None or len(body) <= limit, "private file too large")
        try:
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    raise ValueError("invalid state file") from None


def write_private_json(directory, name, value):
    try:
        check_file(os.stat(name, dir_fd=directory, follow_symlinks=False))
    except FileNotFoundError:
        pass
    temp = ".flow-" + secrets.token_hex(16)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            os.fchmod(out.fileno(), 0o600)
            json.dump(value, out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, name, src_dir_fd=directory, dst_dir_fd=directory)
    finally:
        try:
            os.unlink(temp, dir_fd=directory)
        except FileNotFoundError:
            pass


def save_preferences(path, prefs):
    with private_dir(path.parent) as directory:
        write_private_json(directory, path.name, validate_preferences(prefs))


def load_preferences(path, overrides):
    with private_dir(path.parent) as directory:
        try:
            saved = validate_preferences(read_private_json(directory, path.name))
        except FileNotFoundError:
            saved = None
        prefs = validate_preferences(overrides, saved)
        if prefs != saved:
            write_private_json(directory, path.name, prefs)
        return prefs


def default_config_dir():
    root = Path(os.environ.get("XDG_CONFIG_HOME") or ".")
    if not root.is_absolute():
        root = Path.home() / ".config"
    return root / "omarchy-flow"


def default_socket():
    root = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.geteuid()}"))
    return root / "omarchy-flow/control.sock"


def _frame(obj):
    data = json.dumps(obj, allow_nan=False, separators=(",", ":")).encode() + b"\n"
    require(len(data) <= LIMIT, "control message too large")
    return data


def _parse(data):
    require(len(data) <= LIMIT and data.endswith(b"\n"), "invalid control frame")
    obj = json.loads(data)
    require(type(obj) is dict, "expected a JSON object")
    return obj


class ControlClient:
    def __init__(self, socket_path=None, timeout=10):
        self.path = Path(socket_path) if socket_path else default_socket()
        self.timeout = timeout
        self.lock = threading.Lock()
        self.active = set()
        self.closed = False

    def close(self):
        with self.lock:
            self.closed = True
            for sock in self.active:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

    def call(self, method, **params):
        data = _frame({"method": method, "params": params})
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            with self.lock:
                if self.closed:
                    raise OSError("control client closed")
                self.active.add(sock)
            try:
                sock.settimeout(self.timeout)
                sock.connect(str(self.path))
                sock.sendall(data)
                with sock.makefile("rb") as stream:
                    reply = _parse(stream.readline(LIMIT + 1))
            finally:
                with self.lock:
                    self.active.discard(sock)
        if "error" in reply:
            raise ControlError(reply["error"])
        return reply["result"]


def _same_user(sock):
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1] == os.geteuid()


class ControlServer:
    def __init__(self, path, dispatch):
        self.path, self.dispatch = Path(path), dispatch
        self.server = self.identity = self.directory = None
        self.clients = set()
        self.closing = False

    def _bind(self, sock):
        address = f"/proc/self/fd/{self.directory}/{self.path.name}"
        try:
            sock.bind(address)
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE:
                raise
            info = os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)
            require(stat.S_ISSOCK(info.st_mode), "control path is occupied")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(.3)
                try:
                    probe.connect(address)
                except ConnectionRefusedError:
                    require(os.path.samestat(info, os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)), "control socket changed")
                    os.unlink(self.path.name, dir_fd=self.directory)
                else:
                    raise ControlError("control socket is in use")
            sock.bind(address)
        self.identity = os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)
        os.chmod(self.path.name, 0o600, dir_fd=self.directory)
        sock.listen(16)

    async def start(self):
        require(hasattr(socket, "SO_PEERCRED"), "Linux peer credentials unavailable")
        with private_dir(self.path.parent) as directory:
            self.directory = os.dup(directory)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._bind(sock)
                sock.setblocking(False)
                self.server = await asyncio.start_unix_server(self._handle, sock=sock, limit=LIMIT)
            except BaseException:
                sock.close()
                self._unlink()
                raise
            finally:
                fcntl.flock(directory, fcntl.LOCK_UN)

    def _unlink(self):
        try:
            if self.identity and os.path.samestat(self.identity, os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)):
                os.unlink(self.path.name, dir_fd=self.directory)
        except FileNotFoundError:
            pass
        self.identity = None
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        reply = None
        try:
            if not _same_user(writer.get_extra_info("socket")) or self.closing or len(self.clients) >= 16:
                return
            self.clients.add(task)
            started = asyncio.get_running_loop().time()
            line = await asyncio.wait_for(reader.readline(), 3)
            if not line:
                return
            request = _parse(line)
            require(not request.keys() - {"method", "params"} and type(request.get("method")) is str
                    and type(request.get("params", {})) is dict, "invalid request")
            method = request["method"]
            limit = RESCAN_TIMEOUT if method == "rescan_devices" else RPC_TIMEOUT
            remaining = started + limit - asyncio.get_running_loop().time()
            result = await asyncio.wait_for(self.dispatch(method, request.get("params", {})), remaining)
            reply = _frame({"result": result})
        except asyncio.TimeoutError:
            reply = _frame({"error": "control request timed out"})
        except ControlError as exc:
            reply = _frame({"error": str(exc)})
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            reply = _frame({"error": "invalid request or operation unavailable"})
        finally:
            try:
                if reply is not None:
                    writer.write(reply)
                    await asyncio.wait_for(writer.drain(), 3)
            except (OSError, TimeoutError):
                pass
            finally:
                writer.close()
                self.clients.discard(task)

    async def close(self):
        self.closing = True
        if self.server:
            self.server.close()
            tasks = tuple(self.clients)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.server.wait_closed()
        self._unlink()
