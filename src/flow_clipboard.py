"""Bounded Wayland clipboard I/O and the Marconi RGBA image representation."""
import asyncio
from contextlib import suppress
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import struct
from threading import Event
from urllib.parse import unquote_to_bytes, urlsplit
import zlib

from flow_transfer import CaptureBudget, MAX_ENTRIES, MAX_TOTAL, OfferedRoot, TransferError, disk_io
from marconi_packets import ClipboardImage, MAX_RGBA_BYTES

MAX_PNG = MAX_RGBA_BYTES + (1 << 20)
MAX_TEXT = 16 << 20
PNG = b"\x89PNG\r\n\x1a\n"
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
FILES_MIME = "x-special/gnome-copied-files"
TEXT = {b"text/plain": ("text/plain;charset=utf-8", "text/plain", "UTF8_STRING"),
        b"text/html": ("text/html",), b"text/rtf": ("text/rtf", "application/rtf"),
        b"text/xml": ("text/xml", "application/xml")}
IMAGE_TYPES = {"image/png": "png", "image/jpeg": "jpeg", "image/bmp": "bmp", "image/tiff": "tiff"}


def dimensions(w, h):
    if not (1 <= w <= 16384 and 1 <= h <= 16384 and w*h*4 <= MAX_RGBA_BYTES):
        raise TransferError()


def _png_dimensions(png_bytes):
    if len(png_bytes) > MAX_PNG or len(png_bytes) < 33 or not png_bytes.startswith(PNG):
        raise TransferError()
    length, kind = struct.unpack_from(">I4s", png_bytes, 8)
    if length != 13 or kind != b"IHDR":
        raise TransferError()
    data = memoryview(png_bytes)[16:29]
    if zlib.crc32(data, zlib.crc32(kind)) != struct.unpack_from(">I", png_bytes, 29)[0]:
        raise TransferError()
    w, h = struct.unpack_from(">2I", data)
    dimensions(w, h)
    return w, h


def chunk(kind, data):
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(data, zlib.crc32(kind))))


async def convert_image(codec, *args):
    stop = Event()
    worker = asyncio.create_task(asyncio.to_thread(codec, *args, _stop=stop))
    try:
        return await asyncio.shield(worker)
    finally:
        stop.set()
        await asyncio.gather(worker, return_exceptions=True)


def marconi_image_to_png(width, height, pixels, *, _stop=None):
    dimensions(width, height)
    stride = width * 4
    if len(pixels) != stride * height:
        raise TransferError()
    compressor = zlib.compressobj(3)
    encoded = bytearray()
    for start in range(0, len(pixels), stride):
        if _stop is not None and _stop.is_set():
            raise TransferError()
        encoded.extend(compressor.compress(b"\0" + pixels[start:start+stride]))
    encoded.extend(compressor.flush())
    header = struct.pack(">2I5B", width, height, 8, 6, 0, 0, 0)
    return PNG + chunk(b"IHDR", header) + chunk(b"IDAT", bytes(encoded)) + chunk(b"IEND", b"")


def unfilter(row, prev, step, method):
    if method == 0:
        return
    if method > 4:
        raise TransferError()
    for i, x in enumerate(row):
        left = row[i-step] if i >= step else 0
        up = prev[i]
        if method == 1:
            delta = left
        elif method == 2:
            delta = up
        elif method == 3:
            delta = (left + up) // 2
        else:
            corner = prev[i-step] if i >= step else 0
            p = left + up - corner
            a, b, c = abs(p-left), abs(p-up), abs(p-corner)
            delta = left if a <= b and a <= c else up if b <= c else corner
        row[i] = (x + delta) & 255


def png_to_marconi_image(png_bytes, *, _stop=None):
    if len(png_bytes) > MAX_PNG or not png_bytes.startswith(PNG):
        raise TransferError()
    pos = 8
    w = h = color = None
    palette = alpha = None
    compressed = bytearray()
    started = ended = False
    while True:
        if (_stop is not None and _stop.is_set()) or pos + 12 > len(png_bytes):
            raise TransferError()
        length, kind = struct.unpack_from(">I4s", png_bytes, pos)
        end = pos + 8 + length
        if end + 4 > len(png_bytes):
            raise TransferError()
        data = memoryview(png_bytes)[pos+8:end]
        if zlib.crc32(data, zlib.crc32(kind)) != struct.unpack_from(">I", png_bytes, end)[0]:
            raise TransferError()
        pos = end + 4
        if w is None and kind != b"IHDR":
            raise TransferError()
        if kind == b"IHDR":
            if w is not None or length != 13:
                raise TransferError()
            w, h, bits, color, comp, filt, interlace = struct.unpack(">2I5B", data)
            dimensions(w, h)
            if bits != 8 or color not in CHANNELS or comp or filt or interlace:
                raise TransferError()
        elif kind == b"PLTE":
            if (started or palette is not None or alpha is not None or color in (0, 4)
                    or not 0 < length <= 768 or length % 3):
                raise TransferError()
            palette = bytes(data)
        elif kind == b"tRNS":
            if started or alpha is not None or color not in (0, 2, 3):
                raise TransferError()
            if color == 3:
                if palette is None or not 0 < length <= len(palette)//3:
                    raise TransferError()
            elif length != (2 if color == 0 else 6) or any(data[::2]):
                raise TransferError()
            alpha = bytes(data)
        elif kind == b"IDAT":
            if ended or color == 3 and palette is None:
                raise TransferError()
            started = True
            compressed.extend(data)
        elif kind == b"IEND":
            if length or not started or pos != len(png_bytes):
                raise TransferError()
            break
        else:
            if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind) or not kind[0] & 32 or kind[2] & 32:
                raise TransferError()
            ended = started
    stride = w * CHANNELS[color]
    expected = h * (stride + 1)
    stream = zlib.decompressobj()
    try:
        raw = stream.decompress(compressed, expected + 1)
    except zlib.error:
        raise TransferError() from None
    if len(raw) != expected or not stream.eof or stream.unused_data or stream.unconsumed_tail:
        raise TransferError()
    pixels = bytearray(w*h*4)
    prev = bytes(stride)
    transparent = tuple(struct.unpack(">H" if color == 0 else ">3H", alpha)) if alpha and color in (0, 2) else ()
    for y in range(h):
        if _stop is not None and _stop.is_set():
            raise TransferError()
        start = y * (stride + 1)
        row = bytearray(raw[start+1:start+1+stride])
        unfilter(row, prev, CHANNELS[color], raw[start])
        prev = row
        dest = memoryview(pixels)[y*w*4:(y+1)*w*4]
        if color == 6:
            dest[:] = row
        elif color == 3:
            for x, index in enumerate(row):
                if 3*index >= len(palette):
                    raise TransferError()
                dest[4*x:4*x+3] = palette[3*index:3*index+3]
                dest[4*x+3] = alpha[index] if alpha and index < len(alpha) else 255
        else:
            if color == 2:
                for i in range(3):
                    dest[i::4] = row[i::3]
            else:
                gray = row[::CHANNELS[color]]
                for i in range(3):
                    dest[i::4] = gray
            dest[3::4] = row[1::2] if color == 4 else b"\xff"*w
            if transparent:
                for x in range(w):
                    i = x * CHANNELS[color]
                    if tuple(row[i:i+CHANNELS[color]]) == transparent:
                        dest[x*4+3] = 0
    return w, h, bytes(pixels)


@dataclass(frozen=True, repr=False)
class LocalClipboardSnapshot:
    provider_id: bytes
    values: tuple
    roots: tuple
    fingerprint: bytes

    @property
    def formats(self):
        return ((b"file",) if self.roots else ()) + tuple(mime for mime, _ in self.values)


def snapshot(values=(), roots=(), *, selection_key=b""):
    digest = hashlib.sha256()
    digest.update(selection_key)
    for mime, data in values:
        digest.update(mime + b"\0" + hashlib.sha256(data).digest())
    for root in roots:
        digest.update(bytes(root.path) + b"\0" + str(root.identity[:2]).encode())
    return LocalClipboardSnapshot(secrets.token_hex(16).encode(), tuple(values), tuple(roots),
                                  digest.digest())


def local_roots(data, mime):
    lines = data.splitlines()
    if mime == FILES_MIME:
        if lines[:1] not in ([b"copy"], [b"cut"]):
            return ()
        lines = lines[1:]
    if len(lines) > MAX_ENTRIES:
        raise TransferError()
    roots = []
    paths = set()
    budget = CaptureBudget()
    for line in lines:
        try:
            if not line.startswith(b"file://") or any(c < 32 for c in line):
                continue
            uri = urlsplit(line.decode("utf8"))
            if uri.netloc not in ("", "localhost") or uri.query or uri.fragment:
                continue
            path = Path(unquote_to_bytes(uri.path).decode("utf8"))
        except (ValueError, OSError):
            continue
        if path in paths:
            continue
        paths.add(path)
        try:
            roots.append(OfferedRoot.capture(path, budget))
        except TransferError:
            # Invalid roots are omitted, but the selection-wide budget is never reset.
            if budget.entries > MAX_ENTRIES or budget.size > MAX_TOTAL:
                raise
    return tuple(roots)


async def stop_child(proc):
    if proc and proc.returncode is None:
        with suppress(ProcessLookupError):
            proc.kill()
        # Drain pipe transports too when stopping a producer at the byte limit.
        if proc.stdout:
            while await proc.stdout.read(64 << 10):
                pass
        await proc.wait()


async def output(argv, limit, timeout, stdin=None, *, empty_on_status_one=False):
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE if stdin is not None
                                                else asyncio.subprocess.DEVNULL,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    async def feed():
        if stdin is not None:
            proc.stdin.write(stdin)
            await proc.stdin.drain()
            proc.stdin.close()

    async def read():
        buf = bytearray()
        while piece := await proc.stdout.read(64 << 10):
            if len(buf) + len(piece) > limit:
                raise TransferError()
            buf.extend(piece)
        status = await proc.wait()
        if empty_on_status_one and status == 1:
            return b""
        if status:
            raise TransferError()
        return bytes(buf)

    writer = asyncio.create_task(feed())
    try:
        result = await asyncio.wait_for(read(), timeout)
        await writer
        return result
    finally:
        writer.cancel()
        await asyncio.gather(writer, return_exceptions=True)
        await stop_child(proc)


class WaylandUnavailable(Exception):
    """A transient local clipboard publication failure."""


class WaylandClipboard:
    def __init__(self):
        self.owner = None
        self.lock = asyncio.Lock()
        self.image_cache = self.root_cache = None
        self.local_generation = 0
        self.selection_key = None
        self.observed_types = None

    def forget_local(self):
        self.image_cache = self.root_cache = None

    def owns_selection(self):
        # asyncio.Process.returncode is updated by the child watcher.
        return self.owner is not None and self.owner.returncode is None

    async def _observe(self):
        if self.owns_selection():
            result, key = None, "owned"
        else:
            result = await self._snapshot()
            key = result.fingerprint if result is not None else None
        if self.selection_key != key:
            self.selection_key = key
            self.local_generation += 1
        return result

    async def snapshot_local(self):
        async with self.lock:
            try:
                return await self._observe()
            except (ValueError, OSError, asyncio.TimeoutError):
                self.local_generation += 1
                self.selection_key = "unavailable"
                self.forget_local()
                return None

    async def _image(self, mime, coder, encoded):
        key = mime, hashlib.sha256(encoded).digest()
        if self.image_cache and self.image_cache[0] == key:
            return self.image_cache[1]
        self.image_cache = None
        if coder == "png" and len(encoded) > 4096 and os.path.exists("/usr/bin/magick"):
            w, h = _png_dimensions(encoded)
            rgba = await output(["/usr/bin/magick", "-limit", "disk", "0", "-limit", "map", "0",
                                 "-limit", "memory", "160MiB", "-limit", "width", "16384",
                                 "-limit", "height", "16384", "-limit", "thread", "1",
                                 "png:-[0]", "-strip", "-colorspace", "sRGB", "-alpha", "on",
                                 "-depth", "8", "rgba:-"],
                                w * h * 4, 5, encoded)
            if len(rgba) != w * h * 4:
                raise TransferError()
        else:
            if coder != "png":
                encoded = await output(["/usr/bin/magick", "-limit", "disk", "0", "-limit", "map", "0",
                                        "-limit", "memory", "160MiB", "-limit", "width", "16384",
                                        "-limit", "height", "16384", "-limit", "thread", "1",
                                        coder + ":-[0]", "-strip", "-interlace", "none",
                                        "-define", "png:compression-filter=0",
                                        "-define", "png:compression-level=1", "png32:-"],
                                       MAX_PNG, 5, encoded)
            w, h, rgba = await convert_image(png_to_marconi_image, encoded)
        image = ClipboardImage(w, h, rgba).encode()
        self.image_cache = key, image
        return image

    async def _types(self):
        raw = await output(["/usr/bin/wl-paste", "--list-types"], 16384, 2, empty_on_status_one=True)
        return tuple(sorted(set(raw.decode("utf8").splitlines())))

    async def _snapshot(self):
        paste = "/usr/bin/wl-paste"
        types = self.observed_types = await self._types()
        key = hashlib.sha256("\0".join(types).encode())

        async def read(mime, cap):
            return await output([paste, "--no-newline", "--type", mime], cap, 5)

        roots = ()
        values = []
        for mime in (FILES_MIME, "text/uri-list"):
            if mime in types:
                try:
                    uris = await read(mime, 1 << 20)
                    root_key = (mime, hashlib.sha256(uris).digest())
                    key.update(root_key[1])
                    if self.root_cache and self.root_cache[0] == root_key:
                        roots = self.root_cache[1]
                    else:
                        roots = await disk_io(local_roots, uris, mime)
                        self.root_cache = (root_key, roots)
                except (OSError, ValueError, asyncio.TimeoutError):
                    continue
                if roots:
                    break
        if not roots:
            self.root_cache = None
        for mime, coder in IMAGE_TYPES.items():
            if mime in types:
                try:
                    image = await self._image(mime, coder, await read(mime, MAX_PNG))
                except (OSError, ValueError, asyncio.TimeoutError):
                    continue
                values.append((b"image", image))
                break
        else:
            self.image_cache = None
        left = MAX_TEXT
        for wire, aliases in TEXT.items():
            mime = next((t for t in types if t.lower() in {a.lower() for a in aliases}), None)
            if mime:
                try:
                    data = await read(mime, left)
                    if wire == b"text/plain":
                        data.decode("utf8")
                except (OSError, ValueError, asyncio.TimeoutError):
                    continue
                left -= len(data)
                values.append((wire, data))
        return snapshot(values, roots, selection_key=key.digest()) if types else None

    async def _publish(self, mime, data, generation):
        async with self.lock:
            if generation is not None:
                await self._observe()
                if (not self.owns_selection() and self.observed_types is not None
                        and await self._types() != self.observed_types):
                    self.local_generation += 1
                if self.local_generation != generation:
                    raise TransferError()
            previous = self.owner
            try:
                await self._install(mime, data)
                self.selection_key = "owned"
                self.forget_local()
            finally:
                if previous is not self.owner:
                    await stop_child(previous)

    async def _install(self, mime, data):
        self.owner = await asyncio.create_subprocess_exec(
            "/usr/bin/wl-copy", "--foreground", "--type", mime, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)

        async def feed():
            self.owner.stdin.write(data)
            await self.owner.stdin.drain()
            self.owner.stdin.close()
            await self.owner.stdin.wait_closed()
            while self.owns_selection():
                try:
                    value = await output(["/usr/bin/wl-paste", "--no-newline", "--type", mime],
                                         len(data), 2)
                    if value == data and self.owns_selection():
                        return
                except (ValueError, asyncio.TimeoutError):
                    pass
                await asyncio.sleep(.04)
            raise WaylandUnavailable()

        try:
            await asyncio.wait_for(feed(), 5)
        except BaseException:
            await stop_child(self.owner)
            raise

    async def set_text(self, mime, data, *, generation=None):
        if mime not in TEXT or len(data) > MAX_TEXT:
            raise TransferError()
        await self._publish(TEXT[mime][0], data, generation)

    async def set_image_png(self, png, *, generation=None):
        await self._publish("image/png", png, generation)

    async def set_files(self, paths, *, generation=None):
        data = ("copy\n" + "\n".join(p.as_uri() for p in paths)).encode()
        await self._publish(FILES_MIME, data, generation)

    async def close(self):
        async with self.lock:
            await stop_child(self.owner)
            self.owner = None
            self.forget_local()
