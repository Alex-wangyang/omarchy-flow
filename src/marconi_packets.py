"""Marconi FARS packets, authenticated envelopes and TCP framing."""
from contextvars import ContextVar
from dataclasses import dataclass
import time
from enum import IntEnum
from struct import pack, unpack
from typing import ClassVar, Tuple, Union
import zlib

from fars import (BinHeader, Buffer, DecodeError, PlaintextHeader, Reader, SerializableV1,
                  SessionHeader, byte_string, size_t, unwrap_plaintext)
from marconi_crypto import DHEParams, decrypt_frame, encrypt_frame


@dataclass(frozen=True)
class InitiateDiscoveryPacket:
    device_id: int
    serial_number: int
    channel: int
    force: bool
    version: ClassVar[int] = 1


@dataclass(frozen=True)
class BeaconPacket:
    device_id: int
    serial_number: int
    channel: int
    host_id: bytes
    force: bool
    port: int
    version: ClassVar[int] = 2


@dataclass(frozen=True)
class PingPacket(BeaconPacket):
    """The ping writer emits the same fields as the beacon writer."""


Discovery = Union[InitiateDiscoveryPacket, BeaconPacket, PingPacket]
_TYPES = {cls.__name__.encode("ascii"): cls
          for cls in (InitiateDiscoveryPacket, BeaconPacket, PingPacket)}


def encode_discovery(packet: Discovery) -> bytes:
    type_name = type(packet).__name__.encode("ascii")
    if _TYPES.get(type_name) is not type(packet):
        raise ValueError("unsupported discovery type")
    body = pack(">III", packet.device_id, packet.serial_number, packet.channel)
    if isinstance(packet, InitiateDiscoveryPacket):
        body += pack(">?", packet.force)
    else:
        body += byte_string(packet.host_id) + pack(">?H", packet.force, packet.port)
    return BinHeader(type_name, packet.version, len(body)).encode() + body


def decode_discovery(data: bytes) -> Discovery:
    reader = Reader(data)
    header = BinHeader.read(reader)
    cls = _TYPES.get(header.type_name)
    if cls is None or cls.version != header.version:
        raise DecodeError("unsupported discovery class or version")
    body = Reader(reader.take(header.payload_size))
    reader.finish()
    identity = unpack(">III", body.take(12))
    if cls is InitiateDiscoveryPacket:
        packet = cls(*identity, body.uint(1) == 1)
    else:
        packet = cls(*identity, body.byte_string(), body.uint(1) == 1, body.uint(2))
    body.finish()
    return packet


@dataclass(frozen=True)
class Peer:
    channel: int
    keyboard_channel: int
    host_id: bytes
    enabled: bool

    def encode(self) -> bytes:
        return (pack(">II", self.channel, self.keyboard_channel)
                + byte_string(self.host_id) + pack(">?", self.enabled))

    @classmethod
    def read(cls, reader: Reader) -> "Peer":
        return cls(reader.uint(4), reader.uint(4), reader.byte_string(), reader.uint(1) == 1)


@dataclass(frozen=True)
class Settings:
    counter: int
    layout: bytes
    on: bool
    ctrl_key: bool
    copy_paste: bool
    drag_drop: bool
    hot_corners: bool
    keyboard_link: bool
    keyboard_id: int
    keyboard_serial_number: int
    peers: Tuple[Peer, Peer, Peer]

    def encode(self) -> bytes:
        if len(self.peers) != 3:
            raise ValueError("settings requires three peer records")
        flags = pack(">6?", self.on, self.ctrl_key, self.copy_paste,
                     self.drag_drop, self.hot_corners, self.keyboard_link)
        keyboard = pack(">II", self.keyboard_id, self.keyboard_serial_number)
        return (pack(">I", self.counter) + byte_string(self.layout) + flags + keyboard
                + b"".join(peer.encode() for peer in self.peers))

    @classmethod
    def read(cls, reader: Reader) -> "Settings":
        counter = reader.uint(4)
        layout = reader.byte_string()
        flags = [value == 1 for value in reader.take(6)]
        keyboard_id, keyboard_serial = unpack(">II", reader.take(8))
        peers = tuple(Peer.read(reader) for _ in range(3))
        return cls(counter, layout, *flags, keyboard_id, keyboard_serial, peers)


@dataclass(frozen=True)
class SettingsPacket:
    device_id: int
    serial_number: int
    channel: int
    settings: Settings

    def encode(self) -> bytes:
        identity = pack(">III", self.device_id, self.serial_number, self.channel)
        return _v1_object(b"SettingsPacket", identity + self.settings.encode())

    @classmethod
    def decode(cls, data: bytes) -> "SettingsPacket":
        body = _v1_body(b"SettingsPacket", data)
        identity = unpack(">III", body.take(12))
        result = cls(*identity, Settings.read(body))
        body.finish()
        return result


def _v1_object(name: bytes, body: bytes) -> bytes:
    return BinHeader(name, 1, len(body)).encode() + body


def _v1_body(name: bytes, data: bytes) -> Reader:
    reader = Reader(data)
    header = BinHeader.read(reader)
    if (header.type_name, header.version) != (name, 1):
        raise DecodeError("unexpected class or version")
    body = Reader(reader.take(header.payload_size))
    reader.finish()
    return body


@dataclass(frozen=True)
class HeartbeatPacket:
    last_received_packet_time: int
    current_time: int

    def encode(self) -> bytes:
        body = pack(">qq", self.last_received_packet_time, self.current_time)
        return _v1_object(b"HeartbeatPacket", body)

    @classmethod
    def decode(cls, data: bytes) -> "HeartbeatPacket":
        body = _v1_body(b"HeartbeatPacket", data)
        packet = cls(*unpack(">qq", body.take(16)))
        body.finish()
        return packet


@dataclass(frozen=True)
class GlobalDataPacket:
    host_id: bytes
    chunk_number: int
    chunk_count: int
    buffer: Buffer

    def encode(self) -> bytes:
        body = (byte_string(self.host_id) + size_t(self.chunk_number)
                + size_t(self.chunk_count) + self.buffer.encode())
        return _v1_object(b"GlobalDataPacket", body)

    @classmethod
    def decode(cls, data: bytes) -> "GlobalDataPacket":
        body = _v1_body(b"GlobalDataPacket", data)
        packet = cls(body.byte_string(), body.size_t(), body.size_t(), Buffer.read(body))
        body.finish()
        return packet


@dataclass(frozen=True)
class DeviceDataPacket:
    device_id: int
    serial_number: int
    channel: int
    chunk_number: int
    chunk_count: int
    buffer: Buffer

    def encode(self) -> bytes:
        identity = pack(">III", self.device_id, self.serial_number, self.channel)
        body = identity + size_t(self.chunk_number) + size_t(self.chunk_count) + self.buffer.encode()
        return _v1_object(b"DeviceDataPacket", body)

    @classmethod
    def decode(cls, data: bytes) -> "DeviceDataPacket":
        body = _v1_body(b"DeviceDataPacket", data)
        identity = unpack(">III", body.take(12))
        packet = cls(*identity, body.size_t(), body.size_t(), Buffer.read(body))
        body.finish()
        return packet


@dataclass
class Session:
    guid: bytes
    inbound_seq: int
    outbound_seq: int

    def __post_init__(self):
        if len(self.guid) != 16 or not all(0 <= n < 1 << 64 for n in
                                          (self.inbound_seq, self.outbound_seq)):
            raise ValueError("invalid session")

    def inverted(self):
        return Session(self.guid, self.outbound_seq, self.inbound_seq)

    def encode(self):
        return self.guid + pack(">QQ", self.inbound_seq, self.outbound_seq)

    @classmethod
    def read(cls, r):
        return cls(r.take(16), r.uint(8), r.uint(8))

    def next_outbound_header(self):
        header = SessionHeader(self.guid, self.outbound_seq)
        self.outbound_seq = (self.outbound_seq + 1) % (1 << 64)
        return header

    def verify_inbound_header(self, header):
        if header != SessionHeader(self.guid, self.inbound_seq):
            raise DecodeError("unexpected session GUID or inbound sequence")
        self.inbound_seq = (self.inbound_seq + 1) % (1 << 64)


CIPHER_SUITE = b"ECDHE_ECDSA_AES-256-GCM_SHA2-512"


@dataclass(frozen=True)
class ClientHelloPacket(SerializableV1):
    host_id: bytes
    cipher_suite: bytes
    params: DHEParams

    def encode_body(self):
        return byte_string(self.host_id) + byte_string(self.cipher_suite) + self.params.encode()

    @classmethod
    def read_body(cls, r):
        return cls(r.byte_string(), r.byte_string(), DHEParams.read(r))


@dataclass(frozen=True)
class ServerHelloPacket(SerializableV1):
    host_id: bytes
    session: Session
    cipher_suite: bytes
    params: DHEParams

    def encode_body(self):
        return (byte_string(self.host_id) + self.session.encode()
                + byte_string(self.cipher_suite) + self.params.encode())

    @classmethod
    def read_body(cls, r):
        return cls(r.byte_string(), Session.read(r), r.byte_string(), DHEParams.read(r))


@dataclass(frozen=True)
class PromoteConnectionPacket(SerializableV1):
    host_id: bytes

    def encode_body(self):
        return byte_string(self.host_id)

    @classmethod
    def read_body(cls, r):
        return cls(r.byte_string())


@dataclass(frozen=True)
class ClientDeviceConnectPacket(SerializableV1):
    device_id: int
    serial_number: int
    channel: int
    host_id: bytes

    def encode_body(self):
        return pack(">III", self.device_id, self.serial_number, self.channel) + byte_string(self.host_id)

    @classmethod
    def read_body(cls, r):
        return cls(r.uint(4), r.uint(4), r.uint(4), r.byte_string())


class ServerDeviceConnectPacket(ClientDeviceConnectPacket):
    pass


class Edge(IntEnum):
    LEFT = 0
    RIGHT = 1
    TOP = 2
    BOTTOM = 3


@dataclass(frozen=True)
class InitiateFlowPacket(SerializableV1):
    edge: Edge
    position: float

    def __post_init__(self):
        Edge(self.edge)
        if not 0 <= self.position <= 1:
            raise ValueError("flow position outside normalized range")

    def encode_body(self):
        return pack(">If", self.edge, self.position)

    @classmethod
    def read_body(cls, r):
        return cls(Edge(r.uint(4)), unpack(">f", r.take(4))[0])


@dataclass(frozen=True)
class SetCurrentHostPacket(SerializableV1):
    channel: int

    def encode_body(self):
        return pack(">I", self.channel)

    @classmethod
    def read_body(cls, r):
        return cls(r.uint(4))


@dataclass(frozen=True)
class SetOwnerPacket(SerializableV1):
    """The historical flag fields carry the previous and new owners' OS codes."""
    previous_owner: bytes
    previous_flag: int
    new_owner: bytes
    new_flag: int

    def encode_body(self):
        return (byte_string(self.previous_owner) + bytes([self.previous_flag])
                + byte_string(self.new_owner) + bytes([self.new_flag]))

    @classmethod
    def read_body(cls, r):
        return cls(r.byte_string(), r.uint(1), r.byte_string(), r.uint(1))


# Local receive limits, independent of the native on-wire SizeT range.
MAX_RGBA_BYTES = 64 * 1024 * 1024
MAX_CLIPBOARD_BODY = MAX_RGBA_BYTES + 65536  # Includes FARS, Buffer and worst-case zlib overhead.
MAX_FORMATS = 1024
MAX_DESCRIPTORS = 2048
MAX_SOURCE_PATH = 4096
MAX_ENTRY_NAME = 1024
MAX_ERROR_LOCATIONS = 256


def _count(value, limit):
    if value > limit:
        raise DecodeError("vector exceeds local item limit")
    return value


def _bounded_string(reader, limit):
    length = reader.size_t()
    if length > limit:
        raise DecodeError("string exceeds local byte limit")
    return reader.take(length)


def _unsigned(value, width):
    if not 0 <= value < 1 << (8 * width):
        raise ValueError("integer outside unsigned wire range")
    return value.to_bytes(width, "big")


def _clipboard_bool(value):
    if value not in (0, 1):
        raise DecodeError("invalid clipboard boolean")
    return bool(value)


class Phase2Packet(SerializableV1):
    """Clipboard or device diagnostic packet with a bounded body."""
    max_payload_size = MAX_CLIPBOARD_BODY


@dataclass(frozen=True, repr=False)
class ClipboardUpdatePacket(Phase2Packet):
    host_id: bytes
    provider_id: bytes
    formats: Tuple[bytes, ...]

    def encode_body(self):
        return (byte_string(self.host_id) + byte_string(self.provider_id)
                + size_t(_count(len(self.formats), MAX_FORMATS))
                + b"".join(byte_string(item) for item in self.formats))

    @classmethod
    def read_body(cls, r):
        host, provider = r.byte_string(), r.byte_string()
        return cls(host, provider, tuple(r.byte_string() for _ in range(
            _count(r.size_t(), MAX_FORMATS))))


@dataclass(frozen=True, repr=False)
class _ClipboardOperation(Phase2Packet):
    host_id: bytes
    provider_id: bytes
    request_id: bytes

    def prefix(self):
        return byte_string(self.host_id) + byte_string(self.provider_id) + byte_string(self.request_id)

    @staticmethod
    def read_prefix(r):
        return r.byte_string(), r.byte_string(), r.byte_string()


@dataclass(frozen=True, repr=False)
class GetFormatDataPacket(_ClipboardOperation):
    mime_type: bytes

    def encode_body(self):
        return self.prefix() + byte_string(self.mime_type)

    @classmethod
    def read_body(cls, r):
        return cls(*cls.read_prefix(r), r.byte_string())


def _clipboard_buffer(buf):
    if buf.endian not in (1, 2):
        raise DecodeError("invalid clipboard Buffer endianness")
    return buf


ENCODE_STOP = ContextVar("omarchy_flow_encode_stop", default=None)
_DEFLATE_CHUNK = 1 << 18


class EncodeCancelled(Exception):
    """Raised inside a worker thread when an off-loop packet encode is cancelled."""


def _deflate_buffer(buf):
    """Match thekogans::util::Buffer::Deflate (RFC 1950 zlib level 9, empty bypass)."""
    buf = _clipboard_buffer(buf)
    raw = buf.storage[buf.read_offset:buf.write_offset]
    if not raw:
        return Buffer(1, 0, 0, b"DefaultAllocator", b"")
    stop = ENCODE_STOP.get()
    if stop is None or len(raw) <= _DEFLATE_CHUNK:
        if stop is not None and stop.is_set():
            raise EncodeCancelled()
        compressed = zlib.compress(raw, 9)
    else:
        compressor = zlib.compressobj(9)
        view = memoryview(raw)
        parts = []
        for start in range(0, len(view), _DEFLATE_CHUNK):
            if stop.is_set():
                raise EncodeCancelled()
            parts.append(compressor.compress(view[start:start + _DEFLATE_CHUNK]))
        if stop.is_set():
            raise EncodeCancelled()
        parts.append(compressor.flush())
        compressed = b"".join(parts)
    return Buffer(buf.endian, 0, len(compressed), b"DefaultAllocator", compressed)


def _inflate_buffer(buf, max_size):
    """Match thekogans::util::Buffer::Inflate with bounded decompression."""
    buf = _clipboard_buffer(buf)
    raw = buf.storage[buf.read_offset:buf.write_offset]
    if not raw:
        return Buffer(1, 0, 0, b"DefaultAllocator", b"")
    inflater = zlib.decompressobj()
    try:
        inflated = inflater.decompress(raw, max_size + 1)
    except zlib.error as error:
        raise DecodeError("invalid compressed clipboard buffer") from error
    if not inflater.eof or inflater.unused_data or len(inflated) > max_size:
        raise DecodeError("incomplete, oversized or trailing compressed clipboard buffer")
    return Buffer(buf.endian, 0, len(inflated), b"DefaultAllocator", inflated)


@dataclass(frozen=True, repr=False)
class FormatDataPacket(GetFormatDataPacket):
    data: Buffer

    def encode_body(self):
        return super().encode_body() + _deflate_buffer(self.data).encode()

    @classmethod
    def read_body(cls, r):
        return cls(*cls.read_prefix(r), r.byte_string(),
                   _inflate_buffer(Buffer.read(r), MAX_CLIPBOARD_BODY))


@dataclass(frozen=True, repr=False)
class ClipboardImage:
    """The inline Image in a format-data Buffer, after applying its offsets."""
    width: int
    height: int
    pixels: bytes

    def __post_init__(self):
        if not (0 <= self.width < 1 << 32 and 0 <= self.height < 1 << 32):
            raise DecodeError("image dimensions outside unsigned wire range")
        size = self.width * self.height * 4
        if size > MAX_RGBA_BYTES or size != len(self.pixels):
            raise DecodeError("invalid clipboard pixel byte count")

    @staticmethod
    def _layout(endian):
        if endian not in (1, 2):
            raise DecodeError("invalid clipboard Buffer endianness")
        return "<II" if endian == 1 else ">II"

    def encode(self, endian=2):
        return pack(self._layout(endian), self.width, self.height) + self.pixels

    @classmethod
    def decode(cls, data, endian=2):
        r = Reader(data)
        width, height = unpack(cls._layout(endian), r.take(8))
        size = width * height * 4
        if size > MAX_RGBA_BYTES:
            raise DecodeError("clipboard image exceeds local size limit")
        image = cls(width, height, r.take(size))
        r.finish()
        return image


@dataclass(frozen=True, repr=False)
class DirectoryEntry(SerializableV1):
    filesystem: int
    kind: int
    name: bytes
    attributes_or_mode: int
    creation_or_status_time: int
    access_time: int
    modification_time: int
    size: int

    max_payload_size = MAX_ENTRY_NAME + 64

    @classmethod
    def wire_name(cls):
        return b"Directory::Entry"

    def __post_init__(self):
        if self.filesystem not in (0, 1) or self.kind not in (0, 1, 2, 3):
            raise DecodeError("invalid directory entry filesystem or type")

    def encode_body(self):
        mode = self.attributes_or_mode.to_bytes(4, "big", signed=self.filesystem == 1)
        dates = pack(">qqq", self.creation_or_status_time, self.access_time, self.modification_time)
        return bytes((self.filesystem, self.kind)) + byte_string(self.name) + mode + dates + size_t(self.size)

    @classmethod
    def read_body(cls, r):
        filesystem, kind, name = r.uint(1), r.uint(1), _bounded_string(r, MAX_ENTRY_NAME)
        mode = int.from_bytes(r.take(4), "big", signed=filesystem == 1)
        return cls(filesystem, kind, name, mode, *unpack(">qqq", r.take(24)), r.size_t())


class _InlineRecord:
    @classmethod
    def decode(cls, data):
        if len(data) > MAX_CLIPBOARD_BODY:
            raise DecodeError("inline record exceeds local size limit")
        r = Reader(data)
        record = cls.read(r)
        r.finish()
        return record


@dataclass(frozen=True, repr=False)
class FileDescriptor(_InlineRecord):
    """Inline source path and its independently length-delimited directory entry."""
    path: bytes
    entry: DirectoryEntry

    def encode(self):
        return byte_string(self.path) + self.entry.encode()

    @classmethod
    def read(cls, r):
        return cls(_bounded_string(r, MAX_SOURCE_PATH), DirectoryEntry.read(r))


@dataclass(frozen=True, repr=False)
class GetFileDescriptorsPacket(_ClipboardOperation):
    top_level_only: bool

    def encode_body(self):
        return self.prefix() + bytes([_clipboard_bool(self.top_level_only)])

    @classmethod
    def read_body(cls, r):
        return cls(*cls.read_prefix(r), _clipboard_bool(r.uint(1)))


@dataclass(frozen=True, repr=False)
class GetFolderFileDescriptorsPacket(_ClipboardOperation):
    folder: bytes
    top_level_only: bool

    def encode_body(self):
        return self.prefix() + byte_string(self.folder) + bytes([_clipboard_bool(self.top_level_only)])

    @classmethod
    def read_body(cls, r):
        return cls(*cls.read_prefix(r), _bounded_string(r, MAX_SOURCE_PATH), _clipboard_bool(r.uint(1)))


@dataclass(frozen=True, repr=False)
class FileDescriptorsPacket(_ClipboardOperation):
    descriptors: Tuple[FileDescriptor, ...]
    sender_os: int

    def encode_body(self):
        return (self.prefix() + size_t(_count(len(self.descriptors), MAX_DESCRIPTORS))
                + b"".join(item.encode() for item in self.descriptors) + _unsigned(self.sender_os, 1))

    @classmethod
    def read_body(cls, r):
        prefix = cls.read_prefix(r)
        items = tuple(FileDescriptor.read(r) for _ in range(_count(r.size_t(), MAX_DESCRIPTORS)))
        return cls(*prefix, items, r.uint(1))


@dataclass(frozen=True, repr=False)
class GetFileDataPacket(_ClipboardOperation):
    descriptor: FileDescriptor
    offset: int
    length: int

    def __post_init__(self):
        if not 0 <= self.offset < 1 << 64 or not 0 <= self.length < 1 << 32:
            raise DecodeError("file range outside unsigned wire widths")
        if self.offset + self.length > 1 << 64:
            raise DecodeError("file range extends beyond 64-bit offsets")

    def encode_body(self):
        return self.prefix() + self.descriptor.encode() + pack(">QI", self.offset, self.length)

    @classmethod
    def read_body(cls, r):
        return cls(*cls.read_prefix(r), FileDescriptor.read(r), r.uint(8), r.uint(4))


@dataclass(frozen=True, repr=False)
class FileDataPacket(GetFileDataPacket):
    data: Buffer

    def __post_init__(self):
        super().__post_init__()
        if self.data.write_offset - self.data.read_offset > self.length:
            raise DecodeError("file response exceeds requested byte count")

    def encode_body(self):
        return super().encode_body() + _deflate_buffer(self.data).encode()

    @classmethod
    def read_body(cls, r):
        prefix = cls.read_prefix(r)
        descriptor, offset, length = FileDescriptor.read(r), r.uint(8), r.uint(4)
        if offset + length > 1 << 64:
            raise DecodeError("file range extends beyond 64-bit offsets")
        data = _inflate_buffer(Buffer.read(r), min(length, MAX_CLIPBOARD_BODY))
        return cls(*prefix, descriptor, offset, length, data)


@dataclass(frozen=True, repr=False)
class ExceptionLocation(_InlineRecord):
    file: bytes
    function: bytes
    line: int
    build_time: bytes

    def encode(self):
        return (byte_string(self.file) + byte_string(self.function)
                + _unsigned(self.line, 4) + byte_string(self.build_time))

    @classmethod
    def read(cls, r):
        return cls(r.byte_string(), r.byte_string(), r.uint(4), r.byte_string())


@dataclass(frozen=True, repr=False)
class WireException(_InlineRecord):
    code: int
    message: bytes
    locations: Tuple[ExceptionLocation, ...]

    def encode(self):
        return (pack(">i", self.code) + byte_string(self.message)
                + size_t(_count(len(self.locations), MAX_ERROR_LOCATIONS))
                + b"".join(item.encode() for item in self.locations))

    @classmethod
    def read(cls, r):
        code, message = unpack(">i", r.take(4))[0], r.byte_string()
        locations = tuple(ExceptionLocation.read(r) for _ in range(_count(r.size_t(), MAX_ERROR_LOCATIONS)))
        return cls(code, message, locations)


@dataclass(frozen=True, repr=False)
class ErrorPacket(_ClipboardOperation):
    error: WireException

    def encode_body(self):
        return self.prefix() + self.error.encode()

    @classmethod
    def read_body(cls, r):
        return cls(*cls.read_prefix(r), WireException.read(r))


@dataclass(frozen=True, repr=False)
class DeviceErrorPacket(Phase2Packet):
    device_id: int
    serial_number: int
    channel: int
    error: WireException

    def encode_body(self):
        return pack(">III", self.device_id, self.serial_number, self.channel) + self.error.encode()

    @classmethod
    def read_body(cls, r):
        return cls(r.uint(4), r.uint(4), r.uint(4), WireException.read(r))


@dataclass(frozen=True)
class IgnoredPacket:
    """Envelope for an optional capability whose body was skipped."""
    type_name: bytes
    version: int
    payload_size: int


_PHASE2_TYPES = (
    ClipboardUpdatePacket, GetFormatDataPacket, FormatDataPacket, GetFileDescriptorsPacket,
    GetFolderFileDescriptorsPacket, FileDescriptorsPacket, GetFileDataPacket, FileDataPacket,
    ErrorPacket, DeviceErrorPacket,
)
OPTIONAL_PACKETS = frozenset(cls.wire_name() for cls in _PHASE2_TYPES) | {b"KeyPacket"}


_PACKETS = {cls.__name__.encode(): cls for cls in (
    SettingsPacket, HeartbeatPacket, GlobalDataPacket, DeviceDataPacket, ClientHelloPacket,
    ServerHelloPacket, PromoteConnectionPacket, ClientDeviceConnectPacket, ServerDeviceConnectPacket,
    InitiateFlowPacket, SetCurrentHostPacket, SetOwnerPacket, *_PHASE2_TYPES)}


def _safe_text(value, limit=64):
    if isinstance(value, bytes):
        value = value[:limit * 4].decode(errors="replace")
    return "".join(ch for ch in value if ch.isprintable())[:limit]


def decode_packet(data: bytes):
    name = BinHeader.read(Reader(data)).type_name
    if name in _TYPES:
        return decode_discovery(data)
    if name not in _PACKETS:
        raise DecodeError("unsupported packet class")
    return _PACKETS[name].decode(data)


def decode_inner_packet(data: bytes, *, decode_optional=True):
    """Read a typed inner packet, or only its FARS envelope for disabled capabilities."""
    reader = Reader(data)
    header = BinHeader.read(reader)
    cls = _PACKETS.get(header.type_name)
    enabled = (decode_optional is True or
               isinstance(decode_optional, frozenset) and header.type_name in decode_optional)
    if cls is not None and (enabled or header.type_name not in OPTIONAL_PACKETS):
        return cls.decode(data)
    if header.type_name in OPTIONAL_PACKETS:
        reader.take(header.payload_size)
        reader.finish()
        return IgnoredPacket(header.type_name, header.version, header.payload_size)
    raise DecodeError("unsupported packet class")


def seal_packet(key, key_id, packet_bytes, session=None, compressed=False):
    outbound = SessionHeader(session.guid, session.outbound_seq) if session else None
    header = PlaintextHeader.fresh(outbound, compressed)
    frame = encrypt_frame(key, key_id, header.wrap(packet_bytes))
    if session is not None:
        session.next_outbound_header()
    return frame


def open_packet(key, key_id, frame, session=None, *, max_body=16 * 1024 * 1024):
    header, body = unwrap_plaintext(decrypt_frame(key, key_id, frame), max_body=max_body)
    if not 1 <= len(header.padding) <= 100:
        raise DecodeError("invalid padding length")
    if session is None:
        if header.session is not None:
            raise DecodeError("unexpected session header")
    else:
        session.verify_inbound_header(header.session)
    return body


MAX_BLOCK = 16 * 1024 * 1024 + 1024
HANDSHAKE_MAX_BLOCK = 16 * 1024
BASE_INFLIGHT_BYTES = 32 * 1024 * 1024
MAX_INFLIGHT_BYTES = 96 * 1024 * 1024
CHUNK_TIMEOUT = 15.0


class ByteBudget:
    """Reservations belong to the daemon event loop."""
    def __init__(self, limit=MAX_INFLIGHT_BYTES):
        self.limit = limit
        self.used = 0

    def reserve(self, amount):
        if self.used + amount > self.limit:
            raise DecodeError("receive budget exhausted")
        self.used += amount

    def release(self, amount):
        self.used -= amount


def _block_length(header, max_block=MAX_BLOCK):
    length = int.from_bytes(header[32:36], "big")
    if not 36 < length <= max_block:
        raise DecodeError("invalid TCP frame size")
    return length


async def read_frame(reader, *, max_block=MAX_BLOCK, expected_key_id=None, budget=None):
    header = await reader.readexactly(36)
    if expected_key_id is not None and header[:32] != expected_key_id:
        raise DecodeError("unexpected TCP key ID")
    length = _block_length(header, max_block)
    if budget is not None:
        budget.reserve(length)
    try:
        return header + await reader.readexactly(length)
    finally:
        if budget is not None:
            budget.release(length)


class FrameStreamBuffer:
    def __init__(self):
        self.pending = bytearray()

    def feed(self, data):
        self.pending.extend(data)
        frames = []
        offset = 0
        while len(self.pending) - offset >= 36:
            end = offset + 36 + _block_length(self.pending[offset:offset+36])
            if end > len(self.pending):
                break
            frames.append(bytes(self.pending[offset:end]))
            offset = end
        del self.pending[:offset]
        return frames


def _buffer(data):
    return Buffer(2, 0, len(data), b"DefaultAllocator", data)


def wrap_device_packet(device_id, serial_number, channel, inner_packet_bytes, device_key, device_key_id):
    frame = seal_packet(device_key, device_key_id, inner_packet_bytes)
    return DeviceDataPacket(device_id, serial_number, channel, 1, 1, _buffer(frame))


def wrap_global_packet(host_id, inner_packet_bytes):
    return GlobalDataPacket(host_id, 1, 1, _buffer(inner_packet_bytes))


DEFAULT_GLOBAL_CHUNK = 2_096_843
TRANSFER_TIMEOUT = 300.0


def wrap_global_packets(host_id, payload, chunk_size=DEFAULT_GLOBAL_CHUNK):
    if not 0 < len(payload) <= MAX_CLIPBOARD_BODY or not 0 < chunk_size <= MAX_BLOCK:
        raise DecodeError("invalid global packet size")
    count = (len(payload) + chunk_size - 1) // chunk_size
    if count > 4096:
        raise DecodeError("too many global chunks")
    return tuple(GlobalDataPacket(host_id, number, count, _buffer(payload[start:start+chunk_size]))
                 for number, start in enumerate(range(0, len(payload), chunk_size), 1))


class ChunkAssembler:
    """One transfer per stream. Chunk numbers are 1-based (1..chunk_count)."""

    def __init__(self, budget=None, *, limit=MAX_BLOCK + 36, lifetime=CHUNK_TIMEOUT):
        self.budget = budget
        self.limit = limit
        self.lifetime = lifetime
        self.activity = None
        self.started = None
        self.identity = None
        self.parts = {}
        self.size = 0

    def reset(self):
        if self.budget is not None:
            self.budget.release(self.size)
        self.parts.clear()
        self.size = 0
        self.identity = self.started = None

    def check_deadline(self):
        now = time.monotonic()
        if self.started is not None and (now - self.started >= self.lifetime or
                                         now - self.activity >= CHUNK_TIMEOUT):
            self.reset()
            raise DecodeError("chunk transfer timed out")

    def add(self, packet):
        self.check_deadline()
        try:
            return self._add(packet)
        except BaseException:
            self.reset()
            raise

    def _add(self, packet):
        if isinstance(packet, DeviceDataPacket):
            identity = (packet.device_id, packet.serial_number, packet.channel)
        else:
            identity = (packet.host_id,)
        identity += (packet.chunk_count,)
        if self.identity is not None and self.identity != identity:
            raise DecodeError("interleaved chunk identity")
        count, number = packet.chunk_count, packet.chunk_number
        if not 1 <= number <= count <= 4096 or number in self.parts:
            raise DecodeError("invalid or duplicate chunk")
        buf = packet.buffer
        if buf.endian not in (1, 2) or buf.allocator_name not in (b"DefaultAllocator", b"SecureAllocator"):
            raise DecodeError("unexpected chunk buffer format")
        data = buf.storage[buf.read_offset:buf.write_offset]
        if self.size + len(data) > self.limit:
            raise DecodeError("oversized chunk transfer")
        if self.budget is not None:
            self.budget.reserve(len(data))
        self.size += len(data)
        self.activity = time.monotonic()
        if self.started is None:
            self.started = self.activity
        self.identity = identity
        self.parts[number] = data
        if len(self.parts) == count:
            data = b"".join(self.parts[i] for i in range(1, count + 1))
            self.reset()
            return data
        return None


def _join_chunks(packets, cls):
    if isinstance(packets, cls):
        packets = (packets,)
    assembler = ChunkAssembler(limit=MAX_CLIPBOARD_BODY if cls is GlobalDataPacket else MAX_BLOCK + 36)
    complete = None
    for packet in packets:
        if complete is not None or not isinstance(packet, cls):
            raise DecodeError("unexpected chunk")
        complete = assembler.add(packet)
    if complete is None:
        raise DecodeError("incomplete chunks")
    return complete


def unwrap_device_packet(device_data_packet, device_key, device_key_id):
    return open_packet(device_key, device_key_id, _join_chunks(device_data_packet, DeviceDataPacket))


def unwrap_global_packet(global_data_packet):
    return _join_chunks(global_data_packet, GlobalDataPacket)
