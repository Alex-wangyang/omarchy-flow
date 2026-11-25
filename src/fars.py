"""Offline codecs for the network-endian thekogans binary serializer."""
from dataclasses import dataclass, field
import secrets
from typing import Optional
import zlib


class DecodeError(ValueError):
    """The input cannot be decoded as the expected object."""


def size_t(value: int) -> bytes:
    if not 0 <= value < 1 << 64:
        raise ValueError("SizeT is an unsigned 64-bit integer")
    width = max(1, (value.bit_length() + 6) // 7)
    if width > 8:
        return b"\0" + value.to_bytes(8, "big")
    tagged = ((value << 1) | 1) << (width - 1)
    return tagged.to_bytes(width, "little")


def byte_string(value: bytes) -> bytes:
    return size_t(len(value)) + value


class Reader:
    """Cursor over a single in-memory input. Check lengths before slicing."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def take(self, count: int) -> bytes:
        end = self._pos + count
        if count < 0 or end > len(self._data):
            raise DecodeError("field exceeds available bytes")
        data = self._data[self._pos:end]
        self._pos = end
        return data

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def size_t(self) -> int:
        first = self.uint(1)
        if first == 0:
            return self.uint(8)
        width = (first & -first).bit_length()
        packed = first | (int.from_bytes(self.take(width - 1), "little") << 8)
        return packed >> width

    def byte_string(self) -> bytes:
        return self.take(self.size_t())

    def rest(self) -> bytes:
        return self.take(len(self._data) - self._pos)

    def finish(self) -> None:
        if self._pos != len(self._data):
            raise DecodeError("unexpected trailing bytes")


@dataclass(frozen=True)
class Buffer:
    endian: int
    read_offset: int
    write_offset: int
    allocator_name: bytes
    storage: bytes = field(repr=False)

    def __post_init__(self):
        if not 0 <= self.read_offset <= self.write_offset <= len(self.storage):
            raise DecodeError("invalid buffer offsets")

    def encode(self) -> bytes:
        return (bytes([self.endian]) + size_t(len(self.storage))
                + size_t(self.read_offset) + size_t(self.write_offset)
                + byte_string(self.allocator_name) + self.storage)

    @classmethod
    def read(cls, reader: Reader) -> "Buffer":
        endian = reader.uint(1)
        capacity = reader.size_t()
        read_offset = reader.size_t()
        write_offset = reader.size_t()
        allocator = reader.byte_string()
        return cls(endian, read_offset, write_offset, allocator, reader.take(capacity))


@dataclass(frozen=True)
class BinHeader:
    type_name: bytes
    version: int
    payload_size: int

    def encode(self) -> bytes:
        return (b"FARS" + byte_string(self.type_name)
                + self.version.to_bytes(2, "big") + size_t(self.payload_size))

    @classmethod
    def read(cls, reader: Reader) -> "BinHeader":
        if reader.take(4) != b"FARS":
            raise DecodeError("invalid FARS magic")
        return cls(reader.byte_string(), reader.uint(2), reader.size_t())


@dataclass(frozen=True)
class SessionHeader:
    guid: bytes
    sequence: int

    def encode(self) -> bytes:
        if len(self.guid) != 16:
            raise ValueError("session GUID must have 16 bytes")
        return self.guid + self.sequence.to_bytes(8, "big")

    @classmethod
    def read(cls, reader: Reader) -> "SessionHeader":
        return cls(reader.take(16), reader.uint(8))


@dataclass(frozen=True)
class PlaintextHeader:
    padding: bytes
    session: Optional[SessionHeader] = None
    compressed: bool = False

    @classmethod
    def fresh(cls, session: Optional[SessionHeader] = None, compressed: bool = False):
        return cls(secrets.token_bytes(1 + secrets.randbelow(100)), session, compressed)

    def encode(self) -> bytes:
        if not 1 <= len(self.padding) <= 100:
            raise ValueError("writer padding length must be in 1..100")
        flags = int(self.session is not None) | (int(self.compressed) << 1)
        session = self.session.encode() if self.session is not None else b""
        return bytes([len(self.padding), flags]) + self.padding + session

    @classmethod
    def read(cls, reader: Reader) -> "PlaintextHeader":
        count, flags = reader.take(2)
        if flags & ~3:
            raise DecodeError("unknown plaintext flags")
        padding = reader.take(count)
        session = SessionHeader.read(reader) if flags & 1 else None
        return cls(padding, session, bool(flags & 2))

    def wrap(self, fars_object: bytes) -> bytes:
        body = zlib.compress(fars_object, 9) if self.compressed else fars_object
        return self.encode() + body


def unwrap_plaintext(data: bytes, *, max_body: int = 16 * 1024 * 1024):
    """Return the header and FARS bytes, bounding decompression output."""
    if max_body < 0:
        raise ValueError("negative body limit")
    reader = Reader(data)
    header = PlaintextHeader.read(reader)
    body = reader.rest()
    if header.compressed:
        inflater = zlib.decompressobj()
        try:
            body = inflater.decompress(body, max_body + 1)
        except zlib.error as error:
            raise DecodeError("invalid zlib stream") from error
        if not inflater.eof or inflater.unused_data:
            raise DecodeError("incomplete, oversized or trailing compressed data")
    if len(body) > max_body:
        raise DecodeError("body exceeds size limit")
    return header, body


class SerializableV1:
    """A length-delimited FARS object, usable standalone or inside another."""

    max_payload_size = None

    @classmethod
    def wire_name(cls):
        return cls.__name__.encode("ascii")

    def encode(self):
        payload = self.encode_body()
        if self.max_payload_size is not None and len(payload) > self.max_payload_size:
            raise ValueError("FARS object exceeds local size limit")
        return BinHeader(self.wire_name(), 1, len(payload)).encode() + payload

    @classmethod
    def read(cls, reader):
        header = BinHeader.read(reader)
        if (header.type_name, header.version) != (cls.wire_name(), 1):
            raise DecodeError("unexpected FARS class or version")
        if cls.max_payload_size is not None and header.payload_size > cls.max_payload_size:
            raise DecodeError("FARS object exceeds local size limit")
        body = Reader(reader.take(header.payload_size))
        value = cls.read_body(body)
        body.finish()
        return value

    @classmethod
    def decode(cls, data):
        reader = Reader(data)
        value = cls.read(reader)
        reader.finish()
        return value
