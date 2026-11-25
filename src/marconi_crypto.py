"""Marconi device and tunnel keys, exchange parameters and AES-GCM frames."""
from dataclasses import dataclass, field, replace
import hashlib
import re
import secrets
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fars import Buffer, DecodeError, SerializableV1, byte_string, size_t


_HEADER = struct.Struct(">32sIHIH")
_IV_SIZE = 12
_TAG_SIZE = 16


def _cipher(key: bytes, key_id: bytes) -> AESGCM:
    if len(key_id) != 32 or len(key) != 32:
        raise ValueError("key ID and AES-256 key must each have 32 bytes")
    return AESGCM(key)


def encrypt_frame(key: bytes, key_id: bytes, plaintext: bytes) -> bytes:
    cipher = _cipher(key, key_id)
    if not plaintext:
        raise ValueError("empty packet plaintext")
    iv = secrets.token_bytes(_IV_SIZE)
    sealed = cipher.encrypt(iv, plaintext, None)
    block_size = 8 + _IV_SIZE + len(sealed)
    header = _HEADER.pack(key_id, block_size, _IV_SIZE, len(plaintext), _TAG_SIZE)
    return header + iv + sealed


def decrypt_frame(key: bytes, key_id: bytes, frame: bytes) -> bytes:
    cipher = _cipher(key, key_id)
    if len(frame) < _HEADER.size:
        raise DecodeError("truncated frame header")
    received_id, block_size, iv_size, body_size, tag_size = _HEADER.unpack_from(frame)
    if received_id != key_id:
        raise DecodeError("unexpected frame key ID")
    if (iv_size, tag_size) != (_IV_SIZE, _TAG_SIZE) or body_size == 0:
        raise DecodeError("invalid AES-GCM field lengths")
    if block_size != len(frame) - 36 or block_size != 8 + iv_size + body_size + tag_size:
        raise DecodeError("inconsistent frame lengths")
    offset = _HEADER.size + iv_size
    return cipher.decrypt(frame[_HEADER.size:offset], frame[offset:], None)


def from_secret_and_salt(secret: bytes, salt: bytes | None, key_length: int,
                         hash_name: str, count: int) -> bytes:
    digests = {"SHA2-256": hashlib.sha256, "SHA2-512": hashlib.sha512}
    if hash_name not in digests or key_length < 0 or count < 1:
        raise ValueError("invalid key derivation parameters")
    digest = digests[hash_name]
    result = bytearray()
    block = b""
    while len(result) < key_length:
        block = digest(block + secret + (salt or b"")).digest()
        for _ in range(1, count):
            block = digest(block).digest()
        result.extend(block)
    return bytes(result[:key_length])


def derive_device_key(device_id: int, serial_number: int, random_hex: str,
                      password: str = "") -> tuple[bytes, bytes]:
    if not isinstance(random_hex, str) or not re.fullmatch("[0-9a-f]{64}", random_hex):
        raise ValueError("expected a 32-byte lowercase hex device identifier")
    label = f"Master device key for: {device_id}:{serial_number}.".encode("ascii")
    secret = struct.pack(">II", device_id, serial_number)
    for raw in (random_hex.encode("ascii"), password.encode("utf-8")):
        # Device::Device allocates SecureBuffer with SecureAllocator, but the
        # agent binary never registers SecureAllocator in Allocator::GetMap(),
        # so Allocator::GetSerializedName() falls back to "DefaultAllocator".
        secret += Buffer(1, 0, len(raw), b"DefaultAllocator", raw).encode()
    return hashlib.sha256(label).digest(), from_secret_and_salt(secret, None, 32, "SHA2-256", 1)


def _fixed32(value):
    if len(value) != 32:
        raise ValueError("expected a 32-byte field")
    return value


@dataclass(frozen=True)
class X25519Params(SerializableV1):
    id: bytes
    name: bytes = b""
    description: bytes = b""

    def encode_body(self):
        return _fixed32(self.id) + byte_string(self.name) + byte_string(self.description)

    @classmethod
    def read_body(cls, r):
        return cls(r.take(32), r.byte_string(), r.byte_string())


@dataclass(frozen=True)
class X25519AsymmetricKey(X25519Params):
    is_private: bool = False
    key: bytes = field(default=b"", repr=False)

    def encode_body(self):
        return super().encode_body() + bytes([self.is_private]) + _fixed32(self.key)

    @classmethod
    def read_body(cls, r):
        return cls(r.take(32), r.byte_string(), r.byte_string(), r.uint(1) == 1, r.take(32))


@dataclass(frozen=True)
class DHEParams(SerializableV1):
    id: bytes
    params: X25519Params
    key_id: bytes
    public_key: X25519AsymmetricKey
    salt: bytes = b""
    key_length: int = 32
    message_digest_name: bytes = b"SHA2-512"
    count: int = 1
    key_name: bytes = b""
    key_description: bytes = b""
    signature: bytes = b""
    signature_key_id: bytes = bytes(32)
    signature_md_name: bytes = b""

    @classmethod
    def wire_name(cls):
        return b"DHEKeyExchange::DHEParams"

    def encode_body(self):
        return (_fixed32(self.id) + byte_string(self.signature) + _fixed32(self.signature_key_id)
                + byte_string(self.signature_md_name) + self.params.encode() + byte_string(self.salt)
                + size_t(self.key_length) + byte_string(self.message_digest_name) + size_t(self.count)
                + _fixed32(self.key_id) + byte_string(self.key_name) + byte_string(self.key_description)
                + self.public_key.encode())

    @classmethod
    def read_body(cls, r):
        ident, sig, sig_id, sig_md = r.take(32), r.byte_string(), r.take(32), r.byte_string()
        params, salt = X25519Params.read(r), r.byte_string()
        length, md, count = r.size_t(), r.byte_string(), r.size_t()
        key_id, name, description = r.take(32), r.byte_string(), r.byte_string()
        return cls(ident, params, key_id, X25519AsymmetricKey.read(r), salt, length, md,
                   count, name, description, sig, sig_id, sig_md)


class DHEKeyExchange:
    """One ephemeral exchange. Pass the initiator's offer to create a responder."""

    def __init__(self, offer: DHEParams | None = None, *, salt: bytes = b""):
        self._private = X25519PrivateKey.generate()
        raw = self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        public = X25519AsymmetricKey(secrets.token_bytes(32), key=raw)
        self._offer = offer
        if offer is None:
            self.params = DHEParams(secrets.token_bytes(32), X25519Params(secrets.token_bytes(32)),
                                    secrets.token_bytes(32), public, salt)
        else:
            self._validate(offer)
            self.params = replace(offer, public_key=public)

    @staticmethod
    def _validate(p):
        # Options+ leaves signature and signature_md_name empty on unsigned
        # X25519 offers, while signature_key_id is default-constructed by ID().
        if (p.public_key.is_private or p.signature or p.signature_md_name or
                (p.key_length, p.message_digest_name, p.count) != (32, b"SHA2-512", 1)):
            raise DecodeError("unsupported DHE parameters")

    def derive_session_key(self, peer: DHEParams) -> bytes:
        self._validate(peer)
        if replace(peer, public_key=self.params.public_key) != self.params:
            raise DecodeError("DHE negotiation mismatch")
        if self._offer is not None and peer != self._offer:
            raise DecodeError("DHE initiator changed")
        a, b = (self.params, peer) if self._offer is None else (peer, self.params)
        salt = byte_string(a.salt) + a.public_key.encode() + b.public_key.encode()
        secret = self._private.exchange(X25519PublicKey.from_public_bytes(peer.public_key.key))
        return from_secret_and_salt(secret, salt, 32, "SHA2-512", 1)
