from dataclasses import replace
import hashlib
import struct
import unittest
from unittest.mock import patch
import zlib

from cryptography.exceptions import InvalidTag

from fars import (BinHeader, Buffer, DecodeError, PlaintextHeader, Reader,
                  SessionHeader, byte_string, size_t, unwrap_plaintext)
import marconi_packets as packets
from marconi_crypto import (DHEKeyExchange, DHEParams, X25519Params, X25519AsymmetricKey,
                            decrypt_frame, derive_device_key, encrypt_frame, from_secret_and_salt)
from marconi_packets import (BeaconPacket, DeviceDataPacket, GlobalDataPacket,
                             HeartbeatPacket, InitiateDiscoveryPacket, PingPacket,
                             SettingsPacket, decode_discovery, encode_discovery)


class FarsTests(unittest.TestCase):
    def test_size_t_wire_vectors(self):
        for value, encoded in [
            (0, "01"), (1, "03"), (127, "ff"), (128, "0202"),
            (16383, "feff"), (16384, "040002"),
            ((1 << 56) - 1, "80ffffffffffffff"),
            (1 << 56, "000100000000000000"),
            ((1 << 64) - 1, "00ffffffffffffffff"),
        ]:
            with self.subTest(value=value):
                wire = bytes.fromhex(encoded)
                self.assertEqual(size_t(value), wire)
                self.assertEqual(Reader(wire).size_t(), value)
                for end in range(len(wire)):
                    with self.assertRaises(DecodeError):
                        Reader(wire[:end]).size_t()

    def test_size_t_every_width_and_limits(self):
        for width in range(1, 9):
            for value in (1 << (7 * (width - 1)), (1 << (7 * width)) - 1):
                wire = size_t(value)
                self.assertEqual(len(wire), width)
                self.assertEqual(Reader(wire).size_t(), value)
        for value in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                size_t(value)
        self.assertEqual(Reader(bytes.fromhex("0200")).size_t(), 0)

    def test_strings_are_arbitrary_octets(self):
        self.assertEqual(byte_string(b"a\0\xff"), b"\x07a\0\xff")
        reader = Reader(b"\x01\x07a\0\xff")
        self.assertEqual(reader.byte_string(), b"")
        self.assertEqual(reader.byte_string(), b"a\0\xff")
        reader.finish()
        with self.assertRaises(DecodeError):
            Reader(b"\xffhi").byte_string()

    def test_buffer_preserves_offsets_and_entire_storage(self):
        value = Buffer(2, 1, 3, b"Example", b"ABCD")
        wire = b"\x02\x09\x03\x07\x0fExampleABCD"
        self.assertEqual(value.encode(), wire)
        self.assertEqual(Buffer.read(Reader(wire)), value)
        self.assertEqual(Buffer(2, 0, 0, b"", b"").encode(), b"\x02\x01\x01\x01\x01")
        for broken in (wire[:-1], wire[:2] + b"\x09" + wire[3:],
                       wire[:3] + b"\x0b" + wire[4:]):
            with self.assertRaises(DecodeError):
                Buffer.read(Reader(broken))

    def test_bin_header_layout_and_truncation(self):
        wire = b"FARS\x03x\x12\x34\x02\x02"
        header = BinHeader(b"x", 0x1234, 128)
        self.assertEqual(header.encode(), wire)
        self.assertEqual(BinHeader.read(Reader(wire)), header)
        for broken in [wire[:i] for i in range(len(wire))] + [b"SRAF" + wire[4:]]:
            with self.assertRaises(DecodeError):
                BinHeader.read(Reader(broken))

    def test_session_wire_and_padding_limits(self):
        session = SessionHeader(bytes(range(16)), 0x0102030405060708)
        wire = bytes(range(16)) + bytes(range(1, 9))
        self.assertEqual(session.encode(), wire)
        self.assertEqual(SessionHeader.read(Reader(wire)), session)
        for count in (1, 100):
            header = PlaintextHeader(b"x" * count, session)
            self.assertEqual(header.encode(), bytes([count, 1]) + b"x" * count + wire)
            self.assertEqual(unwrap_plaintext(header.wrap(b"body")), (header, b"body"))
        for count in (0, 101):
            with self.assertRaises(ValueError):
                PlaintextHeader(b"x" * count).encode()
        for broken in (b"", b"\x05\x00abc", b"\x01\x01x" + wire[:-1], b"\x01\x04x"):
            with self.assertRaises(DecodeError):
                unwrap_plaintext(broken)

    def test_compressed_body_is_bounded_and_consumed_exactly(self):
        body = b"example" * 2048
        header = PlaintextHeader(b"r", None, True)
        wire = header.wrap(body)
        self.assertEqual(wire[:3], b"\x01\x02r")
        self.assertEqual(zlib.decompress(wire[3:]), body)
        self.assertEqual(unwrap_plaintext(wire, max_body=len(body)), (header, body))
        for broken in (wire[:-1], wire + b"extra", wire + wire[3:], wire[:3] + b"bad"):
            with self.assertRaises(DecodeError):
                unwrap_plaintext(broken)
        with self.assertRaises(DecodeError):
            unwrap_plaintext(wire, max_body=len(body) - 1)


class DiscoveryTests(unittest.TestCase):
    def test_discovery_class_version_and_body_vectors(self):
        identity = bytes.fromhex("000000010000000200000000")
        cases = [
            (InitiateDiscoveryPacket(1, 2, 0, True),
             b"FARS\x2fInitiateDiscoveryPacket\x00\x01\x1b", b"\x01"),
            (BeaconPacket(1, 2, 0, b"A", False, 8080),
             b"FARS\x19BeaconPacket\x00\x02\x23", b"\x03A\x00\x1f\x90"),
            (PingPacket(1, 2, 0, b"A", True, 8080),
             b"FARS\x15PingPacket\x00\x02\x23", b"\x03A\x01\x1f\x90"),
        ]
        for packet, header, tail in cases:
            with self.subTest(packet=packet):
                wire = header + identity + tail
                self.assertEqual(encode_discovery(packet), wire)
                self.assertEqual(decode_discovery(wire), packet)
                for broken in (wire[:-1], wire + b"tail", wire.replace(b"Packet", b"Other!"),
                               header[:-3] + b"\xff\xff" + wire[len(header)-1:]):
                    with self.assertRaises(DecodeError):
                        decode_discovery(broken)

    def test_gcm_discovery_round_trip(self):
        key, key_id = bytes(range(32)), bytes(range(32, 64))
        for packet in (InitiateDiscoveryPacket(1, 2, 0, False),
                       BeaconPacket(1, 2, 1, b"beacon", True, 1234),
                       PingPacket(1, 2, 2, b"ping", False, 4321)):
            header = PlaintextHeader.fresh()
            plaintext = header.wrap(encode_discovery(packet))
            frame = encrypt_frame(key, key_id, plaintext)
            parsed_header, data = unwrap_plaintext(decrypt_frame(key, key_id, frame))
            self.assertEqual(parsed_header, header)
            self.assertEqual(decode_discovery(data), packet)


class FrameTests(unittest.TestCase):
    def test_aes256_gcm_known_answer_with_fixed_outer_bytes(self):
        key_id = b"t" * 32
        # AES-256-GCM with zero key, 96-bit zero nonce and one zero block.
        wire = (key_id + bytes.fromhex("00000034000c000000100010") + bytes(12)
                + bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"
                                "d0d1c8a799996bf0265b98b5d48ab919"))
        self.assertEqual(decrypt_frame(bytes(32), key_id, wire), bytes(16))
        with patch("marconi_crypto.secrets.token_bytes", return_value=bytes(12)) as nonce:
            self.assertEqual(encrypt_frame(bytes(32), key_id, bytes(16)), wire)
            nonce.assert_called_once_with(12)

    def test_tampering_and_lengths(self):
        key, key_id = bytes(32), b"t" * 32
        frame = encrypt_frame(key, key_id, b"test")
        for pos in (0, 35, 37, 41, 43, 44, 56, len(frame) - 1):
            broken = bytearray(frame)
            broken[pos] ^= 1
            with self.assertRaises((DecodeError, InvalidTag)):
                decrypt_frame(key, key_id, bytes(broken))
        for broken in (frame[:43], frame[:-1], frame + b"\x00"):
            with self.assertRaises(DecodeError):
                decrypt_frame(key, key_id, broken)
        with self.assertRaises(InvalidTag):
            decrypt_frame(bytes(range(32)), key_id, frame)


class TunnelDataTests(unittest.TestCase):
    def test_heartbeat_signed_fields(self):
        wire = b"FARS\x1fHeartbeatPacket\x00\x01\x21" + bytes.fromhex(
            "ffffffffffffffff 7fffffffffffffff")
        packet = HeartbeatPacket(-1, (1 << 63) - 1)
        self.assertEqual(packet.encode(), wire)
        self.assertEqual(HeartbeatPacket.decode(wire), packet)

    def test_data_packets_consume_one_complete_buffer(self):
        backing = Buffer(2, 1, 3, b"", b"abcd")
        tail = bytes.fromhex("01 03 02 09 03 07 01") + b"abcd"
        for packet, body in (
            (GlobalDataPacket(b"H", 0, 1, backing), b"\x03H" + tail),
            (DeviceDataPacket(1, 2, 0, 0, 1, backing), bytes.fromhex(
                "00000001 00000002 00000000") + tail),
        ):
            name = type(packet).__name__.encode()
            wire = BinHeader(name, 1, len(body)).encode() + body
            self.assertEqual(packet.encode(), wire)
            self.assertEqual(type(packet).decode(wire), packet)
            for broken in (wire[:-1], wire + b"x"):
                with self.assertRaises(DecodeError):
                    type(packet).decode(broken)


class SettingsTests(unittest.TestCase):
    def test_three_peer_records_and_exact_end(self):
        body = (bytes.fromhex("00000001 00000002 00000000 00000005")
                + b"\x03H" + bytes((1, 0, 1, 0, 1, 0))
                + bytes.fromhex("00000011 00000022")
                + bytes.fromhex("00000000 ffffffff") + b"\x01\x01"
                + bytes.fromhex("00000001 00000002") + b"\x03B\x00"
                + bytes.fromhex("00000002 00000001") + b"\x03C\x01")
        header = BinHeader(b"SettingsPacket", 1, len(body))
        packet = SettingsPacket.decode(header.encode() + body)
        self.assertEqual((packet.device_id, packet.serial_number, packet.channel), (1, 2, 0))
        self.assertEqual(packet.encode(), header.encode() + body)
        s = packet.settings
        self.assertEqual((s.counter, s.layout, s.keyboard_id, s.keyboard_serial_number),
                         (5, b"H", 17, 34))
        self.assertEqual((s.on, s.ctrl_key, s.copy_paste, s.drag_drop, s.hot_corners,
                          s.keyboard_link), (True, False, True, False, True, False))
        self.assertEqual([(p.channel, p.keyboard_channel, p.host_id, p.enabled) for p in s.peers],
                         [(0, 0xffffffff, b"", True), (1, 2, b"B", False), (2, 1, b"C", True)])
        for broken in (body[:-1], body + b"tail"):
            with self.assertRaises(DecodeError):
                SettingsPacket.decode(BinHeader(b"SettingsPacket", 1, len(broken)).encode() + broken)


class KeyTests(unittest.TestCase):
    def test_kdf_multiblock_and_count(self):
        for name, digest in [("SHA2-256", hashlib.sha256), ("SHA2-512", hashlib.sha512)]:
            first = digest(digest(b"secretsalt").digest()).digest()
            second = digest(digest(first + b"secretsalt").digest()).digest()
            result = from_secret_and_salt(b"secret", b"salt", len(first) + 3, name, 2)
            self.assertTrue(result == first + second[:3])
        for args in [(1, "unknown", 1), (32, "SHA2-256", 0), (-1, "SHA2-512", 1)]:
            with self.assertRaises(ValueError):
                from_secret_and_salt(b"s", None, *args)

    def test_device_key_wire_input(self):
        # Independent fixed headers for a 64-byte identifier and a two-byte password.
        identifier = bytes(range(32)).hex()
        for password, pw_header in [("", b"\x01\x01\x01"), ("é", b"\x05\x01\x05")]:
            key_id, key = derive_device_key(0x020123, 7, identifier, password)
            self.assertTrue(key_id == hashlib.sha256(b"Master device key for: 131363:7.").digest())
            wire = (bytes.fromhex("0002012300000007 01 81 01 81 21") + b"DefaultAllocator"
                    + identifier.encode() + b"\x01" + pw_header + b"\x21DefaultAllocator"
                    + password.encode())
            self.assertTrue(key == hashlib.sha256(wire).digest())
        for invalid in ["", identifier.upper(), "g" * 64]:
            with self.assertRaises(ValueError):
                derive_device_key(1, 2, invalid)

    def test_nested_dhe_objects_and_public_key_size(self):
        a = DHEKeyExchange()
        p = a.params.public_key
        self.assertEqual(len(p.encode()), 94)
        self.assertTrue(p.encode().endswith(b"\x01\x01\x00" + p.key))
        for obj in [X25519Params(bytes(32), b"name", b"description"), p,
                    replace(a.params, salt=b"s", signature=b"sig", key_description=b"d")]:
            self.assertEqual(type(obj).decode(obj.encode()), obj)
            for bad in (obj.encode()[:-1], obj.encode() + b"x"):
                with self.assertRaises(DecodeError):
                    type(obj).decode(bad)

    def test_bilateral_exchange_and_salt_order(self):
        for salt in (b"", b"salt"):
            a = DHEKeyExchange(salt=salt)
            b = DHEKeyExchange(DHEParams.decode(a.params.encode()))
            with patch("marconi_crypto.from_secret_and_salt", wraps=from_secret_and_salt) as kdf:
                client = a.derive_session_key(b.params)
                server = b.derive_session_key(a.params)
                self.assertTrue(client == server)
                self.assertEqual(len(client), 32)
                expected = byte_string(salt) + a.params.public_key.encode() + b.params.public_key.encode()
                self.assertEqual(len(expected), 189 + len(salt))
                self.assertTrue(all(call.args[1] == expected for call in kdf.call_args_list))
            for bad in (replace(b.params, key_id=bytes(32)), replace(b.params, count=1000000),
                        replace(b.params, public_key=replace(b.params.public_key, is_private=True))):
                with self.assertRaises(DecodeError):
                    a.derive_session_key(bad)


class PeerPacketTests(unittest.TestCase):
    def test_all_packet_bodies(self):
        params = DHEKeyExchange().params
        session = packets.Session(bytes(range(16)), 4, 6)
        identity = struct.pack(">III", 1, 2, 0)
        cases = [
            (packets.ClientHelloPacket(b"A", b"C", params), b"\x03A\x03C" + params.encode()),
            (packets.ServerHelloPacket(b"A", session, b"C", params), b"\x03A" + session.guid
             + struct.pack(">QQ", 4, 6) + b"\x03C" + params.encode()),
            (packets.PromoteConnectionPacket(b"H"), b"\x03H"),
            (packets.ClientDeviceConnectPacket(1, 2, 0, b"H"), identity + b"\x03H"),
            (packets.ServerDeviceConnectPacket(1, 2, 0, b"H"), identity + b"\x03H"),
            (packets.SetCurrentHostPacket(2), bytes.fromhex("00000002")),
            (packets.SetOwnerPacket(b"A", 1, b"B", 0), b"\x03A\x01\x03B\x00"),
        ]
        for edge in packets.Edge:
            cases.append((packets.InitiateFlowPacket(edge, 0.5), struct.pack(">If", int(edge), 0.5)))
        for packet, body in cases:
            wire = BinHeader(type(packet).__name__.encode(), 1, len(body)).encode() + body
            self.assertEqual(packet.encode(), wire)
            self.assertEqual(packets.decode_packet(wire), packet)
            for bad in (wire[:-1], wire + b"tail"):
                with self.assertRaises(DecodeError):
                    packets.decode_packet(bad)

    def test_session_auth_sequence_and_phase(self):
        session = packets.Session(bytes(16), 17, 42)
        other = session.inverted()
        self.assertEqual((other.inbound_seq, other.outbound_seq), (42, 17))
        key, kid = bytes(32), b"i" * 32
        frame = packets.seal_packet(key, kid, b"body", session, compressed=True)
        self.assertEqual(session.outbound_seq, 43)
        for bad in (packets.Session(bytes(16), 41, 17), packets.Session(b"g" * 16, 42, 17), None):
            with self.assertRaises(DecodeError):
                packets.open_packet(key, kid, frame, bad)
        self.assertEqual(packets.open_packet(key, kid, frame, other), b"body")
        self.assertEqual(other.inbound_seq, 43)
        for bad in (frame, packets.seal_packet(key, kid, b"body")):
            with self.assertRaises(DecodeError):
                packets.open_packet(key, kid, bad, other)
        self.assertEqual(other.inbound_seq, 43)

    def test_device_and_global_chunk_reassembly(self):
        key, kid = bytes(32), b"i" * 32
        flow = packets.InitiateFlowPacket(packets.Edge.RIGHT, 0.5).encode()
        owner = packets.SetOwnerPacket(b"A", 1, b"B", 0).encode()
        cases = [
            (packets.wrap_device_packet(1, 2, 1, flow, key, kid), flow,
             lambda parts: packets.unwrap_device_packet(parts, key, kid)),
            (packets.wrap_global_packet(b"A", owner), owner, packets.unwrap_global_packet),
        ]
        for packet, expected, unwrap in cases:
            self.assertEqual((packet.chunk_number, packet.chunk_count), (1, 1))
            self.assertEqual(unwrap(packets.decode_packet(packet.encode())), expected)
            raw = packet.buffer.storage
            chunks = []
            for i, section in enumerate((raw[:7], raw[7:]), start=1):
                backing = Buffer(2, 1, len(section) + 1, b"DefaultAllocator", b"p" + section + b"extra")
                chunks.append(replace(packet, chunk_number=i, chunk_count=2, buffer=backing))
            self.assertEqual(unwrap(reversed(chunks)), expected)
            for bad in ([chunks[0]], [chunks[0], chunks[0]], [replace(packet, chunk_number=0)],
                        [replace(packet, chunk_number=2)], [replace(packet, chunk_count=5000)]):
                with self.assertRaises(DecodeError):
                    unwrap(bad)

    def test_stream_fragmentation_coalescing_and_bounds(self):
        wire = packets.seal_packet(bytes(32), bytes(32), b"payload")
        for cut in range(len(wire)):
            stream = packets.FrameStreamBuffer()
            self.assertEqual(stream.feed(wire[:cut]), [])
            self.assertEqual(stream.feed(wire[cut:] + wire), [wire, wire])
        for length in (0, 36, packets.MAX_BLOCK + 1):
            with self.assertRaises(DecodeError):
                packets.FrameStreamBuffer().feed(bytes(32) + struct.pack(">I", length))


class ReceiveLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_headers_are_checked_before_body_reads(self):
        from unittest.mock import AsyncMock
        kid = b"k" * 32
        for key, length in ((kid, packets.HANDSHAKE_MAX_BLOCK + 1), (bytes(32), 96)):
            reader = AsyncMock()
            reader.readexactly.return_value = key + struct.pack(">I", length)
            with self.assertRaises(DecodeError):
                await packets.read_frame(reader, max_block=packets.HANDSHAKE_MAX_BLOCK,
                                         expected_key_id=kid)
            reader.readexactly.assert_awaited_once_with(36)

    async def test_cancelled_body_and_chunks_share_one_budget(self):
        import asyncio
        budget = packets.ByteBudget(100)
        reader = asyncio.StreamReader()
        reader.feed_data(bytes(32) + struct.pack(">I", 80))
        task = asyncio.create_task(packets.read_frame(reader, budget=budget))
        await asyncio.sleep(0)
        self.assertEqual(budget.used, 80)
        assembler = packets.ChunkAssembler(budget)
        piece = replace(packets.wrap_global_packet(b"peer", bytes(15)), chunk_count=2)
        self.assertIsNone(assembler.add(piece))
        with self.assertRaises(DecodeError):
            assembler.add(replace(piece, chunk_number=2))
        self.assertEqual(budget.used, 80)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(budget.used, 0)

    def test_transfer_deadline_does_not_slide_and_releases_bytes(self):
        from unittest.mock import patch
        budget = packets.ByteBudget(10)
        assembler = packets.ChunkAssembler(budget)
        piece = replace(packets.wrap_global_packet(b"peer", b"x"), chunk_count=3)
        for on_receive in (True, False):
            with patch.object(packets, "time") as clock:
                clock.monotonic.return_value = 2
                assembler.add(piece)
                clock.monotonic.return_value += packets.CHUNK_TIMEOUT - 1
                assembler.add(replace(piece, chunk_number=2))
                clock.monotonic.return_value += 1
                with self.assertRaisesRegex(DecodeError, "timed out"):
                    if on_receive:
                        assembler.add(replace(piece, chunk_number=3))
                    else:
                        assembler.check_deadline()
                self.assertEqual(budget.used, 0)
                self.assertFalse(assembler.parts)

    def test_unknown_class_has_fixed_diagnostic(self):
        for decode in (packets.decode_packet, packets.decode_inner_packet):
            with self.assertRaisesRegex(DecodeError, "^unsupported packet class$"):
                decode(BinHeader(b"private-class-name", 1, 0).encode())


class ClipboardProtocolTests(unittest.TestCase):
    def test_descriptor_decode_byte_limits(self):
        path = b"x" * packets.MAX_SOURCE_PATH
        name = b"y" * packets.MAX_ENTRY_NAME
        entry = packets.DirectoryEntry(1, 1, name, 0, 0, 0, 0, 0)
        valid = packets.FileDescriptor(path, entry)
        self.assertEqual(packets.FileDescriptor.decode(valid.encode()), valid)
        for bad in (replace(valid, path=path+b"x"), replace(valid, entry=replace(entry, name=name+b"y"))):
            with self.assertRaises(DecodeError):
                packets.FileDescriptor.decode(bad.encode())

    # All single-octet lengths and all field bytes here are independent of the codecs.
    # An Entry has a FARS header. Its containing FileDescriptor has none.
    entry_body = bytes.fromhex(
        "01 01 03 61 000001a4 ffffffffffffffff 0000000000000002 0000000000000003 03")
    entry_wire = b"FARS\x21Directory::Entry\x00\x01\x43" + entry_body
    descriptor_wire = b"\x05/a" + entry_wire
    prefix = b"\x03h\x03p\x03q"
    compressed_x = zlib.compress(b"x", 9)
    buffer_wire = (bytes((2,)) + size_t(len(compressed_x)) + b"\x01" + size_t(len(compressed_x))
                   + byte_string(b"DefaultAllocator") + compressed_x)
    range_wire = bytes.fromhex("0000000100000001 01020304")
    exception_wire = bytes.fromhex("fffffffb 03 6d 03 03 66 03 67 00000007 03 74")

    def setUp(self):
        self.entry = packets.DirectoryEntry(1, 1, b"a", 0o644, -1, 2, 3, 1)
        self.descriptor = packets.FileDescriptor(b"/a", self.entry)
        self.buf = Buffer(2, 0, 1, b"DefaultAllocator", b"x")
        self.exc = packets.WireException(-5, b"m", (packets.ExceptionLocation(b"f", b"g", 7, b"t"),))
        prefix = b"h", b"p", b"q"
        file_args = (*prefix, self.descriptor, 0x100000001, 0x01020304)
        self.cases = [
            (packets.ClipboardUpdatePacket(b"h", b"p", (b"a", b"bc")), b"\x03h\x03p\x05\x03a\x05bc"),
            (packets.GetFormatDataPacket(*prefix, b"m"), self.prefix + b"\x03m"),
            (packets.FormatDataPacket(*prefix, b"m", self.buf), self.prefix + b"\x03m" + self.buffer_wire),
            (packets.GetFileDescriptorsPacket(*prefix, True), self.prefix + b"\x01"),
            (packets.GetFolderFileDescriptorsPacket(*prefix, b"/d", False), self.prefix + b"\x05/d\x00"),
            (packets.FileDescriptorsPacket(*prefix, (self.descriptor,), 3),
             self.prefix + b"\x03" + self.descriptor_wire + b"\x03"),
            (packets.GetFileDataPacket(*file_args), self.prefix + self.descriptor_wire + self.range_wire),
            (packets.FileDataPacket(*file_args, self.buf),
             self.prefix + self.descriptor_wire + self.range_wire + self.buffer_wire),
            (packets.ErrorPacket(*prefix, self.exc), self.prefix + self.exception_wire),
            (packets.DeviceErrorPacket(1, 0x23456789, 2, self.exc),
             bytes.fromhex("00000001 23456789 00000002") + self.exception_wire),
        ]

    @staticmethod
    def object_bytes(name, body, version=1):
        # The test objects here have both counts below 128.
        return (b"FARS" + bytes([2 * len(name) + 1]) + name + version.to_bytes(2, "big")
                + bytes([2 * len(body) + 1]) + body)

    def test_packet_vectors_and_dispatch(self):
        for packet, body in self.cases:
            with self.subTest(packet=type(packet).__name__):
                wire = self.object_bytes(type(packet).__name__.encode(), body)
                self.assertEqual(packet.encode(), wire)
                self.assertEqual(type(packet).decode(wire), packet)
                self.assertEqual(packets.decode_packet(wire), packet)
                self.assertEqual(packets.decode_inner_packet(wire), packet)
                self.assertIsInstance(packets.decode_inner_packet(wire, decode_optional=False),
                                      packets.IgnoredPacket)

    def test_every_body_boundary_and_version(self):
        for packet, body in self.cases:
            name = type(packet).__name__.encode()
            for n in range(len(body)):
                with self.subTest(name=name, body_end=n), self.assertRaises(DecodeError):
                    packets.decode_inner_packet(self.object_bytes(name, body[:n]))
            for wire in (self.object_bytes(name, body, 2), self.object_bytes(name, body + b"x"),
                         self.object_bytes(name, body) + b"x", self.object_bytes(name, body)[:-1]):
                with self.subTest(name=name), self.assertRaises(DecodeError):
                    packets.decode_inner_packet(wire)

    def test_nested_vectors_and_windows_attributes(self):
        self.assertEqual(self.entry.encode(), self.entry_wire)
        self.assertEqual(packets.DirectoryEntry.decode(self.entry_wire), self.entry)
        self.assertEqual(self.descriptor.encode(), self.descriptor_wire)
        self.assertEqual(packets.FileDescriptor.decode(self.descriptor_wire), self.descriptor)
        with self.assertRaises(DecodeError):
            packets.FileDescriptor.decode(self.descriptor_wire + b"x")
        self.assertEqual(self.exc.encode(), self.exception_wire)
        self.assertEqual(self.exc.locations[0].encode(), self.exception_wire[7:])
        for value in (self.exc, self.exc.locations[0]):
            self.assertEqual(type(value).decode(value.encode()), value)
            with self.assertRaises(DecodeError):
                type(value).decode(value.encode() + b"x")
        attrs = replace(self.entry, filesystem=0, kind=2, attributes_or_mode=0x80000010, size=2**40)
        self.assertEqual(packets.DirectoryEntry.decode(attrs.encode()), attrs)
        for change in (dict(filesystem=2), dict(kind=4)):
            with self.assertRaises(DecodeError):
                replace(self.entry, **change)

    def test_counts_boolean_and_nested_header_rejection(self):
        bad = [
            (b"ClipboardUpdatePacket", b"\x03h\x03p" + size_t(packets.MAX_FORMATS + 1)),
            (b"FileDescriptorsPacket", self.prefix + size_t(packets.MAX_DESCRIPTORS + 1)),
            (b"ErrorPacket", self.prefix + bytes.fromhex("ffffffff 01") + size_t(packets.MAX_ERROR_LOCATIONS + 1)),
            (b"GetFileDescriptorsPacket", self.prefix + b"\x02"),
            (b"GetFolderFileDescriptorsPacket", self.prefix + b"\x01\xff"),
            (b"GetFileDataPacket", self.prefix + self.descriptor_wire.replace(b"Directory::Entry", b"Directory::Other") + self.range_wire),
            (b"GetFileDataPacket", self.prefix + b"\x05/a" + self.object_bytes(b"Directory::Entry", self.entry_body, 2) + self.range_wire),
        ]
        for body in (b"\x02" + self.entry_body[1:], b"\x01\xff" + self.entry_body[2:], self.entry_body + b"x"):
            bad.append((b"FileDescriptorsPacket", self.prefix + b"\x03\x05/a"
                        + self.object_bytes(b"Directory::Entry", body) + b"\x03"))
        for name, body in bad:
            with self.subTest(name=name), self.assertRaises(DecodeError):
                packets.decode_inner_packet(self.object_bytes(name, body))

    def test_vector_limits_before_element_reads(self):
        for name, prefix, limit in (
                (b"ClipboardUpdatePacket", b"\x01\x01", packets.MAX_FORMATS),
                (b"FileDescriptorsPacket", self.prefix, packets.MAX_DESCRIPTORS),
                (b"ErrorPacket", self.prefix + bytes.fromhex("00000000 01"), packets.MAX_ERROR_LOCATIONS)):
            wire = self.object_bytes(name, prefix + size_t(limit + 1))
            with self.subTest(name=name), self.assertRaisesRegex(DecodeError, "local item limit"):
                packets.decode_inner_packet(wire)
        formats = (b"",) * packets.MAX_FORMATS
        update = packets.ClipboardUpdatePacket(b"h", b"p", formats)
        self.assertEqual(packets.decode_inner_packet(update.encode()), update)

    def test_byte_ranges_and_buffer_bounds(self):
        packet = packets.GetFileDataPacket(b"h", b"p", b"q", self.descriptor, 0, 0)
        for change in (dict(offset=-1), dict(offset=2**64), dict(length=-1), dict(length=2**32)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(packet, **change).encode()
        overflow = self.prefix + self.descriptor_wire + bytes.fromhex("ffffffffffffffff 00000002")
        with self.assertRaises(DecodeError):
            packets.decode_inner_packet(self.object_bytes(b"GetFileDataPacket", overflow))
        too_long = self.prefix + self.descriptor_wire + bytes(12) + self.buffer_wire
        with self.assertRaises(DecodeError):
            packets.decode_inner_packet(self.object_bytes(b"FileDataPacket", too_long))
        extreme = replace(packet, offset=2**64-1, length=0)
        self.assertEqual(packets.decode_inner_packet(extreme.encode()), extreme)
        for buf in ("00 01 01 01 01", "02 03 05 03 01 00", "02 05 01 05 01 00"):
            with self.subTest(buf=buf), self.assertRaises(DecodeError):
                packets.decode_inner_packet(self.object_bytes(b"FormatDataPacket", self.prefix + b"\x03m" + bytes.fromhex(buf)))
        header = BinHeader(b"FormatDataPacket", 1, packets.MAX_CLIPBOARD_BODY + 1)
        with self.assertRaisesRegex(DecodeError, "local size limit"):
            packets.decode_inner_packet(header.encode())

    def test_buffer_deflate_inflate_wire_semantics_and_zip_bombs(self):
        # Independent RFC 1950 stored-block zlib stream for b"x", inside a Buffer with offsets.
        stored_x = bytes.fromhex("78 01 01 01 00 fe ff 78 00 79 00 79")
        padded_wire = Buffer(1, 1, 1 + len(stored_x), b"DefaultAllocator", b"\xee" + stored_x + b"\xff").encode()
        fmt_wire = BinHeader(b"FormatDataPacket", 1, len(self.prefix + b"\x03m" + padded_wire)).encode() + self.prefix + b"\x03m" + padded_wire
        decoded = packets.decode_inner_packet(fmt_wire)
        self.assertEqual(decoded.data, Buffer(1, 0, 1, b"DefaultAllocator", b"x"))

        # Empty readable span matches Buffer::Deflate/Inflate bypass (endian=1, empty storage).
        empty = packets.FormatDataPacket(b"h", b"p", b"q", b"text/plain", Buffer(2, 1, 1, b"", b"ab"))
        empty_wire = BinHeader(b"FormatDataPacket", 1, len(self.prefix + byte_string(b"text/plain") + Buffer(1, 0, 0, b"DefaultAllocator", b"").encode())).encode()
        empty_wire += self.prefix + byte_string(b"text/plain") + Buffer(1, 0, 0, b"DefaultAllocator", b"").encode()
        self.assertEqual(empty.encode(), empty_wire)
        self.assertEqual(packets.decode_inner_packet(empty.encode()).data, Buffer(1, 0, 0, b"DefaultAllocator", b""))

        # Incompressible FileDataPacket where compressed wire bytes exceed request.length still succeeds.
        raw_small = b"0123456789"
        self.assertGreater(len(zlib.compress(raw_small, 9)), len(raw_small))
        small_file = packets.FileDataPacket(b"h", b"p", b"q", self.descriptor, 0, len(raw_small),
                                            Buffer(2, 0, len(raw_small), b"DefaultAllocator", raw_small))
        self.assertEqual(packets.decode_inner_packet(small_file.encode()), small_file)

        # Uncompressed raw bytes, trailing garbage, and zip bombs are rejected.
        raw_buf = Buffer(2, 0, 5, b"DefaultAllocator", b"hello").encode()
        trailing_buf = Buffer(2, 0, len(stored_x) + 1, b"DefaultAllocator", stored_x + b"\x00").encode()
        for bad_buf in (raw_buf, trailing_buf):
            body = self.prefix + b"\x03m" + bad_buf
            with self.assertRaises(DecodeError):
                packets.decode_inner_packet(BinHeader(b"FormatDataPacket", 1, len(body)).encode() + body)

        bomb = zlib.compress(bytes(1 << 20), 9)
        bomb_buf = Buffer(2, 0, len(bomb), b"DefaultAllocator", bomb).encode()
        file_bomb_body = self.prefix + self.descriptor_wire + struct.pack(">QI", 0, 10) + bomb_buf
        with self.assertRaises(DecodeError):
            packets.decode_inner_packet(BinHeader(b"FileDataPacket", 1, len(file_bomb_body)).encode() + file_bomb_body)

        huge_bomb = zlib.compress(bytes(packets.MAX_CLIPBOARD_BODY + 1024), 9)
        huge_buf = Buffer(2, 0, len(huge_bomb), b"DefaultAllocator", huge_bomb).encode()
        fmt_bomb_body = self.prefix + b"\x03m" + huge_buf
        with self.assertRaises(DecodeError):
            packets.decode_inner_packet(BinHeader(b"FormatDataPacket", 1, len(fmt_bomb_body)).encode() + fmt_bomb_body)

        # Cooperative chunked deflate matches one-shot zlib level 9 and honours ENCODE_STOP.
        import threading
        multi_chunk = (b"abcd1234" * 70000)  # > 256 KiB chunk threshold
        stop = threading.Event()
        token = packets.ENCODE_STOP.set(stop)
        try:
            chunked = packets._deflate_buffer(Buffer(2, 0, len(multi_chunk), b"DefaultAllocator", multi_chunk))
            self.assertEqual(chunked.storage, zlib.compress(multi_chunk, 9))
            stop.set()
            with self.assertRaises(packets.EncodeCancelled):
                packets._deflate_buffer(Buffer(2, 0, len(multi_chunk), b"DefaultAllocator", multi_chunk))
        finally:
            packets.ENCODE_STOP.reset(token)

    def test_inline_image_dimensions_and_pixels(self):
        pixels = bytes.fromhex("12 34 56 ff 78 9a bc 80")
        image = packets.ClipboardImage(2, 1, pixels)
        for endian, dims in ((1, "02000000 01000000"), (2, "00000002 00000001")):
            wire = bytes.fromhex(dims) + pixels
            self.assertEqual(image.encode(endian), wire)
            self.assertEqual(packets.ClipboardImage.decode(wire, endian), image)
        for bad in (wire[:-1], wire + b"x", bytes.fromhex("ffffffff ffffffff")):
            with self.assertRaises(DecodeError):
                packets.ClipboardImage.decode(bad)


class ClipboardChunkTests(unittest.TestCase):
    def test_wire_chunk_size_and_sequences(self):
        payload = b"x"*(packets.DEFAULT_GLOBAL_CHUNK*2+9)
        chunks = packets.wrap_global_packets(b"host", payload)
        self.assertEqual([c.chunk_number for c in chunks], [1,2,3])
        self.assertEqual([len(c.buffer.storage) for c in chunks], [2096843,2096843,9])
        self.assertEqual(packets.unwrap_global_packet(chunks), payload)
        self.assertEqual(packets.HANDSHAKE_MAX_BLOCK, 16384)

    def test_activity_and_absolute_deadlines(self):
        from unittest.mock import patch
        pieces = packets.wrap_global_packets(b"h", bytes(50), chunk_size=1)
        for schedule in ([0,14,30], list(range(0,302,14)) + [301]):
            budget = packets.ByteBudget(1024)
            assembler = packets.ChunkAssembler(budget, lifetime=300)
            with patch.object(packets, "time") as clock, self.assertRaises(DecodeError):
                for piece, stamp in zip(pieces, schedule):
                    clock.monotonic.return_value = stamp
                    assembler.add(piece)
            self.assertEqual(budget.used, 0)


if __name__ == "__main__":
    unittest.main()
