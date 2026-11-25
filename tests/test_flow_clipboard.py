import asyncio
from dataclasses import replace
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
import zlib

import flow_clipboard as cb
import flow_transfer as ft
import marconi_packets as p


def png(w, h, color, scanlines, *, extra=(), interlace=0):
    header = struct.pack(">2I5B", w, h, 8, color, 0, 0, interlace)
    return (cb.PNG + cb.chunk(b"IHDR", header) + b"".join(cb.chunk(*c) for c in extra)
            + cb.chunk(b"IDAT", zlib.compress(scanlines)) + cb.chunk(b"IEND", b""))


class Images(unittest.TestCase):
    def test_rgba_roundtrip_and_dimensions(self):
        pixels = bytes(range(24))
        self.assertEqual(cb.png_to_marconi_image(cb.marconi_image_to_png(2, 3, pixels)), (2, 3, pixels))
        for w, h, data in ((0, 1, b""), (1, 0, b""), (16385, 1, b""), (16384, 16384, b""), (1, 1, b"")):
            with self.assertRaises(ft.TransferError):
                cb.marconi_image_to_png(w, h, data)

    def test_color_types_and_transparency(self):
        for color, samples, extra, rgba in (
            (0, b"\x01\x7f", [(b"tRNS", b"\x00\x01")], bytes([1,1,1,0,127,127,127,255])),
            (2, bytes(range(6)), [(b"tRNS", bytes([0,0,0,1,0,2]))], bytes([0,1,2,0,3,4,5,255])),
            (3, b"\x01\x00", [(b"PLTE", bytes(range(6))), (b"tRNS", b"\x12")],
             bytes([3,4,5,255,0,1,2,18])),
            (4, bytes(range(4)), [], bytes([0,0,0,1,2,2,2,3])),
            (6, bytes(range(8)), [], bytes(range(8))),
        ):
            with self.subTest(color=color):
                self.assertEqual(cb.png_to_marconi_image(png(2, 1, color, b"\0"+samples, extra=extra)),
                                 (2, 1, rgba))

    def test_all_five_filters(self):
        # Two RGB pixels per row. Nonzero previous rows exercise all three Paeth candidates.
        rows = [bytes([12, 24, 90, 30, 22, 86]), bytes([15, 13, 11, 7, 44, 67]),
                bytes([4, 43, 69, 35, 18, 8]), bytes([21, 12, 51, 3, 17, 43]),
                bytes([98, 44, 9, 23, 76, 13])]
        raw = b""
        prev = bytes(6)
        for filt, row in enumerate(rows):
            result = bytearray([filt])
            for i, sample in enumerate(row):
                a, b, c = row[i-3] if i >= 3 else 0, prev[i], prev[i-3] if i >= 3 else 0
                closest = min((a,b,c), key=lambda n: abs(a+b-c-n))
                result.append((sample - (0,a,b,(a+b)//2,closest)[filt]) % 256)
            raw += result
            prev = row
        rgba = b"".join(r[i:i+3]+b"\xff" for r in rows for i in (0,3))
        self.assertEqual(cb.png_to_marconi_image(png(2, 5, 2, raw)), (2, 5, rgba))

    def test_reject_corrupt_truncated_and_bombs(self):
        valid = png(1, 1, 6, bytes(5))
        for bad in (valid[:-1], valid + b"x", valid[:-5] + b"xxxxx", png(999999, 1, 0, b""),
                    png(1, 1, 6, bytes(5), interlace=1), png(1, 1, 3, b"\0\0"),
                    png(1, 1, 3, b"\0\x01", extra=[(b"PLTE", bytes(3))]),
                    png(1, 1, 6, bytes(1 << 20)), png(1, 1, 6, bytes(4)),
                    png(1, 1, 6, b"\x05" + bytes(4)), png(0, 1, 6, b"")):
            with self.assertRaises(ft.TransferError):
                cb.png_to_marconi_image(bad)


def descriptor(name=b"item", size=1, kind=1, path=b"/remote/item"):
    return p.FileDescriptor(path, p.DirectoryEntry(1, kind, name, 0o600, 0, 0, 0, size))


class TransferTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.cache = self.base / "cache"
        self.guid = b"a"*32

    async def receive(self, rows, more=None):
        async def request(cls, response, *args):
            if cls is p.GetFileDescriptorsPacket:
                return response(b"h", self.guid, b"id", rows, 3)
            if more:
                return more(cls, response, *args)
            self.fail("unexpected file request")
        self.publish = AsyncMock()
        return await ft.receive_files(self.cache, self.guid, request, self.publish)

    async def test_reject_names_and_links_and_duplicate_entries(self):
        for raw in (b"../evil", b"/etc/passwd", b"a/b", b"a\\b", b"n\0ul", b".", b"..",
                    b"", b"x"*256, b"\xff", b"a\x1b"):
            with self.subTest(name=repr(raw)), self.assertRaises(ft.TransferError):
                await self.receive((descriptor(raw),))
            self.publish.assert_not_awaited()
            self.assertEqual(list(self.cache.glob("*/*")), [])
        for kind in (0, 3):
            with self.assertRaises(ft.TransferError):
                await self.receive((descriptor(kind=kind),))
        with self.assertRaises(ft.TransferError):
            await self.receive((descriptor(size=0),)*2)
        self.publish.assert_not_awaited()
        self.assertFalse(any(self.cache.glob("*/*")))

    async def test_limits_and_wrong_file_response(self):
        with self.assertRaises(ft.TransferError):
            await self.receive((descriptor(size=ft.MAX_FILE+1),))
        with self.assertRaises(ft.TransferError):
            await self.receive((descriptor(size=0),)*(ft.MAX_ENTRIES+1))
        def nested(cls, response, *args):
            return response(b"h", self.guid, b"id", (descriptor(kind=2),), 3)
        with self.assertRaises(ft.TransferError):
            await self.receive((descriptor(kind=2),), nested)
        def wrong(cls, response, desc, offset, length):
            return response(b"h", self.guid, b"id", desc, offset+1, length, p._buffer(b"x"))
        with self.assertRaises(ft.TransferError):
            await self.receive((descriptor(),), wrong)
        self.publish.assert_not_awaited()
        self.assertFalse(any(self.cache.glob("*/*")))

    async def test_total_limit_aborts_after_previous_file(self):
        def provide(cls, response, desc, offset, length):
            return response(b"h", self.guid, b"id", desc, offset, length, p._buffer(b"x"))
        with patch.object(ft, "MAX_TOTAL", 1), self.assertRaises(ft.TransferError):
            await self.receive((descriptor(b"one"), descriptor(b"two")), provide)
        self.publish.assert_not_awaited()
        self.assertFalse(any(self.cache.glob("*/*")))

    def test_outbound_range_clamps_and_rejects_eof(self):
        path = self.base/"selected"
        path.write_bytes(b"0123456789")
        roots = (ft.OfferedRoot.capture(path),)
        req = p.GetFileDataPacket(b"h", self.guid, b"id", roots[0].entries[path].descriptor, 1, 99)
        with patch.object(ft, "MAX_RANGE", 4):
            self.assertEqual(ft.file_range(roots, req), b"1234")
        for offset, count in ((10, 1), (0, 0)):
            with self.assertRaises(ft.TransferError):
                ft.file_range(roots, replace(req, offset=offset, length=count))

    def test_single_link_and_exact_file_version_rechecked_on_each_range(self):
        source = self.base/"selected"
        source.write_bytes(b"abc")
        roots = (ft.OfferedRoot.capture(source),)
        desc = roots[0].entries[source].descriptor
        read = p.GetFileDataPacket(b"h", self.guid, b"id", desc, 0, 1)
        os.link(source, self.base/"alias")
        with self.assertRaises(ft.TransferError):
            ft.file_range(roots, read)
        (self.base/"alias").unlink()
        before = source.stat()
        source.write_bytes(b"xyz")
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        with self.assertRaises(ft.TransferError):
            ft.file_range(roots, read)

    async def test_private_cache_rejects_symlinks_and_prunes(self):
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        self.cache.symlink_to(elsewhere)
        with self.assertRaises(ft.TransferError):
            await self.receive((descriptor(size=0),))
        self.assertFalse(any(elsewhere.iterdir()))
        self.cache.unlink()
        for n in range(7):
            self.guid = ("%032x" % n).encode()
            await self.receive((descriptor(size=0),))
            path, = self.publish.await_args.args[0]
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(list(self.cache.glob("*/*"))), 5)
        previous = path
        await self.receive((descriptor(size=0),))
        current, = self.publish.await_args.args[0]
        self.assertNotEqual(previous.parent, current.parent)
        self.assertTrue(current.is_file() and previous.is_file())
        self.assertEqual(len(list((self.cache/"completed").iterdir())), 5)

    async def test_outbound_root_identity_and_recursive_listing(self):
        offered = self.base / "offered"
        offered.mkdir()
        (offered / "dir").mkdir()
        (offered / "dir" / "file").write_bytes(b"x")
        (offered / "link").symlink_to(self.base)
        roots = (ft.OfferedRoot.capture(offered),)
        query = p.GetFileDescriptorsPacket(b"h", self.guid, b"id", False)
        self.assertEqual({d.entry.name for d in ft.descriptors(roots, query)},
                         {b"offered", b"offered/dir", b"offered/dir/file"})
        for bad in (self.base, offered/"link", offered/"dir"/".."):
            with self.assertRaises((ft.TransferError, OSError)):
                ft.descriptors(roots, p.GetFolderFileDescriptorsPacket(b"h", self.guid, b"id", bytes(bad), True))
        offered.rename(self.base / "old")
        offered.mkdir()
        self.assertEqual({d.entry.name for d in ft.descriptors(roots, query)},
                         {b"offered", b"offered/dir", b"offered/dir/file"})
        desc = roots[0].entries[offered/"dir"/"file"].descriptor
        with self.assertRaises(ft.TransferError):
            ft.file_range(roots, p.GetFileDataPacket(b"h", self.guid, b"id", desc, 0, 1))

    async def test_mime_negotiation_and_live_owner_suppression(self):
        path = self.base/"space here"
        path.touch()
        link = self.base/"link"
        link.symlink_to(path)
        self.assertEqual(cb.local_roots(("copy\n"+link.as_uri()).encode(), cb.FILES_MIME), ())
        content = ("copy\n"+path.as_uri()+"\nfile://elsewhere/nonlocal").encode()
        backend = cb.WaylandClipboard()
        with patch.object(cb, "output", AsyncMock(side_effect=[(cb.FILES_MIME+"\ntext/plain").encode(), content, b"text"])):
            first = await backend.snapshot_local()
        self.assertEqual(first.formats, (b"file", b"text/plain"))
        self.assertEqual(first.roots[0].path, path)
        self.assertRegex(first.provider_id, rb"^[0-9a-f]{32}$")
        backend.owner = type("Owner", (), {"returncode": None})()
        with patch.object(cb, "output", AsyncMock(side_effect=[b"text/uri-list", path.as_uri().encode()])):
            self.assertIsNone(await backend.snapshot_local())
        backend.owner.returncode = 0
        with patch.object(cb, "output", AsyncMock(side_effect=[b"UTF8_STRING\ntext/html\napplication/xml",
                                                               b"text", b"<html>", b"<x/>"])):
            self.assertEqual((await backend.snapshot_local()).formats, (b"text/plain", b"text/html", b"text/xml"))
        with patch.object(cb, "output", AsyncMock(side_effect=[b"image/jpeg", b"fixture",
                                      cb.marconi_image_to_png(1,1,bytes(4))])) as cmd:
            self.assertEqual((await backend.snapshot_local()).formats, (b"image",))
            self.assertEqual(cmd.await_args.args[0][0], "/usr/bin/magick")
            self.assertEqual(cmd.await_args.args[-1], b"fixture")

    async def test_bidi_controls_rejected_before_creation(self):
        for code in (*range(0x202a, 0x202f), *range(0x2066, 0x206a), 0x200e, 0x200f, 0x061c):
            with self.subTest(code=code), self.assertRaises(ft.TransferError):
                await self.receive((descriptor(("a" + chr(code) + "b").encode(), size=0),))
            self.publish.assert_not_awaited()

    async def test_nested_metadata_budget_releases_parent_packet(self):
        import weakref
        parents = []
        async def request(cls, reply, *args):
            if cls is p.GetFileDescriptorsPacket:
                packet = reply(b"h", self.guid, b"id", (descriptor(kind=2),), 3)
                parents.append(weakref.ref(packet))
                return packet
            self.assertIsNone(parents[0]())
            rows = tuple(descriptor(str(n).encode(), 0, path=b"x"*4096) for n in range(12))
            return reply(b"h", self.guid, b"id", rows, 3)

        publish = AsyncMock()
        with patch.object(ft, "MAX_TRAVERSAL_META_BYTES", 8192), self.assertRaises(ft.TransferError):
            await ft.receive_files(self.cache, self.guid, request, publish)
        publish.assert_not_awaited()
        self.assertFalse(list(self.cache.glob("*/*")))

    async def test_recovery_skips_live_staging_and_prunes_completed_bytes(self):
        waiting, resume = asyncio.Event(), asyncio.Event()
        async def blocked(cls, reply, *args):
            waiting.set()
            await resume.wait()
            return reply(b"h", self.guid, b"id", (descriptor(size=0),), 3)
        active = asyncio.create_task(ft.receive_files(self.cache, self.guid, blocked, AsyncMock()))
        try:
            await asyncio.wait_for(waiting.wait(), 2)
            staging = self.cache/"staging"
            live, = staging.iterdir()
            abandoned = staging/"abandoned"
            abandoned.mkdir(mode=0o700)
            (abandoned/"partial").touch()
            ft.recover_cache(self.cache)
            self.assertTrue(live.is_dir())
            self.assertFalse(abandoned.exists())
            def contents(cls, reply, desc, offset, length):
                return reply(b"h", self.guid, b"id", desc, offset, length, p._buffer(b"ab"))
            with patch.object(ft, "MAX_CACHE_BYTES", 3):
                await self.receive((descriptor(size=2),), contents)
                older, = self.publish.await_args.args[0]
                await self.receive((descriptor(size=2),), contents)
                newer, = self.publish.await_args.args[0]
                self.assertFalse(older.exists())
                self.assertEqual(newer.read_bytes(), b"ab")
                self.assertTrue(live.is_dir())
        finally:
            resume.set()
            await active

    def test_capture_rejects_hardlinks_and_enforces_shared_entry_limit(self):
        path = self.base/"selected"
        path.touch()
        os.link(path, self.base/"alias")
        with self.assertRaises(ft.TransferError):
            ft.OfferedRoot.capture(path)
        root = self.base/"dir"
        root.mkdir()
        os.link(path, root/"alias")
        self.assertEqual(set(ft.OfferedRoot.capture(root).entries), {root})
        (root/"new").touch()
        with patch.object(ft, "MAX_ENTRIES", 2), self.assertRaises(ft.TransferError):
            ft.OfferedRoot.capture(root)

    async def test_wayland_type_change_at_publication_aborts_before_spawn(self):
        backend = cb.WaylandClipboard()
        with patch.object(cb, "output", AsyncMock(side_effect=[
                b"text/plain", b"old", b"text/plain", b"old", b"image/png"])):
            await backend.snapshot_local()
            generation = backend.local_generation
            with patch.object(backend, "_install", AsyncMock()) as install, self.assertRaises(ft.TransferError):
                await backend.set_text(b"text/plain", b"remote", generation=generation)
            install.assert_not_awaited()
            self.assertGreater(backend.local_generation, generation)

    async def test_preexisting_unsupported_format_does_not_block_publication(self):
        backend = cb.WaylandClipboard()
        with patch.object(cb, "output", AsyncMock(side_effect=[
                b"application/x-custom", b"application/x-custom", b"application/x-custom"])):
            snap = await backend.snapshot_local()
            self.assertEqual(snap.formats, ())
            generation = backend.local_generation
            with patch.object(backend, "_install", AsyncMock()) as install:
                await backend.set_text(b"text/plain", b"from-mac", generation=generation)
            install.assert_awaited_once_with("text/plain;charset=utf-8", b"from-mac")

        # Switching to an unsupported format mid-transfer still aborts publication.
        backend2 = cb.WaylandClipboard()
        with patch.object(cb, "output", AsyncMock(side_effect=[
                b"text/plain", b"old", b"application/x-custom", b"application/x-custom"])):
            await backend2.snapshot_local()
            generation = backend2.local_generation
            with patch.object(backend2, "_install", AsyncMock()) as install, self.assertRaises(ft.TransferError):
                await backend2.set_text(b"text/plain", b"from-mac", generation=generation)
            install.assert_not_awaited()

    async def test_output_cap_and_timeout_reap_real_children(self):
        with self.assertRaises(ft.TransferError):
            await cb.output([sys.executable, "-c", "import os; os.write(1,bytes(1000000))"], 128, 2)
        with self.assertRaises(TimeoutError):
            await cb.output([sys.executable, "-c", "import time; time.sleep(5)"], 128, .05)

    async def test_foreground_copy_replacement_shutdown(self):
        spawn = asyncio.create_subprocess_exec
        children = []
        async def substitute(*argv, **kwargs):
            self.assertEqual(argv[:3], ("/usr/bin/wl-copy", "--foreground", "--type"))
            child = await spawn(sys.executable, "-c",
                                "import sys,time; sys.stdin.buffer.read(); time.sleep(5)", **kwargs)
            children.append(child)
            return child
        backend = cb.WaylandClipboard()
        png = cb.marconi_image_to_png(1, 1, bytes(4))
        with patch.object(asyncio, "create_subprocess_exec", substitute), patch.object(
                cb, "output", AsyncMock(side_effect=[b"synthetic", png])):
            try:
                await backend.set_text(b"text/plain", b"synthetic")
                self.assertIsNone(await backend.snapshot_local())
                await backend.set_image_png(png)
                self.assertIsNotNone(children[0].returncode)
            finally:
                await backend.close()
        self.assertTrue(all(c.returncode is not None for c in children))
