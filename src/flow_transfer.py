"""Private disk staging and capability-scoped local file access for Flow."""
import asyncio
from collections import deque
import fcntl
import hashlib
import os
import re
import secrets
import shutil
import stat
import struct
import sys
import unicodedata
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, replace
from types import MappingProxyType
from pathlib import Path

from marconi_packets import (MAX_ENTRY_NAME, MAX_SOURCE_PATH, DirectoryEntry, FileDescriptor, FileDataPacket, FileDescriptorsPacket,
                             GetFileDataPacket, GetFileDescriptorsPacket, GetFolderFileDescriptorsPacket)

LINUX_OS = 2
GUID = re.compile(rb"[0-9a-f]{32}")
MAX_DEPTH = 32
MAX_ENTRIES = 2048
MAX_FILE = 256 << 20
MAX_TOTAL = 512 << 20
MAX_TRAVERSAL_META_BYTES = 4 << 20
MAX_CACHE_BYTES = 512 << 20
MAX_COMPLETED = 5
MAX_RANGE = 8 << 20
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


BIDI = frozenset((*range(0x202a, 0x202f), *range(0x2066, 0x206a), 0x200e, 0x200f, 0x061c))


class TransferError(ValueError):
    def __init__(self):
        super().__init__("clipboard operation unavailable")


async def disk_io(fn, *args):
    # A cancelled coroutine must not release its descriptor/lease (or start
    # another manifest scan) while the worker still uses it.
    worker = asyncio.create_task(asyncio.to_thread(fn, *args))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
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


@contextmanager
def private_io():
    # Path-bearing OSErrors must not escape the clipboard API.
    try:
        yield
    except (OSError, UnicodeError, OverflowError):
        raise TransferError() from None


def basename(raw):
    try:
        name = raw.decode("utf-8")
    except UnicodeError:
        raise TransferError() from None
    if (not name or len(raw) > 255 or name in (".", "..") or "/" in name or "\\" in name
            or any(unicodedata.category(c) == "Cc" or ord(c) in BIDI for c in name)):
        raise TransferError()
    return name


@contextmanager
def opened(path, flags, *, parent=None, mode=0o600):
    fd = os.open(path, flags, mode, dir_fd=parent)
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def directory(path, create=False):
    """Pin every ancestor without following links, including the cache root."""
    if not path.is_absolute() or ".." in path.parts or path.anchor != "/":
        raise TransferError()
    fd = os.open("/", DIR)
    try:
        for name in path.parts[1:]:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(name, DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def version(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


def eligible(st):
    return stat.S_ISDIR(st.st_mode) or (stat.S_ISREG(st.st_mode) and st.st_nlink == 1)


@contextmanager
def pinned(parent, name):
    if hasattr(os, "O_PATH"):
        flags = os.O_PATH
    elif hasattr(os, "O_EVTONLY"):
        # Darwin's metadata descriptor can also be reopened through /dev/fd.
        if not eligible(os.stat(name, dir_fd=parent, follow_symlinks=False)):
            raise TransferError()
        flags = os.O_EVTONLY
    else:
        raise TransferError()
    with opened(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, parent=parent) as fd:
        yield fd


def pinned_path(fd):
    return f"/proc/self/fd/{fd}" if hasattr(os, "O_PATH") else f"/dev/fd/{fd}"


@dataclass(frozen=True, repr=False)
class ManifestEntry:
    identity: tuple
    descriptor: FileDescriptor

    @property
    def folder(self):
        return self.descriptor.entry.kind == 2


@dataclass
class CaptureBudget:
    entries: int = 0
    size: int = 0


@dataclass(frozen=True, repr=False)
class OfferedRoot:
    path: Path
    entries: MappingProxyType

    @property
    def identity(self):
        return self.entries[self.path].identity

    @classmethod
    @private_io()
    def capture(cls, path, budget=None):
        manifest = {}
        budget = budget if budget is not None else CaptureBudget()

        def capture_entry(parent, path, depth):
            budget.entries += 1
            if depth > MAX_DEPTH or budget.entries > MAX_ENTRIES or len(bytes(path)) > MAX_SOURCE_PATH:
                raise TransferError()
            name = os.fsencode(path.name)
            basename(name)
            # Skip unsupported children without opening them on platforms without O_PATH.
            if not eligible(os.stat(name, dir_fd=parent, follow_symlinks=False)):
                return
            with pinned(parent, name) as fd:
                st = os.fstat(fd)
                if not eligible(st):
                    return
                folder = stat.S_ISDIR(st.st_mode)
                size = 0 if folder else st.st_size
                budget.size += size
                if size > MAX_FILE or budget.size > MAX_TOTAL:
                    raise TransferError()
                entry = DirectoryEntry(1, 2 if folder else 1, name, st.st_mode & 0o777,
                                       int(st.st_ctime), int(st.st_atime), int(st.st_mtime), size)
                manifest[path] = ManifestEntry(version(st)[:2] if folder else version(st),
                                               FileDescriptor(bytes(path), entry))
                if folder:
                    with opened(".", DIR, parent=fd) as directory_fd, os.scandir(directory_fd) as it:
                        for child in it:
                            capture_entry(directory_fd, path / child.name, depth + 1)

        with directory(path.parent) as parent:
            capture_entry(parent, path, 1)
        if path not in manifest:
            raise TransferError()
        return cls(path, MappingProxyType(manifest))


def lookup(roots, raw):
    path = Path(os.fsdecode(raw))
    for root in roots:
        node = root.entries.get(path)
        if node and raw == node.descriptor.path:
            return root, path, node
    raise TransferError()


@private_io()
def descriptors(roots, request):
    entries = []
    if isinstance(request, GetFolderFileDescriptorsPacket):
        root, base, node = lookup(roots, request.folder)
        if not node.folder:
            raise TransferError()
        scopes = ((root, base),)
    else:
        scopes = ((root, root.path.parent) for root in roots)
    for root, base in scopes:
        for path, node in root.entries.items():
            if path == base or not path.is_relative_to(base):
                continue
            if request.top_level_only and path.parent != base:
                continue
            name = bytes(path.relative_to(base))
            if len(name) > MAX_ENTRY_NAME:
                raise TransferError()
            desc = node.descriptor
            entries.append(replace(desc, entry=replace(desc.entry, name=name)))
    return tuple(entries)


@private_io()
def file_range(roots, request):
    desc = request.descriptor
    root, path, node = lookup(roots, desc.path)
    # Recursive listings can prefix the basename with manifest ancestors.
    name = desc.entry.name
    relative = bytes(path.relative_to(root.path.parent))
    if (node.folder or not name or not (relative == name or relative.endswith(b"/" + name))
            or desc.entry != replace(node.descriptor.entry, name=name)
            or not 0 <= request.offset < node.identity[2] or request.length <= 0):
        raise TransferError()

    def verify(fd):
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or version(st) != node.identity:
            raise TransferError()

    with directory(root.path.parent) as parent:
        fd = os.dup(parent)
        try:
            ancestor = root.path.parent
            for part in path.relative_to(root.path.parent).parts[:-1]:
                child = os.open(part, DIR, dir_fd=fd)
                os.close(fd)
                fd = child
                ancestor = ancestor / part
                if version(os.fstat(fd))[:2] != root.entries[ancestor].identity:
                    raise TransferError()
            with pinned(fd, path.name) as pin:
                verify(pin)
                with opened(pinned_path(pin), os.O_RDONLY | os.O_NONBLOCK) as data_fd:
                    verify(data_fd)
                    length = min(request.length, MAX_RANGE, node.identity[2] - request.offset)
                    data = os.pread(data_fd, length, request.offset)
                    verify(data_fd)
                    if len(data) != length:
                        raise TransferError()
                    return data
        finally:
            os.close(fd)


def remove_tree(parent, name):
    # Python 3.10 has fd-safe rmtree on Linux but lacks its dir_fd keyword.
    if sys.version_info < (3, 11):
        shutil.rmtree(f"{pinned_path(parent)}/{name}")
    else:
        shutil.rmtree(name, dir_fd=parent)


def check_private(fd):
    st = os.fstat(fd)
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise TransferError()


def recover_staging(staging):
    # Creation and lease acquisition happen under the same directory lock.
    fcntl.flock(staging, fcntl.LOCK_EX)
    try:
        with os.scandir(staging) as it:
            for item in it:
                if not item.is_dir(follow_symlinks=False):
                    continue
                try:
                    with opened(item.name, DIR, parent=staging) as fd:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        remove_tree(staging, item.name)
                except (BlockingIOError, FileNotFoundError):
                    # An active job owns the lease or has just moved to completed.
                    continue
    finally:
        fcntl.flock(staging, fcntl.LOCK_UN)


def recover_cache(cache):
    if not cache.exists():
        return
    with private_io(), directory(cache) as root:
        check_private(root)
        try:
            with opened("staging", DIR, parent=root) as staging:
                check_private(staging)
                recover_staging(staging)
        except FileNotFoundError:
            pass

        try:
            with opened("completed", DIR, parent=root) as completed:
                check_private(completed)
                fcntl.flock(completed, fcntl.LOCK_EX | fcntl.LOCK_NB)
                prune(completed)
        except (FileNotFoundError, BlockingIOError):
            # An active publisher prunes before releasing this lock.
            pass


def disk_bytes(fd):
    size = 0
    with os.scandir(fd) as it:
        for item in it:
            st = item.stat(follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                with opened(item.name, DIR, parent=fd) as sub:
                    size += disk_bytes(sub)
            else:
                size += st.st_size
    return size


def prune(completed, keep=None, size=0):
    rows = []
    with os.scandir(completed) as it:
        for item in it:
            if item.name != keep and item.is_dir(follow_symlinks=False):
                rows.append((item.stat(follow_symlinks=False).st_mtime_ns, item.name))
    count = int(keep is not None)
    for _, name in sorted(rows, reverse=True):
        with opened(name, DIR, parent=completed) as fd:
            amount = disk_bytes(fd)
        if count >= MAX_COMPLETED or size + amount > MAX_CACHE_BYTES:
            remove_tree(completed, name)
        else:
            count += 1
            size += amount


async def acquire_lock(fd):
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            await asyncio.sleep(.02)


@asynccontextmanager
async def staging_job(staging, token):
    await acquire_lock(staging)
    try:
        os.mkdir(token, 0o700, dir_fd=staging)
        fd = os.open(token, DIR, dir_fd=staging)
        fcntl.flock(fd, fcntl.LOCK_EX)
    finally:
        fcntl.flock(staging, fcntl.LOCK_UN)
    try:
        yield fd
    finally:
        try:
            await disk_io(remove_tree, staging, token)
        except FileNotFoundError:  # Atomically moved to completed.
            pass
        finally:
            os.close(fd)


# The wire requires requests to echo the offered POSIX/Windows attributes
# exactly. Keep those fixed-width fields packed, alongside compact path data.
ENTRY_ATTRS = struct.Struct(">Bqqqq")


class Traversal:
    def __init__(self):
        self.queue = deque()
        self.count = self.size = self.meta_bytes = 0
        self.top = []

    def enqueue(self, packet, parent):
        for desc in packet.descriptors:
            entry = desc.entry
            parts = (*parent, basename(entry.name))
            self.count += 1
            self.size += entry.size if entry.kind == 1 else 0
            if (entry.kind not in (1, 2) or len(desc.path) > MAX_SOURCE_PATH
                    or len(parts) > MAX_DEPTH or self.count > MAX_ENTRIES
                    or entry.size > MAX_FILE or self.size > min(MAX_TOTAL, MAX_CACHE_BYTES)):
                raise TransferError()
            attrs = ENTRY_ATTRS.pack(entry.filesystem, entry.attributes_or_mode,
                                     entry.creation_or_status_time, entry.access_time, entry.modification_time)
            row = (desc.path, parts, entry.kind, entry.size, attrs)
            # Charge Python storage, including wide Unicode and queue slots.
            # Counting shared ancestors again keeps this a job-wide upper bound.
            self.meta_bytes += (64 + sys.getsizeof(row) + sum(map(sys.getsizeof, row))
                                + sum(map(sys.getsizeof, parts)))
            if self.meta_bytes > MAX_TRAVERSAL_META_BYTES:
                raise TransferError()
            self.queue.append(row)
            if not parent:
                self.top.append(parts[0])

    async def fill(self, dest, request):
        self.enqueue(await request(GetFileDescriptorsPacket, FileDescriptorsPacket, True), ())
        if not self.top:
            raise TransferError()
        while self.queue:
            path, parts, kind, size, attrs = self.queue.popleft()
            fd = os.dup(dest)
            try:
                for part in parts[:-1]:
                    child = os.open(part, DIR, dir_fd=fd)
                    os.close(fd)
                    fd = child
                if kind == 2:
                    os.mkdir(parts[-1], 0o700, dir_fd=fd)
                    self.enqueue(await request(GetFolderFileDescriptorsPacket,
                                               FileDescriptorsPacket, path, True), parts)
                else:
                    fs, mode, created, accessed, modified = ENTRY_ATTRS.unpack(attrs)
                    entry = DirectoryEntry(fs, kind, os.fsencode(parts[-1]), mode,
                                           created, accessed, modified, size)
                    with opened(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                parent=fd) as out:
                        await write_file(out, FileDescriptor(path, entry), request)
            finally:
                os.close(fd)


async def write_file(out, desc, request):
    offset = 0
    while offset < desc.entry.size:
        length = min(MAX_RANGE, desc.entry.size - offset)
        reply = await request(GetFileDataPacket, FileDataPacket, desc, offset, length)
        buf = reply.data
        data = memoryview(buf.storage)[buf.read_offset:buf.write_offset]
        if (reply.descriptor != desc or reply.offset != offset or reply.length != length
                or not 0 < len(data) <= length):
            raise TransferError()
        offset += len(data)
        while data:
            written = os.write(out, data)
            if not written:
                raise TransferError()
            data = data[written:]
        del data, buf, reply


async def receive_files(cache, provider, request, publish, *, peer=b""):
    if not GUID.fullmatch(provider):
        raise TransferError()
    token = provider.decode("ascii") + "-" + secrets.token_hex(16)
    final = hashlib.sha256(peer).hexdigest()[:16] + "-" + token
    tree = Traversal()
    with private_io(), directory(cache, create=True) as root:
        check_private(root)
        for sub in ("staging", "completed"):
            try:
                os.mkdir(sub, 0o700, dir_fd=root)
            except FileExistsError:
                pass
        with opened("staging", DIR, parent=root) as staging, opened("completed", DIR, parent=root) as completed:
            check_private(staging)
            check_private(completed)
            async with staging_job(staging, token) as dest:
                await tree.fill(dest, request)
                # A concurrent publisher must retain its paths until wl-copy has
                # taken ownership. Contended locks yield to the other coroutine.
                await acquire_lock(completed)
                os.utime(dest)
                os.rename(token, final, src_dir_fd=staging, dst_dir_fd=completed)
                try:
                    await publish(tuple(cache / "completed" / final / name for name in tree.top))
                except BaseException:
                    await disk_io(remove_tree, completed, final)
                    raise
                await disk_io(prune, completed, final, tree.size)
    return len(tree.top), tree.size
