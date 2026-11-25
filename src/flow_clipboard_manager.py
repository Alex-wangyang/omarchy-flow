"""Authenticated clipboard offers, scoped providers and correlated transfer jobs."""
import asyncio
from collections import deque
import logging
from pathlib import Path
import secrets
import subprocess
from struct import unpack_from

from fars import DecodeError
import marconi_packets as wire
from flow_clipboard import MAX_TEXT, WaylandClipboard, WaylandUnavailable, convert_image, marconi_image_to_png
from flow_control import clipboard_summary
from flow_transfer import GUID, LINUX_OS, TransferError, descriptors, file_range, receive_files

LOG = logging.getLogger("omarchy-flow")
REQUESTS = (wire.GetFormatDataPacket, wire.GetFileDescriptorsPacket, wire.GetFolderFileDescriptorsPacket,
            wire.GetFileDataPacket)
RESPONSES = (wire.FormatDataPacket, wire.FileDescriptorsPacket, wire.FileDataPacket, wire.ErrorPacket)
PREFERENCE = (b"file", b"image", b"text/plain", b"text/html", b"text/rtf", b"text/xml")


def _fmt_names(formats):
    return [wire._safe_text(item, 32) for item in formats[:8]]


class ClipboardManager:
    def __init__(self, daemon, backend=None, cache=None):
        self.daemon = daemon
        self.backend = backend if backend is not None else WaylandClipboard()
        self.cache = Path(cache) if cache else Path.home() / ".cache/omarchy-flow/transfers"
        self.local = self.remote = self.job = self.last_summary = None
        self.recipients = set()
        self.participants = set()
        self.local_gen = None
        self.waiters = {}
        self.serving = {}
        self.lock = asyncio.Lock()
        self.epoch = 0
        self.capture = None

    def allowed(self, tunnel):
        d = self.daemon
        if not self.enabled() or d.tunnels.get(tunnel.host) is not tunnel:
            return False
        peer = d.ready_peer(tunnel.peer_channel)
        return peer is not None and peer.host_id == tunnel.host

    def enabled(self):
        d = self.daemon
        return bool(d.settings and d.settings.on and d.settings.copy_paste and not d.reset_local
                    and not d.closing and any(p.enabled and p.host_id == d.host and
                        p.channel == d.identity[2] for p in d.settings.peers))

    def status(self):
        return dict(enabled=self.enabled(), busy=bool(self.job or self.serving),
                    last_summary=self.last_summary)

    def stop_import(self):
        if self.job:
            self.job.cancel()
            self.job = None
        for _, _, future in self.waiters.values():
            future.cancel()
        self.waiters.clear()

    def revoke_local(self, *, serving_tunnel=None):
        self.local = None
        self.recipients.clear()
        for tunnel in tuple(self.serving):
            if tunnel is not serving_tunnel:
                self.stop_serving(tunnel, reject=self.allowed(tunnel))

    def stop_serving(self, tunnel, *, reject=False):
        service = self.serving.pop(tunnel, None)
        if service:
            task, queue = service
            task.cancel()
            if reject and queue:
                requests = tuple(packet for packet, _ in queue)
                self.daemon.spawn(self.reject_requests(tunnel, requests))
            queue.clear()

    async def reject_requests(self, tunnel, requests):
        try:
            for request in requests:
                await self.error(tunnel, request)
        except (ValueError, OSError, asyncio.TimeoutError):
            pass

    def invalidate(self):
        self.epoch += 1
        if not self.enabled():
            self.backend.forget_local()
            if self.capture:
                self.capture.cancel()
            self.stop_import()
            self.remote = None
            self.revoke_local()
        else:
            if self.remote and not self.allowed(self.remote[0]):
                self.stop_import()
                self.remote = None
            for t in tuple(self.recipients):
                if not self.allowed(t):
                    self.disconnect(t)

    def disconnect(self, tunnel):
        if tunnel not in self.participants:
            return
        self.participants.remove(tunnel)
        self.epoch += 1
        if self.remote and self.remote[0] is tunnel:
            self.stop_import()
            self.remote = None
        self.recipients.discard(tunnel)
        if not self.recipients:
            self.local = None
            self.backend.forget_local()
        for key, (owner, _, future) in tuple(self.waiters.items()):
            if owner is tunnel:
                future.cancel()
                del self.waiters[key]
        self.stop_serving(tunnel)

    async def observe(self, *, serving_tunnel=None):
        selection = await self.backend.snapshot_local()
        if self.local and (self.local_gen != self.backend.local_generation or not selection
                           or self.local.fingerprint != selection.fingerprint):
            self.revoke_local(serving_tunnel=serving_tunnel)
        return selection

    async def announce(self, targets, *, crossing=False, crossing_target=None):
        epoch = self.epoch
        async with self.lock:
            if not self.enabled():
                return
            self.capture = asyncio.create_task(self.observe())
            try:
                selection = await self.capture
            except asyncio.CancelledError:
                if epoch == self.epoch or self.daemon.closing:
                    raise
                return
            finally:
                self.capture = None
            if (epoch != self.epoch or self.job or not selection or not selection.formats
                    or (not crossing and self.daemon.active_owner != self.daemon.host)
                    or not any(self.allowed(t) for t in targets)):
                return
            if not self.local:
                self.local = selection
                self.local_gen = self.backend.local_generation
                self.remote = None
            current = self.local

        async def notify(tunnel):
            def eligible():
                return (epoch == self.epoch and self.allowed(tunnel) and self.local is current
                        and self.local_gen == self.backend.local_generation
                        and (crossing or tunnel not in self.recipients))

            def committed():
                self.recipients.add(tunnel)
                self.participants.add(tunnel)

            if eligible():
                packet = wire.ClipboardUpdatePacket(self.daemon.host, current.provider_id, current.formats)
                try:
                    sent = await asyncio.wait_for(
                        tunnel.send_global(packet, allowed=eligible, committed=committed), .25)
                    if sent:
                        LOG.info("Clipboard ANNOUNCE -> peer=%s formats=%s crossing=%s",
                                 wire._safe_text(tunnel.host), _fmt_names(current.formats), crossing)
                except (ValueError, OSError, asyncio.TimeoutError) as exc:
                    LOG.warning("Clipboard ANNOUNCE failed -> peer=%s (%s)",
                                wire._safe_text(tunnel.host), type(exc).__name__)

        if crossing_target is not None:
            for tunnel in targets:
                if tunnel is not crossing_target and self.allowed(tunnel):
                    self.daemon.spawn(notify(tunnel))
            await notify(crossing_target)
        else:
            await asyncio.gather(*(notify(t) for t in targets), return_exceptions=True)

    async def monitor(self):
        while not self.daemon.closing:
            await asyncio.sleep(1)
            if self.enabled():
                try:
                    await self.announce(tuple(self.daemon.tunnels.values()))
                except (ValueError, OSError, asyncio.TimeoutError):
                    continue

    async def request(self, tunnel, provider, cls, response_type, *args):
        key = provider, secrets.token_hex(16).encode()
        future = asyncio.get_running_loop().create_future()
        self.waiters[key] = tunnel, response_type, future
        async def exchange():
            await tunnel.send_global(cls(self.daemon.host, *key, *args))
            return await future

        try:
            return await asyncio.wait_for(exchange(), wire.TRANSFER_TIMEOUT)
        finally:
            self.waiters.pop(key, None)
            future.cancel()

    def owner_changed(self):
        self.epoch += 1
        if self.daemon.active_owner != self.daemon.host:
            self.stop_import()
        elif self.remote and self.allowed(self.remote[0]) and not self.job:
            self.job = self.daemon.spawn(self.materialize(*self.remote))

    async def dispatch(self, tunnel, packet):
        if packet.host_id != tunnel.host:
            return
        if isinstance(packet, wire.ClipboardUpdatePacket):
            if self.allowed(tunnel) and GUID.fullmatch(packet.provider_id):
                self.participants.add(tunnel)
                formats = tuple(f for f in PREFERENCE if f in packet.formats)
                offer = (tunnel, wire.ClipboardUpdatePacket(tunnel.host, packet.provider_id, formats))
                if offer != self.remote:
                    LOG.info("Clipboard OFFER <- peer=%s formats=%s supported=%s owner=%s",
                             wire._safe_text(tunnel.host), _fmt_names(packet.formats),
                             _fmt_names(formats), wire._safe_text(self.daemon.active_owner or b""))
                    self.stop_import()
                    self.revoke_local()
                    self.remote = offer
                    self.owner_changed()
            else:
                LOG.debug("Clipboard OFFER ignored <- peer=%s allowed=%s",
                          wire._safe_text(tunnel.host), self.allowed(tunnel))
            return
        if not GUID.fullmatch(packet.provider_id) or not GUID.fullmatch(packet.request_id):
            LOG.debug("Clipboard packet ignored <- peer=%s (invalid operation GUID)",
                      wire._safe_text(tunnel.host))
            return
        if type(packet) in RESPONSES:
            match = self.waiters.get((packet.provider_id, packet.request_id))
            if match and match[0] is tunnel and not match[2].done():
                if type(packet) is match[1]:
                    match[2].set_result(packet)
                else:
                    if isinstance(packet, wire.ErrorPacket):
                        LOG.warning("Clipboard REMOTE ERROR <- peer=%s code=%d",
                                    wire._safe_text(tunnel.host), packet.error.code)
                    match[2].set_exception(TransferError())
            return
        if type(packet) in REQUESTS:
            if (not self.allowed(tunnel) or tunnel not in self.recipients or not self.local
                    or self.local.provider_id != packet.provider_id or not self.valid_request(packet)):
                LOG.info("Clipboard DENY %s <- peer=%s (allowed=%s recipient=%s has_local=%s provider_match=%s)",
                         type(packet).__name__, wire._safe_text(tunnel.host),
                         self.allowed(tunnel), tunnel in self.recipients, self.local is not None,
                         bool(self.local and self.local.provider_id == packet.provider_id))
                await self.error(tunnel, packet)
                return
            service = self.serving.get(tunnel)
            if service:
                queue = service[1]
                if len(queue) >= 4:
                    await self.error(tunnel, packet)
                    return
                queue.append((packet, self.local))
            else:
                queue = deque([(packet, self.local)])
                self.serving[tunnel] = self.daemon.spawn(self.drain(tunnel, queue)), queue

    def valid_request(self, packet):
        if type(packet) is wire.GetFormatDataPacket:
            return packet.mime_type in dict(self.local.values)
        if not self.local.roots:
            return False
        if type(packet) is wire.GetFileDataPacket:
            return len(packet.descriptor.path) <= 4096 and len(packet.descriptor.entry.name) <= wire.MAX_ENTRY_NAME
        return type(packet) is wire.GetFileDescriptorsPacket or len(packet.folder) <= 4096

    async def drain(self, tunnel, queue):
        try:
            while queue:
                packet, local = queue[0]
                await self.serve(tunnel, packet, local)
                if queue and queue[0][0] is packet:
                    queue.popleft()
        finally:
            if self.serving.get(tunnel, (None, None))[1] is queue:
                del self.serving[tunnel]

    def reply_started(self, tunnel, request):
        # Once the first frame is being written, revocation cannot replace
        # that response with another reply for the same operation.
        service = self.serving.get(tunnel)
        if service and service[1] and service[1][0][0] is request:
            service[1].popleft()

    async def error(self, tunnel, request):
        await tunnel.send_global(wire.ErrorPacket(self.daemon.host, request.provider_id, request.request_id,
                                                  wire.WireException(-1, b"Unavailable", ())),
                                 started=lambda: self.reply_started(tunnel, request))

    async def serve(self, tunnel, request, local):
        try:
            await asyncio.wait_for(self.send_response(tunnel, request, local), wire.TRANSFER_TIMEOUT)
        except (OSError, ValueError, KeyError, asyncio.TimeoutError, OverflowError) as exc:
            LOG.warning("Clipboard OUT failed %s -> peer=%s (%s)",
                        type(request).__name__, wire._safe_text(tunnel.host), type(exc).__name__)
            try:
                await self.error(tunnel, request)
            except (ValueError, OSError, asyncio.TimeoutError):
                pass

    async def send_response(self, tunnel, request, local):
        def eligible():
            return (self.allowed(tunnel) and tunnel in self.recipients and self.local is local
                    and self.local_gen == self.backend.local_generation)

        await self.observe(serving_tunnel=tunnel)
        if not eligible():
            raise TransferError()
        prefix = self.daemon.host, request.provider_id, request.request_id
        if isinstance(request, wire.GetFormatDataPacket):
            data = dict(local.values).get(request.mime_type)
            if data is None:
                raise TransferError()
            response = wire.FormatDataPacket(*prefix, request.mime_type, wire._buffer(data))
        elif not local.roots:
            raise TransferError()
        elif isinstance(request, wire.GetFileDataPacket):
            data = await asyncio.to_thread(file_range, local.roots, request)
            response = wire.FileDataPacket(*prefix, request.descriptor, request.offset,
                                           request.length, wire._buffer(data))
        else:
            items = await asyncio.to_thread(descriptors, local.roots, request)
            response = wire.FileDescriptorsPacket(*prefix, items, LINUX_OS)
        if not await tunnel.send_global(response, allowed=eligible,
                                        started=lambda: self.reply_started(tunnel, request)):
            raise TransferError()
        if isinstance(response, wire.FormatDataPacket):
            if response.mime_type == b"image":
                width, height = unpack_from(">II", data)
                self.last_summary = clipboard_summary("OUT", "image", width, height)
            else:
                self.last_summary = clipboard_summary("OUT", "text", len(data))
        elif isinstance(response, wire.FileDescriptorsPacket):
            self.last_summary = f"Clipboard OUT · {len(items)} files offered"
        else:
            self.last_summary = "Clipboard OUT · file data served"
        LOG.info("Clipboard OUT -> peer=%s %s", wire._safe_text(tunnel.host), self.last_summary)

    async def materialize(self, tunnel, offer):
        task = asyncio.current_task()
        timer = asyncio.get_running_loop().call_later(wire.TRANSFER_TIMEOUT, task.cancel)
        try:
            await self.observe()
            generation = self.backend.local_generation
            for attempt in range(3):
                try:
                    await self.import_selection(tunnel, offer, generation)
                    break
                except WaylandUnavailable:
                    LOG.warning("Clipboard IN Wayland publish retry %d/3 <- peer=%s",
                                attempt + 1, wire._safe_text(tunnel.host))
                    if attempt == 2:
                        break
                    await asyncio.sleep(.2)
                    await self.observe()
                    if (not self.allowed(tunnel) or self.remote != (tunnel, offer)
                            or self.daemon.active_owner != self.daemon.host
                            or self.backend.local_generation != generation):
                        break
        except (OSError, ValueError, asyncio.TimeoutError) as exc:
            detail = f": {exc}" if isinstance(exc, DecodeError) else ""
            LOG.warning("Clipboard IN failed <- peer=%s (%s%s)",
                        wire._safe_text(tunnel.host), type(exc).__name__, detail)
        finally:
            timer.cancel()
            if self.job is task:
                self.job = self.remote = None

    async def import_selection(self, tunnel, offer, generation):
        async def publish(method, *args):
            if (self.daemon.active_owner != self.daemon.host or not self.allowed(tunnel)
                    or self.remote != (tunnel, offer) or self.backend.local_generation != generation):
                raise TransferError()
            try:
                await method(*args, generation=generation)
            except (OSError, subprocess.SubprocessError, asyncio.TimeoutError):
                raise WaylandUnavailable() from None

        async def publish_files(paths):
            await publish(self.backend.set_files, paths)

        async def request(cls, response, *args):
            return await self.request(tunnel, offer.provider_id, cls, response, *args)

        fmt = next((f for f in PREFERENCE if f in offer.formats), None)
        if fmt:
            LOG.info("Clipboard IN start <- peer=%s fmt=%s",
                     wire._safe_text(tunnel.host), wire._safe_text(fmt, 32))
        if fmt == b"file":
            count, total = await receive_files(self.cache, offer.provider_id, request, publish_files,
                                               peer=tunnel.host)
            summary = clipboard_summary("IN", "files", count, total)
        elif fmt:
            reply = await request(wire.GetFormatDataPacket, wire.FormatDataPacket, fmt)
            if reply.mime_type != fmt:
                raise TransferError()
            buf = reply.data
            data = buf.storage[buf.read_offset:buf.write_offset]
            if fmt == b"image":
                img = wire.ClipboardImage.decode(data, buf.endian)
                png = await convert_image(marconi_image_to_png, img.width, img.height, img.pixels)
                await publish(self.backend.set_image_png, png)
                summary = clipboard_summary("IN", "image", img.width, img.height)
            else:
                if len(data) > MAX_TEXT:
                    raise TransferError()
                if fmt == b"text/plain":
                    try:
                        data.decode("utf8")
                    except UnicodeError:
                        raise TransferError() from None
                await publish(self.backend.set_text, fmt, data)
                summary = clipboard_summary("IN", "text", len(data))
        else:
            return
        self.last_summary = summary
        LOG.info("Clipboard IN ok <- peer=%s %s", wire._safe_text(tunnel.host), summary)
