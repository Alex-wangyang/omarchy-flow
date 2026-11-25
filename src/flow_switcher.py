"""Dispatch a verified local Bolt switch off the network event loop."""
import asyncio
from contextlib import contextmanager
import logging
import os
import threading

from bolt_hidpp import SOFTWARE_ID, bolt_path, bolt_receivers, read_device_info, set_current_host, _pairing_info

LOG = logging.getLogger("omarchy-flow")


class StaleCrossing(Exception):
    pass


class Switcher:
    def __init__(self, state, hidraw=None, dry_run=False):
        self.devices = {r: {k: v for k, v in state[r].items() if k in
                            ("device_id", "serial_number", "slot")}
                        for r in ("mouse", "keyboard") if r in state}
        self.hidraw, self.dry_run = hidraw, dry_run
        self.generation = 0
        self.lock = threading.Lock()
        self.task = self.pending = None
        self.closed = threading.Event()
        self._verified = {}

    def invalidate(self):
        with self.lock:
            self.generation += 1
            self.pending = None
            return self.generation

    def active(self, generation):
        return not self.closed.is_set() and generation == self.generation

    @contextmanager
    def write_guard(self, generation):
        # Invalidation and the single nonblocking ChangeHost write are serialized.
        with self.lock:
            if not self.active(generation):
                raise StaleCrossing()
            yield

    def _pairing_matches(self, fd, slot, identity):
        model, serial = _pairing_info(fd, slot)
        return (0x020000 | model, serial) == (identity["device_id"], identity["serial_number"])

    def switch(self, role, channel, generation=None):
        if generation is None:
            generation = self.generation
        if self.dry_run:
            LOG.info("Dry run: %s switch to channel %d", role, channel)
            return False
        SOFTWARE_ID.set(0x0D if role == "keyboard" else 0x0E)
        device = self.devices[role]
        identity = {k: device[k] for k in ("device_id", "serial_number")}
        id_key = (identity["device_id"], identity["serial_number"])
        for path in ([bolt_path(self.hidraw)] if self.hidraw else bolt_receivers()):
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                hint = device.get("slot")
                slots = sorted(range(1, 7), key=lambda slot: slot != hint)
                for slot in slots:
                    if not self.active(generation):
                        raise StaleCrossing()
                    try:
                        pairing_ok = self._pairing_matches(fd, slot, identity)
                    except (OSError, ValueError):
                        if slot != hint:
                            continue
                        pairing_ok = False
                    if slot != hint and not pairing_ok:
                        continue
                    cached = self._verified.get(id_key) if pairing_ok else None
                    if cached is not None:
                        device["slot"] = slot
                        try:
                            set_current_host(fd, slot, channel,
                                             guard=self.write_guard(generation),
                                             change_host=cached)
                        except ValueError:
                            self._verified.pop(id_key, None)
                            raise
                        LOG.info("HID++ submitted %s switch (slot %d) -> channel %d (fast)",
                                 role, slot, channel)
                        return True
                    try:
                        actual = read_device_info(fd, slot)
                    except (OSError, ValueError):
                        continue
                    if actual == identity:
                        device["slot"] = slot
                        learned = []
                        set_current_host(fd, slot, channel,
                                         guard=self.write_guard(generation),
                                         on_change_host=learned.append)
                        if pairing_ok and learned:
                            self._verified[id_key] = learned[0]
                        LOG.info("HID++ submitted %s switch (slot %d) -> channel %d", role, slot, channel)
                        return True
            finally:
                os.close(fd)
        raise OSError("paired device unavailable")

    async def _attempt(self, role, channel, generation):
        for attempt in range(2):
            if not self.active(generation):
                return False
            try:
                return await asyncio.to_thread(self.switch, role, channel, generation)
            except StaleCrossing:
                return False
            except (OSError, ValueError) as exc:
                LOG.warning("%s switch unavailable (%s)", role, type(exc).__name__)
                if attempt or not isinstance(exc, OSError) or not self.active(generation):
                    return False
                await asyncio.sleep(.15)

    async def _work(self):
        while self.pending is not None:
            generation, mouse, keyboard = self.pending
            self.pending = None
            if await self._attempt("mouse", mouse, generation) and keyboard is not None:
                await self._attempt("keyboard", keyboard, generation)

    def submit_crossing(self, mouse_channel, keyboard_channel=None):
        if self.closed.is_set():
            return
        generation = self.invalidate()
        self.pending = (generation, mouse_channel, keyboard_channel)
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._work())

    async def close(self):
        self.invalidate()
        self.closed.set()
        if self.task:
            await self.task
