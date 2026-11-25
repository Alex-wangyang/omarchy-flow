"""Synchronous HID++ access to the local C548 management interface."""
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
import os
from pathlib import Path
import select
import socket
import time
import threading

from flow_control import check_file, default_config_dir, private_dir, read_private_json, write_private_json
from flow_probe import bolt_receivers, bolt_slot, read_name_part


def default_state_path():
    return default_config_dir() / "state.json"


DEFAULT_CONFIG = default_state_path()
PAIRING_LOCK = threading.Lock()
SOFTWARE_ID = ContextVar("hidpp_software_id", default=0x0E)


SCAN_TIMEOUT = 8.0
_SCAN_DEADLINE = ContextVar("scan_deadline", default=None)


def _remaining():
    deadline = _SCAN_DEADLINE.get()
    if deadline is None:
        return None
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("receiver inventory timed out")
    return left


@contextmanager
def _pairing_lock():
    left = _remaining()
    if not PAIRING_LOCK.acquire(timeout=-1 if left is None else left):
        raise TimeoutError("receiver inventory timed out")
    try:
        yield
    finally:
        PAIRING_LOCK.release()


def _write(fd, report):
    _remaining()
    if os.write(fd, report) != len(report):
        raise OSError("short HID++ write")


def _reply(fd, prefix, *, subregister=None, timeout=2.5):
    left = _remaining()
    deadline = time.monotonic() + (timeout if left is None else min(left, timeout))
    while (remaining := deadline - time.monotonic()) > 0:
        if not select.select([fd], [], [], remaining)[0]:
            break
        report = os.read(fd, 64)
        if not report:
            raise OSError("HID++ device disconnected")
        if len(report) < 7 or report[1] != prefix[0]:
            continue
        if report[2] in (0x8F, 0xFF) and report[3:5] == prefix[1:]:
            raise OSError(f"HID++ request rejected (code {report[5]})")
        if report[1:4] != prefix or (subregister is not None and report[4] != subregister):
            continue
        if (report[0], len(report)) not in ((0x10, 7), (0x11, 20)):
            raise OSError("invalid HID++ report length")
        return report[4:]
    raise TimeoutError("local receiver did not answer; activate the device on this host")


def _feature(fd, slot, index, function, payload=b"", *, expect_reply=True):
    if not 1 <= slot <= 6:
        raise ValueError("invalid Bolt slot")
    prefix = bytes([slot, index, function << 4 | SOFTWARE_ID.get()])
    _write(fd, b"\x11" + prefix + payload.ljust(16, b"\0"))
    if expect_reply:
        return _reply(fd, prefix)


def get_feature_index(fd, slot, feature_id) -> int | None:
    return _feature(fd, slot, 0, 0, feature_id.to_bytes(2, "big"))[0] or None


def _required_feature(fd, slot, feature):
    index = get_feature_index(fd, slot, feature)
    if index is None:
        raise ValueError(f"slot {slot} lacks HID++ feature 0x{feature:04x}")
    return index


def _pairing_record(fd, slot):
    prefix = bytes((0xff, 0x83, 0xb5))
    subregister = 0x50 + slot
    # Negative receiver-register replies omit the slot number.
    with _pairing_lock():
        _write(fd, b"\x10" + prefix + bytes((subregister, 0, 0)))
        data = _reply(fd, prefix, subregister=subregister)
    if len(data) < 8:
        raise OSError("short Bolt pairing record")
    return data


def _pairing_info(fd, slot):
    data = _pairing_record(fd, slot)
    return int.from_bytes(data[2:4], "little"), int.from_bytes(data[4:8], "big")


def read_device_info(fd, slot):
    index = get_feature_index(fd, slot, 0x0003)
    if index is None:
        wpid, serial = _pairing_info(fd, slot)
    else:
        data = _feature(fd, slot, index, 0)
        if len(data) < 13:
            raise OSError("short HID++ identity response")
        serial = int.from_bytes(data[1:5], "big")
        transports = int.from_bytes(data[5:7], "big")
        if transports & 0x0002:
            # BLE / Logi Bolt model ID slot.
            offset = 7 + 2 * (transports & 0x0001).bit_count()
            wpid = int.from_bytes(data[offset:offset+2], "big")
        elif transports & 0x0004:
            # eQuad / Unifying WPID slot.
            offset = 7 + 2 * (transports & 0x0003).bit_count()
            wpid = int.from_bytes(data[offset:offset+2], "big")
        else:
            wpid, _ = _pairing_info(fd, slot)
    return {"device_id": 0x020000 | wpid, "serial_number": serial}


def read_crypto_identifier(fd, slot) -> str:
    index = _required_feature(fd, slot, 0x0021)
    halves = [_feature(fd, slot, index, part) for part in (0, 1)]
    if any(len(part) != 16 for part in halves):
        raise OSError("short HID++ identifier response")
    return b"".join(halves).hex()


def get_host_info(fd, slot) -> tuple[int, int]:
    index = _required_feature(fd, slot, 0x1814)
    hosts, current = _feature(fd, slot, index, 0)[:2]
    if not 0 <= current < hosts:
        raise ValueError("invalid HID++ host information")
    return hosts, current


def read_change_host(fd, slot) -> tuple[int, int]:
    index = _required_feature(fd, slot, 0x1814)
    hosts = _feature(fd, slot, index, 0)[0]
    if hosts < 1:
        raise ValueError("invalid HID++ host count")
    return index, hosts


def set_current_host(fd, slot, host_index: int, *, guard=None, change_host=None,
                     on_change_host=None) -> None:
    if change_host is None:
        index, hosts = read_change_host(fd, slot)
        if on_change_host is not None:
            on_change_host((index, hosts))
    else:
        index, hosts = change_host
    if not 0 <= host_index < hosts:
        raise ValueError("invalid target host index")
    # Switching can remove the return path. Submit exactly one request.
    with guard if guard is not None else nullcontext():
        _feature(fd, slot, index, 1, bytes([host_index]), expect_reply=False)


def bolt_path(hidraw):
    path = Path(hidraw).resolve(strict=True)
    if path not in bolt_receivers():
        raise ValueError("expected a Bolt receiver management interface")
    return path


def _device_name(fd, slot):
    index = _required_feature(fd, slot, 0x0005)
    length = _feature(fd, slot, index, 0)[0]
    name = bytearray()
    while len(name) < length:
        name.extend(_feature(fd, slot, index, 1, bytes([len(name)])))
    return name[:length].decode("utf-8", errors="replace")


def _inventory_slot(fd, slot):
    # The probe's name register has a bounded 750 ms read per fragment. Check
    # the scan deadline between fragments, including on offline peripherals.
    name = bytearray()
    part = 1
    while True:
        _remaining()
        data = read_name_part(fd, slot, part)
        if data is None:
            return {"status": "timeout"}
        if isinstance(data, int):
            return {"status": "receiver_error", "code": data}
        if part == 1:
            length, data = data[0], data[1:]
            if not length:
                raise ValueError("empty Bolt device name")
        name.extend(data)
        if len(name) >= length:
            return {"status": "paired", "name": name[:length].decode("ascii")}
        part += 1


def inventory_bolt_devices(hidraw=None):
    """Query receiver pairing records even if the peripheral is on another host."""
    devices = []
    token = SOFTWARE_ID.set(0x0c)
    scan = _SCAN_DEADLINE.set(time.monotonic() + SCAN_TIMEOUT)
    try:
        for path in ([bolt_path(hidraw)] if hidraw else bolt_receivers()):
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                for slot in range(1, 7):
                    with _pairing_lock():
                        row = _inventory_slot(fd, slot)
                    if row["status"] == "timeout":
                        break
                    if row["status"] != "paired":
                        continue
                    record = _pairing_record(fd, slot)
                    device = dict(slot=slot, name=row["name"], channel=None,
                                  kind={1: "keyboard", 2: "mouse"}.get(record[1] & 15, "other"),
                                  device_id=0x020000 | int.from_bytes(record[2:4], "little"),
                                  serial_number=int.from_bytes(record[4:8], "big"))
                    try:
                        device["channel"] = get_host_info(fd, slot)[1]
                    except (OSError, ValueError):
                        pass
                    try:
                        device["name"] = _device_name(fd, slot) or row["name"]
                    except (OSError, ValueError):
                        pass
                    devices.append(device)
            finally:
                os.close(fd)
        _remaining()
    finally:
        _SCAN_DEADLINE.reset(scan)
        SOFTWARE_ID.reset(token)
    return devices


def _read_slots(fd, devices):
    for slot in range(1, 7):
        info = bolt_slot(fd, slot)
        if info["status"] == "receiver_error" and info["code"] == 8:
            continue
        if info["status"] != "paired":
            raise OSError(f"could not inspect Bolt pairing slot {slot}")
        if get_feature_index(fd, slot, 0x1814) is None:
            continue
        mouse = get_feature_index(fd, slot, 0x0021) is not None
        role = "mouse" if mouse else "keyboard"
        if role in devices:
            raise ValueError(f"multiple eligible devices for role {role}")
        device = read_device_info(fd, slot)
        _, channel = get_host_info(fd, slot)
        if channel >= 3:
            raise ValueError("device channel outside Flow layout")
        device.update(slot=slot, channel=channel)
        if mouse:
            device["random"] = read_crypto_identifier(fd, slot)
        devices[role] = device


def state_destination(config, directory):
    if config.name in ("preferences.json", "control.sock"):
        raise ValueError("reserved state destination")
    try:
        info = os.stat(config.name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    check_file(info)
    if info.st_nlink != 1:
        raise ValueError("state destination must be a private file")


def load_state(path):
    path = Path(path).expanduser()
    with private_dir(path.parent, create=False) as directory:
        state_destination(path, directory)
        return read_private_json(directory, path.name, limit=None)


def provision_local_devices(config=None, host_id=None, *, fd=None, clear_password=False):
    config = default_state_path() if config is None else Path(config).expanduser()
    with private_dir(config.parent) as directory:
        state_destination(config, directory)
        try:
            previous = read_private_json(directory, config.name, limit=None)
        except FileNotFoundError:
            previous = {}
        if not isinstance(previous, dict) or not isinstance(previous.get("password", ""), str):
            raise ValueError("invalid state file")
        password = previous.get("password")
        if password is not None:
            password.encode("utf-8")
        devices = _provision_devices(fd)
        state = {"host_id": host_id or socket.gethostname(), **devices}
        if password is not None and not clear_password:
            state["password"] = password
        write_private_json(directory, config.name, state)
    return {"host_id": state["host_id"], **{
        role: {**{k: device[k] for k in ("device_id", "serial_number", "slot", "channel")},
               "has_random": "random" in device} for role, device in devices.items()}}


def _provision_devices(fd):
    devices = {}
    if fd is not None:
        _read_slots(fd, devices)
    else:
        for path in bolt_receivers():
            handle = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                _read_slots(handle, devices)
            finally:
                os.close(handle)
    if "mouse" not in devices:
        raise ValueError("no active Flow mouse found on a local Bolt receiver")
    return devices
