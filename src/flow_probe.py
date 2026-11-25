"""Linux-side bring-up for an Options+ peer. Uses only the standard library."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import select
import selectors
import socket
import struct
import sys
import time
from contextlib import ExitStack


def bolt_receivers():
    for entry in sorted(Path("/sys/class/hidraw").glob("hidraw*")):
        device = (entry / "device").resolve()
        if not device.name.startswith("0003:046D:C548."):
            continue
        # Only the vendor HID++ interface, never a keyboard or mouse input interface.
        interface_number = (device.parent / "bInterfaceNumber").read_text().strip()
        if interface_number == "02":
            yield Path("/dev") / entry.name


def read_name_part(fd, slot, part):
    # HID++ long register read, receiver information, Bolt device name.
    subregister = 0x60 + slot
    request = bytes((0x10, 0xFF, 0x83, 0xB5, subregister, part, 0))
    if os.write(fd, request) != len(request):
        raise OSError("short HID++ write")
    deadline = time.monotonic() + 0.75
    while (remaining := deadline - time.monotonic()) > 0:
        if not select.select([fd], [], [], remaining)[0]:
            break
        data = os.read(fd, 64)
        if data[:5] == bytes((0x10, 0xFF, 0x8F, 0x83, 0xB5)) and len(data) >= 6:
            return data[5]
        if data[:6] != bytes((0x11, 0xFF, 0x83, 0xB5, subregister, part)):
            continue
        if len(data) != 20:
            raise ValueError("invalid Bolt name report length")
        return data[6:]
    return None


def bolt_slot(fd, slot):
    name = bytearray()
    part = 1
    while True:
        payload = read_name_part(fd, slot, part)
        if payload is None:
            return {"status": "timeout"}
        if isinstance(payload, int):
            return {"status": "receiver_error", "code": payload}
        if part == 1:
            length = payload[0]
            if length == 0:
                raise ValueError("empty Bolt device name")
            name.extend(payload[1:])
        else:
            name.extend(payload)
        if len(name) >= length:
            return {"status": "paired", "name": name[:length].decode("ascii")}
        part += 1


def change_host_capability(fd, slot):
    # HID++ 2.0 Root.GetFeature(0x1814). Only look up the feature index.
    # Querying the root never invokes ChangeHost on the device.
    request = bytes((0x10, slot, 0, 0x0E, 0x18, 0x14, 0))
    if os.write(fd, request) != len(request):
        raise OSError("short HID++ write")
    deadline = time.monotonic() + 0.75
    while (remaining := deadline - time.monotonic()) > 0:
        if not select.select([fd], [], [], remaining)[0]:
            break
        data = os.read(fd, 64)
        if len(data) < 7 or data[0] not in (0x10, 0x11) or data[1] != slot:
            continue
        if data[2:4] == request[2:4]:
            return {"status": "supported" if data[4] else "unsupported"}
        if data[2] in (0x8F, 0xFF) and data[3:5] == request[2:4]:
            return {"status": "unconfirmed", "error": data[5]}
    return {"status": "unconfirmed", "reason": "timeout"}


def inventory():
    receivers = []
    for path in bolt_receivers():
        fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        try:
            slots = []
            for slot in range(1, 7):
                result = bolt_slot(fd, slot)
                if result["status"] == "paired":
                    result["change_host"] = change_host_capability(fd, slot)
                slots.append({"slot": slot, **result})
                # Errors lack a slot identifier. After a timeout, a late reply
                # could otherwise be attributed to the next request.
                if result["status"] == "timeout":
                    break
        finally:
            os.close(fd)
        receivers.append({"receiver": str(path), "slots": slots})
    return {"bolt_receivers": receivers}


def matches_envelope(header, packet_size):
    if packet_size < 72 or len(header) < 44:
        return False
    block, iv, body, tag = struct.unpack_from(">IHIH", header, 32)
    return (block, iv, tag) == (packet_size - 36, 12, 16) and body == packet_size - 72


def observe(peer, seconds, ports=(59870, 59871), additional_addresses=()):
    counts = {port: 0 for port in ports}
    framed = {port: 0 for port in ports}
    sources = dict.fromkeys((peer, *additional_addresses), 0)
    header = bytearray(44)
    with ExitStack() as resources:
        selector = resources.enter_context(selectors.DefaultSelector())
        for port in ports:
            sock = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            sock.bind(("", port))  # Linux must accept subnet broadcasts here.
            selector.register(sock, selectors.EVENT_READ, port)
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            for key, _ in selector.select(remaining):
                # Linux MSG_TRUNC reports the full datagram size while copying
                # only its outer header. No ciphertext or input data is retained.
                size, _, _, sender = key.fileobj.recvmsg_into([header], 0, socket.MSG_TRUNC)
                if sender[0] in sources:
                    sources[sender[0]] += 1
                    counts[key.data] += 1
                    if matches_envelope(header, size):
                        framed[key.data] += 1
    return {"peer": peer, "seconds": seconds, "udp_datagrams_by_source": sources,
            "udp_datagrams_by_port": counts,
            "matching_envelopes_by_port": framed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inventory", help="read paired-device names from a C548 Bolt receiver")
    watch = commands.add_parser("observe", help="count datagrams from one IPv4 peer")
    watch.add_argument("--peer", type=ipaddress.IPv4Address, required=True, action="append",
                       help="LAN IPv4 address of the Mac; repeat for each active interface")
    watch.add_argument("--seconds", type=int, default=45, metavar="1..300")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("this prototype runs on Linux")
    try:
        if args.command == "inventory":
            result = inventory()
        else:
            if not 1 <= args.seconds <= 300:
                parser.error("--seconds must be in 1..300")
            primary, *additional = map(str, args.peer)
            result = observe(primary, args.seconds, additional_addresses=additional)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
