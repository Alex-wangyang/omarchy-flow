import socket
import struct
import threading
import unittest
from unittest.mock import patch

import flow_probe


class BoltNameTests(unittest.TestCase):
    def test_capability_is_a_root_query_and_a_missing_device_is_unconfirmed(self):
        reader, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with reader, receiver:
            for reply, expected in [
                (bytes((17, 2, 0, 14, 9, 0, 1)), {"status": "supported"}),
                (bytes((17, 2, 0, 14, 0, 0, 0)), {"status": "unsupported"}),
                (bytes((16, 2, 143, 0, 14, 9, 0)), {"status": "unconfirmed", "error": 9}),
            ]:
                receiver.send(reply)
                self.assertEqual(flow_probe.change_host_capability(reader.fileno(), 2), expected)
                self.assertEqual(receiver.recv(64), bytes((16, 2, 0, 14, 24, 20, 0)))

    def test_two_report_name(self):
        # C548 slot 2 returns a length and 13 name bytes, then the final B.
        name = b"MX Master 3S B"
        reader, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with reader, receiver:
            for part, data in [(1, bytes([len(name)]) + name[:13]), (2, name[13:])]:
                receiver.send(bytes((17, 255, 131, 181, 98, part)) + data.ljust(14, b"\0"))
            self.assertEqual(flow_probe.bolt_slot(reader.fileno(), 2), {
                "status": "paired", "name": "MX Master 3S B"
            })
            for part in (1, 2):
                self.assertEqual(receiver.recv(64), bytes((16, 255, 131, 181, 98, part, 0)))

    def test_missing_slot_and_timeout_remain_distinct(self):
        reader, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with reader, receiver:
            receiver.send(bytes((16, 255, 143, 131, 181, 8, 0)))
            self.assertEqual(flow_probe.bolt_slot(reader.fileno(), 3), {
                "status": "receiver_error", "code": 8
            })
            with patch("flow_probe.select.select", return_value=([], [], [])):
                self.assertEqual(flow_probe.bolt_slot(reader.fileno(), 4), {"status": "timeout"})


class DiscoveryTests(unittest.TestCase):
    def test_envelope_rejects_inconsistent_sizes(self):
        header = bytes(32) + struct.pack(">IHIH", 41, 12, 5, 16)
        self.assertTrue(flow_probe.matches_envelope(header, 77))
        self.assertFalse(flow_probe.matches_envelope(header[:43], 77))
        self.assertFalse(flow_probe.matches_envelope(header, 78))
        self.assertFalse(flow_probe.matches_envelope(header[:-1] + bytes([0]), 77))

    def test_counts_only_selected_peer_addresses(self):
        ready = threading.Event()
        real_selector = flow_probe.selectors.DefaultSelector
        port = None

        class ReadySelector(real_selector):
            def register(self, sock, events, data=None):
                nonlocal port
                entry = super().register(sock, events, data)
                port = sock.getsockname()[1]
                ready.set()
                return entry

        def send():
            if ready.wait(2):
                frame = bytes(32) + struct.pack(">IHIH", 41, 12, 5, 16) + bytes(33)
                for ip, body in [("127.0.0.1", frame), ("127.0.0.2", frame),
                                 ("127.0.0.3", frame),
                                 ("127.0.0.1", b"fixture")]:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.bind((ip, 0))
                        sock.sendto(body, ("127.0.0.1", port))

        thread = threading.Thread(target=send)
        with patch("flow_probe.selectors.DefaultSelector", ReadySelector):
            thread.start()
            try:
                observed = flow_probe.observe("127.0.0.1", 0.5, ports=(0,),
                                              additional_addresses=("127.0.0.2",))
            finally:
                thread.join()
        self.assertEqual(observed["udp_datagrams_by_port"], {0: 3})
        self.assertEqual(observed["matching_envelopes_by_port"], {0: 2})
        self.assertEqual(observed["udp_datagrams_by_source"], {"127.0.0.1": 2, "127.0.0.2": 1})


if __name__ == "__main__":
    unittest.main()
