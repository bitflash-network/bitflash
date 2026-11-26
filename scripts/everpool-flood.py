#!/usr/bin/env python3
# Test-only: floods a Bitflash node's TESTNET P2P port with Everpool messages
# (docs/pool-registry.md sections 8, 11 and 12), to measure what a hostile peer
# can make the node spend. It speaks the node's wire format directly: a
# version message in the 101 framing, then 102 framing (with checksum).
#
# Point it only at a node you run, on an isolated bench (-testnet -isolate),
# on 127.0.0.1. It refuses any other address.
#
#   everpool-flood.py PORT MODE COUNT [--conns N]
#
# Modes: p2xshare (for pools the node does not carry), p2xsync, p2xgetsh,
# poolwho, poolinv, pooltkt-bad (512 malformed tickets a message),
# poolgettkt, p2xshare-big (250 KB bodies).
#
# Prints messages sent, connections used and refused, and the seconds taken;
# measure the node's own CPU and memory from outside (ps, /proc).

import hashlib
import os
import socket
import struct
import sys
import threading
import time

MAGIC = bytes([0xce, 0xe2, 0xc0, 0xff])    # testnet pchMessageStart
SERVICES = (1 << 2) | (1 << 3)             # NODE_P2POOL | NODE_POOLREG


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def cmd12(c):
    return c.encode() + b"\0" * (12 - len(c))


def compact(n):
    if n < 253:
        return bytes([n])
    if n < 65536:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def frame101(c, payload):
    return MAGIC + cmd12(c) + struct.pack("<I", len(payload)) + payload


def frame102(c, payload):
    return MAGIC + cmd12(c) + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def addr():
    return struct.pack("<Q", SERVICES) + b"\0" * 10 + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", 18433)


def version():
    rel = b"flood"
    p = struct.pack("<iQq", 102, SERVICES, int(time.time())) + addr() + struct.pack("<i", -1) + compact(len(rel)) + rel
    return frame101("version", p)


def drain(s, stop):
    s.settimeout(0.5)
    while not stop.is_set():
        try:
            if not s.recv(1 << 16):
                return
        except socket.timeout:
            continue
        except OSError:
            return


class Conn:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.s.sendall(version())
        self.stop = threading.Event()
        self.t = threading.Thread(target=drain, args=(self.s, self.stop), daemon=True)
        self.t.start()

    def send(self, c, payload):
        self.s.sendall(frame102(c, payload))

    def close(self):
        self.stop.set()
        try:
            self.s.close()
        except OSError:
            pass


def payload_for(mode, i):
    pid = hashlib.sha256(b"pool%d" % i).digest()
    if mode == "p2xshare":
        return "p2xshare", pid + os.urandom(200)
    if mode == "p2xshare-big":
        return "p2xshare", pid + os.urandom(250 * 1024)
    if mode == "p2xsync":
        return "p2xsync", pid + b"\0" * 32
    if mode == "p2xgetsh":
        return "p2xgetsh", pid + compact(1) + hashlib.sha256(b"s%d" % i).digest()
    if mode == "poolwho":
        return "poolwho", pid
    if mode == "poolinv":
        ids = b"".join(hashlib.sha256(b"inv%d.%d" % (i, k)).digest() for k in range(32))
        return "poolinv", compact(32) + ids
    if mode == "pooltkt-bad":
        # epoch 5, a seed this node does not have, 512 bodies of 118 bytes
        return "pooltkt", struct.pack("<I", 5) + b"\x11" * 32 + compact(512) + os.urandom(118 * 512)
    if mode == "poolgettkt":
        return "poolgettkt", struct.pack("<I", 5)
    raise SystemExit("unknown mode " + mode)


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    port, mode, count = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    nconn = 1
    if "--conns" in sys.argv:
        nconn = int(sys.argv[sys.argv.index("--conns") + 1])
    t0 = time.time()
    sent = 0
    conns = refused = 0
    c = None
    # Prebuild one payload per message: the generator's own cost must not be
    # what is measured, so payloads repeat every 4096 messages.
    pre = [payload_for(mode, i) for i in range(min(count, 4096))]
    while sent < count:
        if c is None:
            try:
                c = Conn(port)
                conns += 1
            except OSError:
                refused += 1
                time.sleep(0.2)
                continue
            time.sleep(0.2)
        try:
            cmd, p = pre[sent % len(pre)]
            c.send(cmd, p)
            sent += 1
            if nconn > 1 and sent % (count // nconn or 1) == 0:
                c.close()
                c = None
        except OSError:
            c.close()
            c = None
            refused += 1
    if c:
        time.sleep(1)
        c.close()
    print("mode %s: %d messages sent, %d connections opened, %d dropped by the node, %.1f s" % (
        mode, sent, conns, refused, time.time() - t0))


if __name__ == "__main__":
    main()
