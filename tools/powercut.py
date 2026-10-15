"""The real one: a VM, a hard power-off, and an outside witness to what was acked.

  host   : python tools/powercut.py listen 9999 acks.txt
  guest  : python tools/powercut.py writer evidence/s.wal HOST_IP 9999
  (power the VM off from the hypervisor, NOT a clean shutdown; boot it again)
  guest  : python tools/powercut.py verify evidence/s.wal acks.txt

The writer sends a UDP datagram only AFTER fsync returned, so every seq the host
saw was acknowledged. After the cut, recovery must still contain all of them.
"""
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable.fsys import RealFS
from immutable.wal import Wal

A64 = "a" * 64
IDS = ("EXPC", "SPC", "WSPC")


def writer(path, host, port):
    wal = Wal.create(RealFS(), path, *IDS)
    wal.append("SESSION_START", {"paper_sha256": A64, "roster_sha256": A64,
                                 "agent_ver": "powercut"})
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        ev = wal.append("HEARTBEAT")                       # returns after fsync
        sock.sendto(str(ev.seq).encode(), (host, int(port)))


def listen(port, out):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", int(port)))
    with open(out, "a") as f:
        while True:
            data, _ = sock.recvfrom(64)
            f.write(data.decode() + "\n")
            f.flush()


def verify(path, acks):
    last_ack = max(int(x) for x in open(acks).read().split())
    rep = Wal.recover(RealFS(), path, *IDS)
    print(f"last acked seq seen by host : {last_ack}")
    print(f"last good seq after recovery: {rep.last_good_seq}")
    print(f"torn bytes discarded        : {rep.discarded_bytes}")
    print("PASS" if rep.last_good_seq >= last_ack else "FAIL: acknowledged events were lost")


if __name__ == "__main__":
    {"writer": writer, "listen": listen, "verify": verify}[sys.argv[1]](*sys.argv[2:])
