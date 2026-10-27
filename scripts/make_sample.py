"""Build samples/plant.pcap: a small fake plant network with an attack in the middle.

    10.0.0.10  HMI, polls the PLC every second and writes a setpoint now and then
    10.0.0.20  engineering workstation, checks in a few times
    10.0.0.50  PLC
    10.0.0.99  the attacker

The attacker shows up about a minute in, fingerprints the PLC, sweeps unit IDs,
probes for registers that don't exist, slams a bunch of coil writes, then sends a
Diagnostics "restart comms" to knock the PLC off the network.

Run:  python scripts/make_sample.py
"""

import random
import struct
from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap

PLC = "10.0.0.50"
HMI = "10.0.0.10"
ENG = "10.0.0.20"
ATTACKER = "10.0.0.99"

START = 1_761_500_000.0  # fixed so the output is the same every run
random.seed(7)

packets = []
tid = 0


def mbap(unit: int, pdu: bytes) -> bytes:
    global tid
    tid = (tid + 1) & 0xFFFF
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def send(ts, src, dst, sport, dport, payload):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(payload)
    pkt.time = ts
    packets.append(pkt)


def request(ts, master, sport, unit, pdu, response_pdu, delay=0.004):
    req = mbap(unit, pdu)
    send(ts, master, PLC, sport, 502, req)
    if response_pdu is not None:
        # reuse the same transaction id in the reply, like a real server
        resp = req[:2] + struct.pack(">HHB", 0, len(response_pdu) + 1, unit) + response_pdu
        send(ts + delay, PLC, master, 502, sport, resp)


def read_holding(addr, qty):
    return struct.pack(">BHH", 3, addr, qty)


def read_holding_resp(qty):
    vals = [random.randint(0, 500) for _ in range(qty)]
    return struct.pack(">BB", 3, qty * 2) + struct.pack(f">{qty}H", *vals)


def exception(fc, code):
    return struct.pack(">BB", fc | 0x80, code)


# --- normal traffic: 2 minutes of HMI polling ---
for sec in range(120):
    t = START + sec
    request(t, HMI, 49152, 1, read_holding(0, 10), read_holding_resp(10))
    if sec % 30 == 15:  # operator nudges a setpoint
        pdu = struct.pack(">BHH", 6, 4, random.randint(180, 220))
        request(t + 0.5, HMI, 49152, 1, pdu, pdu)

for sec in (5, 45, 95):
    request(START + sec + 0.2, ENG, 50211, 1, struct.pack(">BHH", 1, 0, 16),
            struct.pack(">BBH", 1, 2, 0x00FF))

# --- the attack, starting at ~60s ---
t = START + 60.3
sp = 41000

# 1. fingerprint the device
request(t, ATTACKER, sp, 1, bytes([43, 14, 1, 0]),
        bytes([43, 14, 1, 1, 0, 0, 2, 0, 7]) + b"AcmePLC" + bytes([1, 4]) + b"M340")

# 2. sweep unit ids, gateway says nobody's home for most of them
for unit in range(1, 9):
    t += 0.2
    resp = read_holding_resp(1) if unit == 1 else exception(3, 11)
    request(t, ATTACKER, sp, unit, read_holding(0, 1), resp)

# 3. probe for registers past the end of the map
for addr in (100, 500, 1000, 4000, 9000, 20000):
    t += 0.15
    request(t, ATTACKER, sp, 1, read_holding(addr, 1), exception(3, 2))

# 4. vendor-specific function code
t += 0.3
request(t, ATTACKER, sp, 1, bytes([90, 0, 2]), exception(90, 1))

# 5. hammer the coils
for i in range(15):
    t += 0.1
    pdu = struct.pack(">BHH", 5, i, 0xFF00)
    request(t, ATTACKER, sp, 1, pdu, pdu)

# 6. restart comms. no reply, the PLC drops off
t += 0.5
request(t, ATTACKER, sp, 1, struct.pack(">BHH", 8, 1, 0), None)

packets.sort(key=lambda p: p.time)
out = Path(__file__).resolve().parent.parent / "samples" / "plant.pcap"
out.parent.mkdir(exist_ok=True)
wrpcap(str(out), packets)
print(f"wrote {len(packets)} packets to {out}")
