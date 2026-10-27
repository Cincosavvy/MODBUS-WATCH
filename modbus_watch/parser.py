"""Pull Modbus/TCP frames out of a pcap.

I parse the MBAP header and PDU by hand instead of using scapy's Modbus
layer. It's not much code and it makes it obvious what's going on the wire.

MBAP header (7 bytes):
    transaction id (2) | protocol id (2, always 0) | length (2) | unit id (1)
then the PDU:
    function code (1) | data (length - 2 bytes)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

from scapy.all import IP, TCP, PcapReader

MODBUS_PORT = 502

FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface (Device ID)",
    90: "Schneider UMAS",
}

WRITE_CODES = {5, 6, 15, 16, 21, 22, 23}

EXCEPTION_NAMES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Failed to Respond",
}


@dataclass
class ModbusFrame:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    transaction_id: int
    unit_id: int
    function_code: int
    is_response: bool
    exception_code: Optional[int] = None
    address: Optional[int] = None
    quantity: Optional[int] = None
    value: Optional[int] = None
    subfunction: Optional[int] = None
    raw_pdu: bytes = field(default=b"", repr=False)

    @property
    def is_write(self) -> bool:
        return self.function_code in WRITE_CODES

    @property
    def function_name(self) -> str:
        return FUNCTION_NAMES.get(self.function_code, f"Unknown ({self.function_code})")

    @property
    def master(self) -> str:
        """The client/master side of the conversation."""
        return self.dst if self.is_response else self.src


def _decode_request(frame: ModbusFrame, data: bytes) -> None:
    fc = frame.function_code
    if fc in (1, 2, 3, 4, 15, 16, 23) and len(data) >= 4:
        frame.address, frame.quantity = struct.unpack(">HH", data[:4])
    elif fc in (5, 6) and len(data) >= 4:
        frame.address, frame.value = struct.unpack(">HH", data[:4])
    elif fc == 22 and len(data) >= 2:
        frame.address = struct.unpack(">H", data[:2])[0]
    elif fc == 8 and len(data) >= 2:
        frame.subfunction = struct.unpack(">H", data[:2])[0]
    elif fc == 43 and len(data) >= 1:
        frame.subfunction = data[0]  # MEI type, 14 = read device identification


def parse_payload(payload: bytes, ts: float, src: str, dst: str,
                  sport: int, dport: int) -> Iterator[ModbusFrame]:
    """One TCP segment can carry more than one Modbus ADU, so loop."""
    offset = 0
    while len(payload) - offset >= 8:
        tid, proto, length, unit = struct.unpack(">HHHB", payload[offset:offset + 7])
        if proto != 0 or length < 2:
            return  # not Modbus, or garbage
        pdu = payload[offset + 7: offset + 6 + length]
        if len(pdu) < 1:
            return
        fc = pdu[0]
        is_response = sport == MODBUS_PORT
        frame = ModbusFrame(
            ts=ts, src=src, dst=dst, sport=sport, dport=dport,
            transaction_id=tid, unit_id=unit,
            function_code=fc & 0x7F, is_response=is_response, raw_pdu=pdu,
        )
        if fc & 0x80:
            frame.exception_code = pdu[1] if len(pdu) > 1 else None
        elif not is_response:
            _decode_request(frame, pdu[1:])
        yield frame
        offset += 6 + length


def read_pcap(path: str) -> Iterator[ModbusFrame]:
    with PcapReader(path) as reader:
        for pkt in reader:
            if IP not in pkt or TCP not in pkt:
                continue
            tcp = pkt[TCP]
            if MODBUS_PORT not in (tcp.sport, tcp.dport):
                continue
            payload = bytes(tcp.payload)
            if not payload:
                continue
            yield from parse_payload(
                payload, float(pkt.time), pkt[IP].src, pkt[IP].dst, tcp.sport, tcp.dport
            )
