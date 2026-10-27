import struct
from pathlib import Path

from modbus_watch import Config, analyze, parse_payload, read_pcap

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "plant.pcap"


def frame(pdu, unit=1, tid=1):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def parse_one(payload, src="10.0.0.10", dst="10.0.0.50", sport=49152, dport=502):
    return list(parse_payload(payload, 0.0, src, dst, sport, dport))


def test_read_holding_request():
    (f,) = parse_one(frame(struct.pack(">BHH", 3, 100, 10)))
    assert f.function_code == 3
    assert f.address == 100 and f.quantity == 10
    assert not f.is_response and not f.is_write


def test_write_single_coil():
    (f,) = parse_one(frame(struct.pack(">BHH", 5, 7, 0xFF00)))
    assert f.is_write and f.address == 7 and f.value == 0xFF00


def test_exception_response():
    (f,) = parse_one(frame(bytes([0x83, 2])), src="10.0.0.50", dst="10.0.0.10",
                     sport=502, dport=49152)
    assert f.is_response and f.function_code == 3 and f.exception_code == 2
    assert f.master == "10.0.0.10"


def test_two_adus_in_one_segment():
    payload = frame(struct.pack(">BHH", 3, 0, 1), tid=1) + frame(struct.pack(">BHH", 3, 5, 1), tid=2)
    frames = parse_one(payload)
    assert [f.transaction_id for f in frames] == [1, 2]


def test_non_modbus_is_ignored():
    assert parse_one(b"GET / HTTP/1.1\r\n\r\n") == []


def test_unauthorized_write_flagged():
    frames = parse_one(frame(struct.pack(">BHH", 6, 4, 999)), src="10.0.0.99")
    rules = {f.rule for f in analyze(frames, Config(allowed_masters={"10.0.0.10"}))}
    assert {"unknown_master", "unauthorized_write"} <= rules


def test_allowed_write_is_quiet():
    frames = parse_one(frame(struct.pack(">BHH", 6, 4, 200)))
    assert analyze(frames, Config(allowed_masters={"10.0.0.10"})) == []


def test_sample_capture_catches_the_attack():
    frames = list(read_pcap(str(SAMPLE)))
    findings = analyze(frames, Config(allowed_masters={"10.0.0.10", "10.0.0.20"}))
    rules = {f.rule for f in findings}
    assert rules == {
        "unknown_master", "device_fingerprint", "unit_id_sweep", "exception_spike",
        "unusual_function", "unauthorized_write", "write_burst", "dangerous_diagnostic",
    }
    # nothing should point at the legit hosts
    assert all(f.src == "10.0.0.99" for f in findings)
