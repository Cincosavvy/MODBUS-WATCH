"""Detection rules.

Nothing fancy here. These are the things I'd actually want flagged if I were
watching a plant network: someone new talking to a PLC, writes coming from
places they shouldn't, diagnostic commands that can knock a device offline,
and the traffic patterns you see when somebody is scanning around.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Iterable, Optional

from .parser import ModbusFrame, WRITE_CODES, EXCEPTION_NAMES

# Codes you'd expect to see in normal polling/control traffic.
COMMON_CODES = {1, 2, 3, 4, 5, 6, 15, 16, 23}

# Diagnostics (FC 8) subfunctions that actually change device state.
DANGEROUS_DIAG = {
    1: "Restart Communications Option",
    4: "Force Listen Only Mode",
    10: "Clear Counters and Diagnostic Register",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    rule: str
    severity: str
    ts: float
    src: str
    dst: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Config:
    allowed_masters: Optional[set[str]] = None   # None = learn nothing, skip allowlist checks
    write_burst_count: int = 10                  # this many writes...
    write_burst_window: float = 5.0              # ...in this many seconds
    exception_threshold: int = 5                 # exception responses per master
    unit_sweep_threshold: int = 5                # distinct unit IDs from one master


def _addr_summary(addrs: set[int]) -> str:
    if not addrs:
        return "addr ?"
    if len(addrs) == 1:
        return f"addr {next(iter(addrs))}"
    return f"addrs {min(addrs)}-{max(addrs)}"


def _value(f: ModbusFrame) -> str:
    if f.value is None:
        return "?"
    if f.function_code == 5:
        return {0xFF00: "ON", 0x0000: "OFF"}.get(f.value, hex(f.value))
    return str(f.value)


def analyze(frames: Iterable[ModbusFrame], config: Config | None = None) -> list[Finding]:
    cfg = config or Config()
    findings: list[Finding] = []

    seen_masters: set[str] = set()
    write_times: dict[str, deque] = defaultdict(deque)
    burst_flagged: set[str] = set()
    exceptions: dict[str, int] = defaultdict(int)
    exception_flagged: set[str] = set()
    unit_ids: dict[str, set[int]] = defaultdict(set)
    sweep_flagged: set[str] = set()
    odd_code_flagged: set[tuple[str, int]] = set()
    bad_writes: dict[tuple, list] = {}

    for f in frames:
        if f.is_response:
            if f.exception_code is not None:
                m = f.master
                exceptions[m] += 1
                if exceptions[m] >= cfg.exception_threshold and m not in exception_flagged:
                    exception_flagged.add(m)
                    name = EXCEPTION_NAMES.get(f.exception_code, f.exception_code)
                    findings.append(Finding(
                        "exception_spike", "medium", f.ts, m, f.src,
                        f"{exceptions[m]} exception responses to {m} (latest: {name}). "
                        "Usually means someone is poking at addresses or codes the device doesn't support.",
                    ))
            continue

        # --- requests from here down ---
        src = f.src

        if src not in seen_masters:
            seen_masters.add(src)
            if cfg.allowed_masters is not None and src not in cfg.allowed_masters:
                findings.append(Finding(
                    "unknown_master", "medium", f.ts, src, f.dst,
                    f"{src} is talking Modbus to {f.dst} and isn't on the allowed list.",
                ))

        if f.function_code in WRITE_CODES:
            if cfg.allowed_masters is not None and src not in cfg.allowed_masters:
                # one finding per host/target/function, with a running count,
                # otherwise a write flood buries everything else
                key = (src, f.dst, f.function_code)
                if key not in bad_writes:
                    finding = Finding("unauthorized_write", "high", f.ts, src, f.dst, "")
                    bad_writes[key] = [finding, 0, set()]
                    findings.append(finding)
                entry = bad_writes[key]
                entry[1] += 1
                if f.address is not None:
                    entry[2].add(f.address)
                entry[0].detail = (
                    f"{entry[1]}x {f.function_name} from unlisted host {src} to {f.dst} "
                    f"(unit {f.unit_id}, {_addr_summary(entry[2])}, last value {_value(f)})."
                )

            q = write_times[src]
            q.append(f.ts)
            while q and f.ts - q[0] > cfg.write_burst_window:
                q.popleft()
            if len(q) >= cfg.write_burst_count and src not in burst_flagged:
                burst_flagged.add(src)
                findings.append(Finding(
                    "write_burst", "medium", f.ts, src, f.dst,
                    f"{len(q)} writes from {src} in {cfg.write_burst_window:.0f}s.",
                ))

        if f.function_code == 8:
            sub = f.subfunction
            if sub in DANGEROUS_DIAG:
                findings.append(Finding(
                    "dangerous_diagnostic", "high", f.ts, src, f.dst,
                    f"Diagnostics subfunction {sub} ({DANGEROUS_DIAG[sub]}) sent to {f.dst}. "
                    "This can take the device off the network.",
                ))

        if f.function_code == 43 and f.subfunction == 14:
            key = (src, 43)
            if key not in odd_code_flagged:
                odd_code_flagged.add(key)
                findings.append(Finding(
                    "device_fingerprint", "low", f.ts, src, f.dst,
                    f"{src} asked {f.dst} for its device ID (vendor, model, firmware). Common recon step.",
                ))
        elif f.function_code not in COMMON_CODES and f.function_code != 8:
            key = (src, f.function_code)
            if key not in odd_code_flagged:
                odd_code_flagged.add(key)
                findings.append(Finding(
                    "unusual_function", "medium", f.ts, src, f.dst,
                    f"Uncommon function code {f.function_code} ({f.function_name}) from {src}.",
                ))

        unit_ids[src].add(f.unit_id)
        if len(unit_ids[src]) >= cfg.unit_sweep_threshold and src not in sweep_flagged:
            sweep_flagged.add(src)
            findings.append(Finding(
                "unit_id_sweep", "medium", f.ts, src, f.dst,
                f"{src} has hit {len(unit_ids[src])} different unit IDs. Looks like it's scanning for devices.",
            ))

    findings.sort(key=lambda x: (x.ts, SEVERITY_ORDER[x.severity]))
    return findings
