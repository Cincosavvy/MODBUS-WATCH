from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone

from .parser import read_pcap
from .rules import Config, analyze

COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m"}
RESET = "\033[0m"


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="modbus-watch",
        description="Look through a pcap for suspicious Modbus/TCP activity.",
    )
    p.add_argument("pcap", help="capture file to read")
    p.add_argument("-a", "--allow", action="append", metavar="IP",
                   help="IP allowed to act as a Modbus master (repeat for more)")
    p.add_argument("--burst", type=int, default=10, help="writes that count as a burst (default 10)")
    p.add_argument("--window", type=float, default=5.0, help="burst window in seconds (default 5)")
    p.add_argument("--json", action="store_true", help="print findings as JSON")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    frames = list(read_pcap(args.pcap))
    cfg = Config(
        allowed_masters=set(args.allow) if args.allow else None,
        write_burst_count=args.burst,
        write_burst_window=args.window,
    )
    findings = analyze(frames, cfg)

    if args.json:
        json.dump([f.to_dict() for f in findings], sys.stdout, indent=2)
        print()
        return 1 if findings else 0

    color = sys.stdout.isatty() and not args.no_color
    requests = [f for f in frames if not f.is_response]
    print(f"{len(frames)} Modbus frames ({len(requests)} requests) in {args.pcap}\n")

    print("Function codes seen:")
    for name, n in Counter(f.function_name for f in requests).most_common():
        print(f"  {n:>6}  {name}")

    print("\nMasters:")
    for ip, n in Counter(f.src for f in requests).most_common():
        tag = "" if not args.allow or ip in args.allow else "  <- not on allow list"
        print(f"  {ip:<16} {n:>6} requests{tag}")

    if not args.allow:
        print("\n(no --allow list given, so unknown-master checks are off)")

    print(f"\nFindings: {len(findings)}")
    for f in findings:
        sev = f.severity.upper()
        if color:
            sev = f"{COLORS[f.severity]}{sev}{RESET}"
        print(f"  [{sev}] {fmt_ts(f.ts)}  {f.rule}")
        print(f"      {f.detail}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
