# modbus-watch

A small Python tool that reads a packet capture and flags sketchy Modbus/TCP traffic.

Modbus is still everywhere in industrial networks (water, power, manufacturing) and it has zero security built in. No auth, no encryption. If you can reach port 502 on a PLC, you can usually read and write whatever you want. So the only real defense in a lot of plants is watching the traffic and knowing what normal looks like.

I built this as part of my OT/ICS security research to get hands-on with what attacks actually look like on the wire, instead of just reading about them.

## What it catches

| Rule | Severity | What it means |
|---|---|---|
| `unauthorized_write` | high | A host that isn't on your allow list wrote to a coil or register |
| `dangerous_diagnostic` | high | FC 8 restart / listen-only / clear counters. These can knock a PLC off the network |
| `unknown_master` | medium | A new host started sending Modbus requests |
| `write_burst` | medium | A lot of writes from one host in a short window |
| `unit_id_sweep` | medium | One host hitting a bunch of unit IDs, i.e. looking for devices |
| `exception_spike` | medium | Lots of error responses, usually someone probing addresses or codes that don't exist |
| `unusual_function` | medium | Function codes you don't see in normal polling, like FC 90 (Schneider UMAS) |
| `device_fingerprint` | low | FC 43/14 read device ID (vendor, model, firmware). Classic recon |

## Running it

```bash
pip install -r requirements.txt
python -m modbus_watch samples/plant.pcap --allow 10.0.0.10 --allow 10.0.0.20
```

`--allow` is the list of hosts that are supposed to be talking to your PLCs (HMIs, engineering workstations, historians). Leave it off and it still runs every other check.

Other options:

```
--json            print findings as JSON (for piping into something else)
--burst N         writes that count as a burst (default 10)
--window SECONDS  burst window (default 5)
```

It exits with code 1 if it finds anything, so you can drop it into a script.

## The sample capture

`samples/plant.pcap` is a made-up plant network I generated with `scripts/make_sample.py`:

- `10.0.0.10` HMI polling the PLC every second and adjusting a setpoint now and then
- `10.0.0.20` engineering workstation checking in
- `10.0.0.50` the PLC
- `10.0.0.99` the attacker

About a minute in, the attacker fingerprints the PLC, sweeps unit IDs, probes for registers that don't exist, tries a vendor-specific function code, flips 15 coils, and then sends a Diagnostics restart to take the PLC offline. Pretty much the playbook you see in real ICS incident reports, just compressed.

Here's what the tool says about it:

```
Masters:
  10.0.0.10           124 requests
  10.0.0.99            32 requests  <- not on allow list
  10.0.0.20             3 requests

Findings: 8
  [MEDIUM] 17:34:20.300  unknown_master
      10.0.0.99 is talking Modbus to 10.0.0.50 and isn't on the allowed list.
  [LOW] 17:34:20.300  device_fingerprint
      10.0.0.99 asked 10.0.0.50 for its device ID (vendor, model, firmware). Common recon step.
  [MEDIUM] 17:34:21.300  unit_id_sweep
      10.0.0.99 has hit 5 different unit IDs. Looks like it's scanning for devices.
  [MEDIUM] 17:34:21.504  exception_spike
      5 exception responses to 10.0.0.99 (latest: Gateway Target Failed to Respond). ...
  [MEDIUM] 17:34:23.100  unusual_function
      Uncommon function code 90 (Schneider UMAS) from 10.0.0.99.
  [HIGH] 17:34:23.200  unauthorized_write
      15x Write Single Coil from unlisted host 10.0.0.99 to 10.0.0.50 (unit 1, addrs 0-14, last value ON).
  [MEDIUM] 17:34:24.100  write_burst
      10 writes from 10.0.0.99 in 5s.
  [HIGH] 17:34:25.099  dangerous_diagnostic
      Diagnostics subfunction 1 (Restart Communications Option) sent to 10.0.0.50. ...
```

The normal HMI traffic, including its setpoint writes, doesn't trigger anything. Full output is in `samples/plant_output.txt`.

## How it works

- `modbus_watch/parser.py` pulls TCP payloads on port 502 out of the pcap with scapy and decodes the MBAP header and PDU by hand. I skipped scapy's built-in Modbus layer on purpose so the protocol parsing is right there to read. It also handles more than one Modbus frame in a single TCP segment, which happens a lot with real devices.
- `modbus_watch/rules.py` runs everything through the detection rules in one pass, keeping some per-host state (write timestamps, unit IDs seen, exception counts).
- `modbus_watch/cli.py` is the command line part.

## Tests

```bash
pip install pytest
python -m pytest
```

## Limitations / what's next

This is a starting point, not a product. Things I know about:

- Only Modbus/TCP for now. **DNP3 is next**, since that's the other big one in utilities.
- Offline pcaps only. I want to add live capture off an interface.
- The thresholds are hardcoded defaults. A better version would learn a baseline from a clean capture first and alert on anything outside it.
- It doesn't reassemble TCP streams, so a Modbus frame split across two segments gets skipped.

If you run it on your own captures and something looks off, open an issue.

## Author

Marnier Crockton, PhD candidate at Howard University, researching OT/ICS security.
