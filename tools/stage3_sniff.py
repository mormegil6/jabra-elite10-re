#!/usr/bin/env python3
"""
stage3_sniff.py - Stage 3: notification sniffer (Jabra Elite 10 Gen 2).

Subscribes to EVERY characteristic that supports notify/indicate at once and
prints each incoming packet as:

    timestamp | short-id | hex bytes | length

"short id": the segment of the UUID that distinguishes Jabra characteristics is
the leading group (e.g. `fe2c1234`, `20231219`). We print the first 8 hex chars
of the UUID; the full UUID is printed once in the subscription list.

By default it sends NO commands first, to answer "does it stream on subscribe?".
Use --init to write candidate command(s) before listening; the target is matched
against characteristic UUIDs by substring, so the full 128-bit form is not required.

    python tools/stage3_sniff.py <UUID> --duration 20
    python tools/stage3_sniff.py <UUID> --duration 30 --log captures/move.txt
    python tools/stage3_sniff.py <UUID> --init fe2c1236:01 --duration 20
"""

import argparse
import asyncio
import time
import sys

from bleak import BleakClient
from bleak.uuids import normalize_uuid_str

JABRA_ADDRESS = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"


def short_id(uuid):
    """Leading group of the UUID, e.g. 'fe2c1234-....' -> 'fe2c1234'."""
    return normalize_uuid_str(uuid).split("-")[0]


def find_char(client, needle):
    """Return the first characteristic whose UUID contains `needle` (case-insensitive)."""
    needle = needle.lower()
    for service in client.services:
        for ch in service.characteristics:
            if needle in ch.uuid.lower():
                return ch
    return None


class Sniffer:
    def __init__(self, logfile=None):
        self.t0 = time.monotonic()
        self.count = {}          # short id -> packet count
        self.last_t = {}         # short id -> last timestamp (for rate)
        self.intervals = {}      # short id -> list of inter-packet gaps
        self.logfile = logfile

    def handle(self, sid):
        def cb(_sender, data):
            now = time.monotonic()
            t = now - self.t0
            self.count[sid] = self.count.get(sid, 0) + 1
            if sid in self.last_t:
                self.intervals.setdefault(sid, []).append(now - self.last_t[sid])
            self.last_t[sid] = now
            line = (f"{t:8.3f} | {sid} | {data.hex(' ')} | len={len(data)}")
            print(line)
            if self.logfile:
                self.logfile.write(line + "\n")
                self.logfile.flush()
        return cb

    def summary(self):
        print("\n" + "=" * 60)
        print("SUMMARY  (packets per characteristic, approx rate)")
        print("=" * 60)
        for sid in sorted(self.count):
            n = self.count[sid]
            gaps = self.intervals.get(sid, [])
            if gaps:
                avg = sum(gaps) / len(gaps)
                rate = 1.0 / avg if avg > 0 else 0
                print(f"  {sid}: {n:5d} packets   ~{rate:6.1f} Hz   "
                      f"(avg gap {avg*1000:.1f} ms)")
            else:
                print(f"  {sid}: {n:5d} packets")
        if not self.count:
            print("  (no notifications received)")


async def main(address, duration, logpath, init_cmds):
    sniffer = None
    logfile = open(logpath, "w") if logpath else None
    try:
        print(f"[sniff] connecting to {address} ...")
        async with BleakClient(address, timeout=20.0) as client:
            print(f"[sniff] connected: {client.is_connected}")
            sniffer = Sniffer(logfile)

            # Discover every notify/indicate characteristic and subscribe.
            notifiable = []
            for service in client.services:
                for ch in service.characteristics:
                    if "notify" in ch.properties or "indicate" in ch.properties:
                        notifiable.append(ch)

            print(f"[sniff] subscribing to {len(notifiable)} characteristic(s):")
            for ch in notifiable:
                print(f"        {short_id(ch.uuid)}  {ch.uuid}  "
                      f"[{','.join(ch.properties)}]")
            print()

            for ch in notifiable:
                try:
                    await client.start_notify(ch, sniffer.handle(short_id(ch.uuid)))
                except Exception as e:
                    print(f"[sniff] could not subscribe {short_id(ch.uuid)}: {e}")

            # Optional start command(s): "fe2c1236:01,fe2c1234:0102"
            for target, payload in init_cmds:
                ch = find_char(client, target)
                if ch is None:
                    print(f"[sniff] init target {target!r} not found")
                    continue
                try:
                    await client.write_gatt_char(ch, bytes.fromhex(payload),
                                                 response=True)
                    print(f"[sniff] wrote {payload} -> {short_id(ch.uuid)}")
                except Exception as e:
                    print(f"[sniff] write {target} failed: {e}")

            print(f"[sniff] listening {duration:.0f}s ... "
                  f"(move your head to correlate)\n")
            await asyncio.sleep(duration)

            for ch in notifiable:
                try:
                    await client.stop_notify(ch)
                except Exception:
                    pass

        sniffer.summary()
    finally:
        if logfile:
            logfile.close()
            print(f"\n[sniff] log written to {logpath}")


def parse_init(items):
    out = []
    for it in items or []:
        target, _, payload = it.partition(":")
        out.append((target.strip().lower(), payload.strip()))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stage 3: notification sniffer (Jabra)")
    ap.add_argument("address", nargs="?", default=JABRA_ADDRESS)
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--log", default=None, help="write packets to this file too")
    ap.add_argument("--init", action="append",
                    help="start command(s) target:hex, e.g. fe2c1236:01")
    args = ap.parse_args()
    if not args.address:
        print("Provide an address.")
        sys.exit(1)
    asyncio.run(main(args.address, args.duration, args.log, parse_init(args.init)))
