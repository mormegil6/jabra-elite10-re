#!/usr/bin/env python3
"""
jabra_listen.py - live head-tracking listener / decoder (Jabra Elite 10 Gen 2).

Connects, subscribes to the head-tracking characteristics (and the fe2c command
channels for context), listens during head movement, and prints candidate
orientation decodings of every packet (float32 / int16-scaled quaternion / etc.).

Primary use: test whether the `20231219-...` stream is readable. The Elite 10
supports multipoint (dual connection), so this can run from the Mac WHILE Jabra
Sound+ on the phone has head tracking enabled - if the head-tracking GATT unlock
is device-wide rather than per-link, the stream shows up here with no auth.

    python tools/jabra_listen.py                 # 30 s listen
    python tools/jabra_listen.py <ADDRESS> --secs 25
    python tools/jabra_listen.py --pre 20231219-...0002:01   # write before listening
"""

import argparse
import asyncio
import math
import struct
import time

from bleak import BleakClient
from bleak.uuids import normalize_uuid_str

JABRA_ADDRESS = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

# Characteristics to TRY subscribing to (head-tracking first, then fe2c context).
TARGETS = [
    "20231219-1730-0000-0000-000000000001",   # head-tracking notify
    "20231219-1730-0000-0000-000000000003",   # head-tracking read+notify
    "fe2c1234", "fe2c1235", "fe2c1237", "fe2c123a",   # fe2c response channels
    "00002455",                                 # wear/volume status (sanity)
]

SUBSCRIBE_TIMEOUT = 5.0


def sid(uuid):
    return normalize_uuid_str(uuid).split("-")[0]


def find_char(client, needle):
    needle = needle.lower()
    for service in client.services:
        for ch in service.characteristics:
            if needle in ch.uuid.lower():
                return ch
    return None


def decode_candidates(data):
    """Every plausible orientation reading, so head motion is visible in numbers."""
    out = []
    n = len(data)
    if n >= 16 and n % 4 == 0:
        out.append("f32x4=" + " ".join(f"{v:+.3f}"
                   for v in struct.unpack_from("<4f", data, 0)))
    if n >= 12 and n % 4 == 0:
        out.append("f32x3=" + " ".join(f"{v:+.3f}"
                   for v in struct.unpack_from("<3f", data, 0)))
    if n >= 8 and n % 2 == 0:
        ints = struct.unpack_from("<4h", data, 0)
        q = [v / 32767.0 for v in ints]
        mag = math.sqrt(sum(c * c for c in q))
        out.append("i16x4=" + " ".join(f"{v:+d}" for v in ints)
                   + f"  q/32767 |q|={mag:.3f}")
    if n >= 6 and n % 2 == 0:
        out.append("i16x3=" + " ".join(f"{v:+d}"
                   for v in struct.unpack_from("<3h", data, 0)))
    return out


async def main(address, secs, pre_writes):
    t0 = time.monotonic()
    packets = {}    # sid -> list of (t, data)
    counts = {}

    def make_cb(s):
        def cb(_sender, data):
            t = time.monotonic() - t0
            d = bytes(data)
            packets.setdefault(s, []).append((t, d))
            counts[s] = counts.get(s, 0) + 1
            # Print head-tracking packets live with decodings; others just count.
            if s.startswith("20231219"):
                print(f"  {t:7.3f} {s} | {d.hex(' ')} | len={len(d)}")
                for line in decode_candidates(d):
                    print(f"          {line}")
            else:
                print(f"  {t:7.3f} {s} | {d.hex(' ')} | len={len(d)}")
        return cb

    print(f"[listen] connecting to {address} ...")
    async with BleakClient(address, timeout=20.0) as client:
        print(f"[listen] connected: {client.is_connected}\n")

        # Optional pre-writes (e.g. a start command) "needle:hexbytes".
        for needle, payload in pre_writes:
            ch = find_char(client, needle)
            if ch is None:
                print(f"[listen] pre-write target {needle!r} not found")
                continue
            for resp in (True, False):
                try:
                    await client.write_gatt_char(ch, bytes.fromhex(payload),
                                                 response=resp)
                    print(f"[listen] pre-write {payload} -> {sid(ch.uuid)} "
                          f"(response={resp})")
                    break
                except Exception as e:
                    err = e
            else:
                print(f"[listen] pre-write {needle} failed: {err}")

        print("[listen] subscribing:")
        unlocked_ht = False
        for needle in TARGETS:
            ch = find_char(client, needle)
            if ch is None:
                print(f"    {needle}: not found")
                continue
            try:
                await asyncio.wait_for(
                    client.start_notify(ch, make_cb(sid(ch.uuid))),
                    SUBSCRIBE_TIMEOUT)
                ok = "OK"
                if needle.startswith("20231219"):
                    unlocked_ht = True
                    ok = "OK  <<< HEAD-TRACKING UNLOCKED"
                print(f"    {sid(ch.uuid)}: {ok}")
            except Exception as e:
                print(f"    {sid(ch.uuid)}: FAIL: {type(e).__name__}: {e}")

        print(f"\n[listen] listening {secs:.0f}s - MOVE YOUR HEAD "
              f"(left/right, up/down, tilt)\n")
        await asyncio.sleep(secs)

        for needle in TARGETS:
            ch = find_char(client, needle)
            if ch is not None:
                try:
                    await client.stop_notify(ch)
                except Exception:
                    pass

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    if not counts:
        print("  no notifications at all")
    for s in sorted(counts):
        print(f"  {s}: {counts[s]} packets")
    ht = [s for s in counts if s.startswith("20231219")]
    if ht:
        print(f"\n  HEAD-TRACKING DATA RECEIVED on {ht} - decode and build the bridge!")
    else:
        print("\n  No head-tracking packets. Stream is still locked on this link.")


def parse_pre(items):
    out = []
    for it in items or []:
        needle, _, payload = it.partition(":")
        out.append((needle.strip().lower(), payload.strip()))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Live head-tracking listener (Jabra)")
    ap.add_argument("address", nargs="?", default=JABRA_ADDRESS)
    ap.add_argument("--secs", type=float, default=30.0)
    ap.add_argument("--pre", action="append",
                    help="write before listening, needle:hex (e.g. fe2c1236:01)")
    args = ap.parse_args()
    asyncio.run(main(args.address, args.secs, parse_pre(args.pre)))
