#!/usr/bin/env python3
"""
jabra_nonce_analysis.py - Stage C: authentication-nonce analysis (Jabra Elite 10).

`fe2c123a` (read/write/notify, 16 bytes) returns a different value on every
connection. The working hypothesis is that it is the authentication challenge
nonce: Jabra Sound+ reads it, computes a response, and writes that response
(to `fe2c1236` and/or back to `fe2c123a`) to unlock head tracking.

This tool gathers evidence about the nonce so we can tell whether it is truly
random (=> we must capture/replicate the real handshake) or has exploitable
structure (counter, timestamp, embedded device id):

  1. Connects N times (default 10), reading `fe2c123a` once per connection.
  2. Within each connection it ALSO reads the nonce a SECOND time to check
     whether it changes mid-session (it should not, if it is a per-connection
     challenge).
  3. Subscribes to `fe2c123a` and writes a probe byte to `fe2c1236`, watching
     for a notification that would mean the nonce rotates in response to writes.
  4. Analyses the collected nonces:
       - per-byte distinct-value count and Shannon entropy (predictable bytes?)
       - Hamming distance between consecutive nonces (~64 bits => random)
       - fixed bytes across all samples (embedded version/device id?)
       - monotonic / counter / timestamp checks on the 128-bit value

    python tools/jabra_nonce_analysis.py
    python tools/jabra_nonce_analysis.py <ADDRESS> --count 10

Known nonces gathered in earlier stages are seeded in SEED_NONCES so the
analysis has data even if a few connections fail.
"""

import argparse
import asyncio
import math
import time

from bleak import BleakClient

JABRA_ADDRESS = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"  # set to your device address (per-Mac UUID on macOS, shown during a scan)

NONCE = "fe2c123a"
CMD = "fe2c1236"

# Nonces observed in stages A/B (one per connection), kept so analysis still has
# a baseline if some live connections drop.
SEED_NONCES = [
    "89a2f5cfb90a2934137ca3811c338acf",
    "694b7aba0c5f39bda915a79eec3d4b2c",
    "bb03c8d3cd325809a76a72f6d3bdaa2a",
    "12a1a2d22333fd4bdf429c48c562b19b",
    "10171b99302acd152eec560f7ca0180d",
]


def find_char(client, needle):
    needle = needle.lower()
    for service in client.services:
        for ch in service.characteristics:
            if needle in ch.uuid.lower():
                return ch
    return None


async def one_session(address, idx):
    """One connection: read nonce twice, probe for write-triggered rotation."""
    result = {"first": None, "second": None, "notify": []}
    try:
        async with BleakClient(address, timeout=20.0) as client:
            nch = find_char(client, NONCE)
            cch = find_char(client, CMD)
            if nch is None:
                print(f"  [{idx}] fe2c123a not found")
                return result

            result["first"] = bytes(await client.read_gatt_char(nch))

            # subscribe to watch for a write-triggered nonce rotation
            got = []
            try:
                await client.start_notify(
                    nch, lambda _s, d: got.append(bytes(d)))
            except Exception:
                pass

            # second read, same session (should be identical)
            await asyncio.sleep(0.2)
            result["second"] = bytes(await client.read_gatt_char(nch))

            # poke the command channel and watch for a notification
            if cch is not None:
                try:
                    await client.write_gatt_char(cch, bytes([0x01]), response=True)
                except Exception:
                    pass
            await asyncio.sleep(1.0)
            result["notify"] = got

            try:
                await client.stop_notify(nch)
            except Exception:
                pass
    except Exception as e:
        print(f"  [{idx}] connection failed: {e}")
    return result


def shannon_entropy(values):
    """Entropy in bits of a list of byte values (max 8 for uniform)."""
    if not values:
        return 0.0
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def analyse(nonces):
    print("\n" + "=" * 70)
    print(f"ANALYSIS over {len(nonces)} nonce(s)")
    print("=" * 70)
    for i, n in enumerate(nonces):
        print(f"  [{i:2d}] {n.hex(' ')}")
    if len(nonces) < 2:
        print("  (need >= 2 nonces for distance/entropy analysis)")
        return

    # Per-byte distinct values + entropy
    print("\n  per-byte: distinct values / 8-bit Shannon entropy "
          "(8.0 = perfectly random)")
    fixed = []
    for pos in range(16):
        col = [n[pos] for n in nonces if len(n) > pos]
        distinct = len(set(col))
        ent = shannon_entropy(col)
        tag = ""
        if distinct == 1:
            tag = f"  <-- FIXED 0x{col[0]:02x}"
            fixed.append((pos, col[0]))
        print(f"    byte[{pos:2d}]  distinct={distinct:2d}/{len(col)}  "
              f"H={ent:4.2f} bits{tag}")

    if fixed:
        print(f"\n  Fixed bytes across ALL samples: "
              + ", ".join(f"[{p}]=0x{v:02x}" for p, v in fixed))
        print("    -> these may encode a constant (version/device id) prefix.")
    else:
        print("\n  No byte is constant across all samples.")

    # Hamming distance between consecutive nonces
    print("\n  Hamming distance between consecutive nonces "
          "(expect ~64/128 bits if random):")
    dists = []
    for i in range(1, len(nonces)):
        d = hamming(nonces[i - 1], nonces[i])
        dists.append(d)
        print(f"    [{i-1}]->[{i}]: {d} bits")
    if dists:
        avg = sum(dists) / len(dists)
        print(f"    average: {avg:.1f} / 128 bits  "
              f"({'consistent with random' if 48 <= avg <= 80 else 'NOT random-looking'})")

    # Counter / timestamp checks on the 128-bit integer (both endiannesses)
    print("\n  128-bit value deltas (looking for a counter/timestamp):")
    for label, byteorder in (("big-endian", "big"), ("little-endian", "little")):
        ints = [int.from_bytes(n, byteorder) for n in nonces]
        diffs = [ints[i] - ints[i - 1] for i in range(1, len(ints))]
        small = all(abs(d) < 2 ** 40 for d in diffs)
        monotonic = all(d > 0 for d in diffs) or all(d < 0 for d in diffs)
        print(f"    {label}: monotonic={monotonic}  small-step={small}")
    print("    (monotonic + small-step would indicate a counter or timestamp;")
    print("     random nonces show neither.)")


async def main(address, count):
    nonces = []
    same_session_changes = 0
    write_triggered = 0

    print(f"[nonce] running {count} connection(s) to {address} ...")
    for i in range(count):
        r = await one_session(address, i)
        if r["first"] is not None:
            nonces.append(r["first"])
            same = (r["first"] == r["second"])
            note = "same" if same else "CHANGED within session!"
            if not same:
                same_session_changes += 1
            wt = ""
            if r["notify"]:
                write_triggered += 1
                wt = f"  notify after write: {[d.hex() for d in r['notify']]}"
            print(f"  [{i:2d}] {r['first'].hex(' ')}  (2nd read: {note}){wt}")
        await asyncio.sleep(0.8)   # let the device settle between connections

    print("\n" + "=" * 70)
    print("SESSION OBSERVATIONS")
    print("=" * 70)
    print(f"  live nonces captured : {len(nonces)} / {count}")
    print(f"  nonce changed within a session (2nd read differed): "
          f"{same_session_changes}")
    print(f"  nonce rotated after a write (notification seen): {write_triggered}")

    # Merge with seeded nonces (dedup) for the structural analysis.
    seed = [bytes.fromhex(s) for s in SEED_NONCES]
    seen = set()
    merged = []
    for n in nonces + seed:
        if n not in seen:
            seen.add(n)
            merged.append(n)
    analyse(merged)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stage C: nonce analysis (Jabra)")
    ap.add_argument("address", nargs="?", default=JABRA_ADDRESS)
    ap.add_argument("--count", type=int, default=10,
                    help="number of connections to make (default: 10)")
    args = ap.parse_args()
    asyncio.run(main(args.address, args.count))
