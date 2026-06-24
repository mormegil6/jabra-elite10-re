#!/usr/bin/env python3
"""
jabra_probe.py - Stage B: unauthenticated data-trigger probe (Jabra Elite 10 Gen 2).

The head-tracking service `20231219-1730-...` refuses subscription
("value's length is invalid") until the device is authenticated: the device
issues a random 16-byte nonce on `fe2c123a` each connection and Jabra Sound+
answers it on `fe2c1236`. Before doing the hard MitM work, this probe tries the
cheap possibilities: maybe a simple command unlocks the stream, or the device
accepts a trivial / echoed challenge response.

What it does:
  1. Subscribes to EVERY notify/indicate characteristic, each in its own
     try/except so one rejection (the locked 20231219 chars) doesn't stop the
     rest. Records which subscriptions succeed and which fail (and why).
  2. Runs a sequence of blind writes to the command channels, waiting 3 s after
     each and reporting every notification that arrives in that window:
        a. 3a01            <- 01
        b. 3a01            <- 23 01
        c. fe2c1236        <- 01
        d. fe2c1236        <- 00 01
        e. fe2c1236        <- 01 00
        f. fe2c1236        <- (the fe2c123a nonce, echoed back unchanged)
        g. fe2c1236        <- 00 * 16
        h. 20231219-0002   <- 01           (newly found head-tracking write char)
        i. 20231219-0002   <- 01 00
  3. After each write, re-attempts subscription to the two locked head-tracking
     characteristics (0001, 0003) and reports whether it now succeeds. A
     successful subscribe is THE milestone: it means authentication passed.
  4. Finally opens a motion-capture window that records everything during head
     movement and tries to decode any head-tracking / fe2c packets as
     orientation (float32 / int16-scaled / quaternion / Euler).

    python tools/jabra_probe.py
    python tools/jabra_probe.py <ADDRESS> --move-secs 20

Nothing here writes to the standard LE-Audio / telephony control points; only the
Jabra-proprietary (f010, fe2c) and head-tracking (20231219) channels are touched.
"""

import argparse
import asyncio
import math
import struct
import time

from bleak import BleakClient
from bleak.uuids import normalize_uuid_str

JABRA_ADDRESS = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"  # set to your device address (per-Mac UUID on macOS, shown during a scan)

# Characteristics referenced by short needle (substring of the full UUID).
C_3A01 = "00003a01"
C_FE2C_NONCE = "fe2c123a"          # read challenge nonce here
C_FE2C_CMD = "fe2c1236"            # write-only command channel
HT_NOTIFY_1 = "20231219-1730-0000-0000-000000000001"
HT_WRITE_2  = "20231219-1730-0000-0000-000000000002"
HT_NOTIFY_3 = "20231219-1730-0000-0000-000000000003"
HT_LOCKED = (HT_NOTIFY_1, HT_NOTIFY_3)   # the two locked head-tracking characteristics

SUBSCRIBE_TIMEOUT = 5.0


def sid(uuid):
    """Leading group of the UUID, e.g. 'fe2c1236-....' -> 'fe2c1236'."""
    return normalize_uuid_str(uuid).split("-")[0]


def find_char(client, needle, writable=False):
    needle = needle.lower()
    for service in client.services:
        for ch in service.characteristics:
            if needle in ch.uuid.lower():
                if writable and not (
                        "write" in ch.properties
                        or "write-without-response" in ch.properties):
                    continue
                return ch
    return None


# ---------------------------------------------------------------------------
# Candidate orientation decoders (Stage-4-style): print every plausible reading
# of a packet so a moving-head correlation is obvious in the numbers.
# ---------------------------------------------------------------------------
def decode_candidates(data):
    out = []
    n = len(data)
    # float32 LE groups
    if n >= 16 and n % 4 == 0:
        f = struct.unpack_from("<4f", data, 0)
        out.append("f32x4=" + " ".join(f"{v:+.3f}" for v in f))
    if n >= 12 and n % 4 == 0:
        f = struct.unpack_from("<3f", data, 0)
        out.append("f32x3=" + " ".join(f"{v:+.3f}" for v in f))
    # int16 LE groups, scaled as a unit quaternion (/32767) and as raw
    if n >= 8 and n % 2 == 0:
        ints = struct.unpack_from("<4h", data, 0)
        out.append("i16x4=" + " ".join(f"{v:+d}" for v in ints))
        q = [v / 32767.0 for v in ints]
        mag = math.sqrt(sum(c * c for c in q))
        out.append(f"q(/32767)=[{q[0]:+.3f} {q[1]:+.3f} {q[2]:+.3f} {q[3]:+.3f}] |q|={mag:.3f}")
    if n >= 6 and n % 2 == 0:
        ints = struct.unpack_from("<3h", data, 0)
        out.append("i16x3=" + " ".join(f"{v:+d}" for v in ints))
    return out


class Probe:
    def __init__(self):
        self.t0 = time.monotonic()
        self.recent = []          # (t, sid, data) since last clear
        self.all_count = {}       # sid -> total packets
        self.subscribed = set()   # char uuids currently notifying

    def handler(self, s):
        def cb(_sender, data):
            t = time.monotonic() - self.t0
            self.recent.append((t, s, bytes(data)))
            self.all_count[s] = self.all_count.get(s, 0) + 1
            print(f"    [notify] {t:7.3f} {s} | {data.hex(' ')} | len={len(data)}")
        return cb

    def clear(self):
        self.recent = []

    def report_window(self):
        if not self.recent:
            print("    -> no notifications in the 3 s window")
            return
        seen = {}
        for _, s, _ in self.recent:
            seen[s] = seen.get(s, 0) + 1
        print("    -> notifications:", ", ".join(f"{k}x{v}" for k, v in seen.items()))


async def try_subscribe(client, probe, ch, note="", reset=False):
    """Attempt start_notify on ch (with timeout). Returns a status string.

    When `reset` is set, first call stop_notify to clear bleak's internal
    callback registration. bleak's CoreBluetooth backend registers the notify
    callback BEFORE the CCCD write; if that write is rejected ("value's length
    is invalid") the registration lingers, so a naive re-subscribe just raises
    "notifications already started" without actually retrying. stop_notify
    clears it so the retest genuinely re-attempts the CCCD write.
    """
    if ch is None:
        return "char not found"
    if ch.uuid in probe.subscribed:
        return "already subscribed"
    if reset:
        try:
            await client.stop_notify(ch)
        except Exception:
            pass
    try:
        await asyncio.wait_for(
            client.start_notify(ch, probe.handler(sid(ch.uuid))),
            SUBSCRIBE_TIMEOUT)
        probe.subscribed.add(ch.uuid)
        return "OK (subscribed!)"
    except asyncio.TimeoutError:
        return "timeout"
    except Exception as e:
        return f"FAIL: {type(e).__name__}: {e}"


async def write_char(client, ch, payload):
    """Write, trying with-response then without-response. Returns status string."""
    if ch is None:
        return "char not found"
    for resp in (True, False):
        try:
            await client.write_gatt_char(ch, payload, response=resp)
            return f"OK (response={resp})"
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
    return f"FAIL: {last}"


async def retest_locked(client, probe):
    """Re-attempt the two locked head-tracking subscriptions; report each."""
    for needle in HT_LOCKED:
        ch = find_char(client, needle)
        status = await try_subscribe(client, probe, ch, note="(head-tracking)",
                                     reset=True)
        flag = "  <<< UNLOCKED!" if status.startswith("OK") else ""
        print(f"    subscribe {sid(needle)}: {status}{flag}")


async def main(address, move_secs):
    print(f"[probe] connecting to {address} ...")
    async with BleakClient(address, timeout=20.0) as client:
        print(f"[probe] connected: {client.is_connected}\n")
        probe = Probe()

        # --- Step 1: subscribe to every notify/indicate char individually ----
        print("=" * 70)
        print("STEP 1: subscribe to all notify characteristics")
        print("=" * 70)
        notifiable = []
        for service in client.services:
            for ch in service.characteristics:
                if "notify" in ch.properties or "indicate" in ch.properties:
                    notifiable.append(ch)
        for ch in notifiable:
            # Skip the feff char whose descriptor I/O hangs CoreBluetooth.
            status = await try_subscribe(client, probe, ch)
            print(f"  {sid(ch.uuid):>10}  {ch.uuid}: {status}")
        print()

        # --- Step 2+3: blind writes, each followed by a 3 s listen + retest --
        print("=" * 70)
        print("STEP 2: blind writes (3 s listen window after each)")
        print("=" * 70)

        # Read the live nonce now, for the echo experiment (f).
        nonce = b""
        nch = find_char(client, C_FE2C_NONCE)
        if nch is not None:
            try:
                nonce = bytes(await client.read_gatt_char(nch))
                print(f"  [info] fe2c123a nonce this session: {nonce.hex(' ')}\n")
            except Exception as e:
                print(f"  [info] could not read nonce: {e}\n")

        experiments = [
            ("a", C_3A01,      bytes([0x01])),
            ("b", C_3A01,      bytes([0x23, 0x01])),
            ("c", C_FE2C_CMD,  bytes([0x01])),
            ("d", C_FE2C_CMD,  bytes([0x00, 0x01])),
            ("e", C_FE2C_CMD,  bytes([0x01, 0x00])),
            ("f", C_FE2C_CMD,  nonce or bytes(16)),     # echo the nonce
            ("g", C_FE2C_CMD,  bytes(16)),              # 00 * 16
            ("h", HT_WRITE_2,  bytes([0x01])),
            ("i", HT_WRITE_2,  bytes([0x01, 0x00])),
        ]

        for tag, needle, payload in experiments:
            ch = find_char(client, needle, writable=True)
            label = f"{tag}: write {sid(needle)} <- {payload.hex(' ') or '(empty)'}"
            print(f"\n--- {label}")
            probe.clear()
            status = await write_char(client, ch, payload)
            print(f"    write status: {status}")
            await asyncio.sleep(3.0)
            probe.report_window()
            await retest_locked(client, probe)

        # --- Step 4: motion-capture window -----------------------------------
        print("\n" + "=" * 70)
        print(f"STEP 4: motion window - MOVE YOUR HEAD for {move_secs:.0f}s")
        print("=" * 70)
        probe.clear()
        # Try one more subscription pass right before listening.
        await retest_locked(client, probe)
        print(f"\n[probe] recording {move_secs:.0f}s; rotate your head left/right, "
              f"up/down, tilt...\n")
        await asyncio.sleep(move_secs)

        # Decode any head-tracking / fe2c packets captured during the window.
        ht_packets = [(t, s, d) for (t, s, d) in probe.recent
                      if s.startswith("20231219") or s.startswith("fe2c")]
        print("\n" + "=" * 70)
        print("DECODE: candidate orientation readings from head-tracking/fe2c packets")
        print("=" * 70)
        if not ht_packets:
            print("  (no head-tracking / fe2c packets captured during motion)")
        else:
            for t, s, d in ht_packets[:40]:
                print(f"  {t:7.3f} {s} | {d.hex(' ')}")
                for line in decode_candidates(d):
                    print(f"           {line}")

        # --- summary ----------------------------------------------------------
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"  total notifications per characteristic: {probe.all_count or '(none)'}")
        unlocked = []
        for needle in HT_LOCKED:
            ch = find_char(client, needle)
            if ch is not None and ch.uuid in probe.subscribed:
                unlocked.append(needle)
        if unlocked:
            print(f"  HEAD-TRACKING UNLOCKED: {[sid(u) for u in unlocked]}")
        else:
            print("  head-tracking still locked (no blind write authenticated).")
            print("  -> proceed to Stage C (nonce analysis) / Stage D (MitM).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stage B: unauthenticated probe (Jabra)")
    ap.add_argument("address", nargs="?", default=JABRA_ADDRESS)
    ap.add_argument("--move-secs", type=float, default=15.0,
                    help="duration of the final move-your-head capture window")
    args = ap.parse_args()
    asyncio.run(main(args.address, args.move_secs))
