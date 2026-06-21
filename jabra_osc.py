#!/usr/bin/env python3
"""
jabra_osc.py - Jabra Elite 10 Gen 2 head tracker with OSC output.

Connects to the Jabra Elite 10 Gen 2 over BLE, (once authenticated) subscribes to
its head-tracking service and emits the orientation as OSC for IEM SceneRotator,
SPARTA/Atmoky (/ypr) and APL Virtuoso - the same output format as the sibling
wavesnx-headtracker and mmrl-headtracker bridges.

    /SceneRotator/quaternions  [qw qx qy qz]   IEM Plugin Suite
    /ypr                       [yaw pitch roll] (deg)  SPARTA/Atmoky/dearVR
    /Virtuoso/quat             [qw qx qy qz]   APL Virtuoso

STATUS: the orientation service `20231219-...` is locked behind Google Fast Pair
/ FMDN account-key authentication (see docs/PROTOCOL.md). This bridge has the
full data path ready - scan, connect, subscribe, decode, OSC, tare, reconnect -
but `authenticate()` is the open hook: without the Fast Pair account key it
cannot unlock the stream, and the exact unlock command must be confirmed by
capturing the Sound+ handshake (see docs/CAPTURE.md). Run with `--account-key`
for the experimental FMDN flow when the account key is available.

Requires: bleak, python-osc  (pip install bleak python-osc)
"""

import argparse
import asyncio
import hashlib
import hmac
import math
import signal
import struct
import sys
import time

from bleak import BleakScanner, BleakClient
from bleak.uuids import normalize_uuid_str
from pythonosc.udp_client import SimpleUDPClient


# ---------------------------------------------------------------------------
# GATT (see docs/PROTOCOL.md)
# ---------------------------------------------------------------------------
HT_SERVICE  = "20231219-1730-0000-0000-000000000000"
HT_NOTIFY_1 = "20231219-1730-0000-0000-000000000001"   # orientation notify
HT_WRITE_2  = "20231219-1730-0000-0000-000000000002"   # command/start (write)
HT_NOTIFY_3 = "20231219-1730-0000-0000-000000000003"   # orientation/state notify
FP_BEACON   = "fe2c123a"   # FMDN Beacon Actions: read nonce, write HMAC-authed cmd
FP_MODEL_ID = "fe2c1233"   # Fast Pair Model ID (read)
BATTERY     = "00002a19-0000-1000-8000-00805f9b34fb"

NAME_HINTS = ("jabra elite 10", "jabra")
SERVICE_HINTS = (HT_NOTIFY_1, "0000fe2c-0000-1000-8000-00805f9b34fb")

# Orientation decode is UNVERIFIED (stream still locked). Best guess, matching the
# Nx layout: 4x int16 LE quaternion, value = raw/32767. Replaced once real
# packets are captured (tools/jabra_listen.py prints every candidate decoding).
QUAT_SCALE = 32767.0

AUTH_HELP = """
[auth] The head-tracking service is locked (Google Fast Pair / FMDN account-key
       authentication). To unlock it you need the 16-byte Fast Pair account key
       your phone obtained when it paired these buds, and the exact unlock command
       Sound+ sends. See docs/CAPTURE.md to capture the handshake, then:
         python jabra_osc.py --account-key <32-hex-chars>
"""


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
osc = None
tare_quat = None
tare_request = False
last_print = 0.0


# ---------------------------------------------------------------------------
# Quaternion math (shared with the Nx/MMRL bridges)
# ---------------------------------------------------------------------------
def quat_conjugate(q):
    w, x, y, z = q
    return (w, -x, -y, -z)


def quat_multiply(a, b):
    aw, ax, ay, az = a
    bw, bx, by, bz = b
    return (
        aw * bw - ax * bx - ay * by - az * bz,
        aw * bx + ax * bw + ay * bz - az * by,
        aw * by - ax * bz + ay * bw + az * bx,
        aw * bz + ax * by - ay * bx + az * bw,
    )


def quat_normalize(q):
    n = math.sqrt(sum(c * c for c in q)) or 1.0
    return tuple(c / n for c in q)


def quat_to_ypr(q):
    """Quaternion (w,x,y,z) -> yaw/pitch/roll in degrees (ZYX)."""
    w, x, y, z = q
    sinr_cosp = 2.0 * (w * x + y * z)
    cosr_cosp = 1.0 - 2.0 * (x * x + y * y)
    roll = math.atan2(sinr_cosp, cosr_cosp)
    sinp = max(-1.0, min(1.0, 2.0 * (w * y - z * x)))
    pitch = math.asin(sinp)
    siny_cosp = 2.0 * (w * z + x * y)
    cosy_cosp = 1.0 - 2.0 * (y * y + z * z)
    yaw = math.atan2(siny_cosp, cosy_cosp)
    return math.degrees(yaw), math.degrees(pitch), math.degrees(roll)


def decode_packet(data):
    """Decode a head-tracking notification into a quaternion (w,x,y,z).

    UNVERIFIED placeholder: assumes 4x int16 LE scaled by 1/32767. Replace once
    the real packet layout is known (see docs/PROTOCOL.md / tools/jabra_listen.py).
    Returns a normalised quaternion or None.
    """
    if len(data) < 8:
        return None
    q = [v / QUAT_SCALE for v in struct.unpack_from("<4h", data, 0)]
    return quat_normalize(tuple(q))


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def process_quaternion(q):
    global tare_quat, tare_request, last_print
    if tare_request:
        tare_quat = q
        tare_request = False
        print("\n[tare] heading zeroed")
    if tare_quat is not None:
        q = quat_multiply(quat_conjugate(tare_quat), q)

    qw, qx, qy, qz = q
    yaw, pitch, roll = quat_to_ypr(q)
    osc.send_message("/SceneRotator/quaternions", [qw, qx, qy, qz])
    osc.send_message("/ypr", [yaw, pitch, roll])
    osc.send_message("/Virtuoso/quat", [qw, qx, qy, qz])

    now = time.monotonic()
    if now - last_print >= 0.2:
        last_print = now
        print(f"\r  yaw {yaw:+7.1f}  pitch {pitch:+7.1f}  roll {roll:+7.1f}   ",
              end="", flush=True)


def notification_handler(_sender, data):
    q = decode_packet(bytes(data))
    if q is not None:
        process_quaternion(q)


# ---------------------------------------------------------------------------
# Authentication (the open hook - see docs/PROTOCOL.md and docs/CAPTURE.md)
# ---------------------------------------------------------------------------
def fmdn_auth_segment(account_key, nonce, data_id, payload=b"",
                      version=0x00, flags=0x01):
    """First 8 bytes of HMAC-SHA256 over the FMDN Beacon Actions input.

    Per the Fast Pair FMDN spec the seeker proves account-key knowledge with
        HMAC-SHA256(account_key, version || nonce || data_id || data_len || payload || flags)[:8]
    The exact field widths/order for THIS device's head-tracking unlock are not
    yet confirmed (capture needed); this helper implements the documented shape so
    it can be matched against a real capture.
    """
    msg = (bytes([version]) + nonce + bytes([data_id, len(payload)])
           + payload + bytes([flags]))
    return hmac.new(account_key, msg, hashlib.sha256).digest()[:8]


def find_char(client, needle):
    needle = needle.lower()
    for service in client.services:
        for ch in service.characteristics:
            if needle in ch.uuid.lower():
                return ch
    return None


async def authenticate(client, account_key):
    """Unlock the head-tracking service. Returns True on (apparent) success.

    Without an account key this cannot proceed and explains why. With a key it
    runs the EXPERIMENTAL FMDN flow: read the fe2c123a nonce, derive the auth
    segment, and test whether the head-tracking service will now subscribe. The
    precise unlock write must be confirmed from a captured handshake.
    """
    if not account_key:
        print(AUTH_HELP)
        return False

    nch = find_char(client, FP_BEACON)
    if nch is None:
        print("[auth] fe2c123a (Beacon Actions) not found")
        return False
    nonce = bytes(await client.read_gatt_char(nch))
    print(f"[auth] fe2c123a nonce: {nonce.hex(' ')}")
    seg = fmdn_auth_segment(account_key, nonce, data_id=0x00)
    print(f"[auth] derived HMAC-SHA256 auth segment: {seg.hex(' ')}")
    print("[auth] EXPERIMENTAL: exact unlock command unconfirmed; attempting "
          "head-tracking subscription to test the link state.")
    # The actual unlock write goes here once the capture confirms it, e.g.:
    #   await client.write_gatt_char(nch, build_beacon_action(seg, ...), response=True)
    return False


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
async def scan_and_pick(scan_time, show_all=False):
    while True:
        print(f"[scan] scanning {scan_time:.0f}s for Jabra Elite devices...")
        discovered = await BleakScanner.discover(timeout=scan_time, return_adv=True)
        items = list(discovered.values())

        def is_jabra(dev, adv):
            name = (adv.local_name or dev.name or "").lower()
            if any(h in name for h in NAME_HINTS):
                return True
            uuids = [u.lower() for u in (adv.service_uuids or [])]
            return any(h.lower() in uuids for h in SERVICE_HINTS)

        found = [(d, a) for (d, a) in items if is_jabra(d, a)]
        if not found and show_all:
            found = sorted(items, key=lambda da: -(da[1].rssi or -999))
        if not found:
            print("[scan] no Jabra found. Take a bud out of the case, make sure it")
            print("       is awake, and quit/disconnect other apps. --all lists everything.")
            choice = input("Press Enter to rescan, or 'q' to quit: ").strip().lower()
            if choice == "q":
                return None
            continue

        print("\nFound devices:")
        for i, (d, a) in enumerate(found):
            name = a.local_name or d.name or "(no name)"
            print(f"  [{i}] {name:<22} {d.address}   rssi {a.rssi}")
        sel = input("\nSelect device number (r=rescan, q=quit): ").strip().lower()
        if sel == "q":
            return None
        if sel == "r":
            continue
        if sel.isdigit() and int(sel) < len(found):
            return found[int(sel)][0].address
        print("Invalid selection.")


# ---------------------------------------------------------------------------
# Streaming session
# ---------------------------------------------------------------------------
async def stream(address, account_key):
    disconnected = asyncio.Event()

    def on_disconnect(_client):
        print("\n[ble] disconnected")
        disconnected.set()

    async with BleakClient(address, disconnected_callback=on_disconnect) as client:
        print(f"[ble] connected to {address}")
        try:
            raw = await client.read_gatt_char(BATTERY)
            print(f"[battery] {raw[0]}%")
        except Exception as e:
            print(f"[battery] unavailable ({e})")

        ok = await authenticate(client, account_key)
        if not ok:
            print("[ble] head-tracking locked; cannot stream. Exiting session.")
            return

        # Subscribe to whichever head-tracking notify channel delivers data.
        subscribed = []
        for needle in (HT_NOTIFY_1, HT_NOTIFY_3):
            ch = find_char(client, needle)
            if ch is None:
                continue
            try:
                await client.start_notify(ch, notification_handler)
                subscribed.append(ch)
            except Exception as e:
                print(f"[ble] subscribe {normalize_uuid_str(ch.uuid).split('-')[0]} "
                      f"failed: {e}")
        if not subscribed:
            print("[ble] no head-tracking channel subscribed; exiting session.")
            return

        print("[jabra] streaming orientation.")
        print("     Press Enter to tare (zero the heading).  Ctrl-C to quit.\n")
        try:
            await disconnected.wait()
        finally:
            if client.is_connected:
                for ch in subscribed:
                    try:
                        await client.stop_notify(ch)
                    except Exception:
                        pass


async def tare_listener():
    global tare_request
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if line == "":
            return
        tare_request = True


async def run(address, port, account_key):
    global osc
    osc = SimpleUDPClient("127.0.0.1", port)
    print(f"[osc] sending to 127.0.0.1:{port}  "
          f"(/SceneRotator/quaternions, /ypr, /Virtuoso/quat)")

    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, task.cancel)
        except (NotImplementedError, RuntimeError):
            pass

    tare_task = asyncio.create_task(tare_listener())
    try:
        while True:
            try:
                await stream(address, account_key)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"\n[ble] connection error: {e}")
            print("[ble] reconnecting in 3 s...")
            await asyncio.sleep(3)
    finally:
        tare_task.cancel()


def main():
    parser = argparse.ArgumentParser(
        description="Jabra Elite 10 Gen 2 head tracker with OSC output")
    parser.add_argument("--device", metavar="ADDR",
                        help="BLE address / CoreBluetooth UUID (skips scanning)")
    parser.add_argument("--port", type=int, default=8000,
                        help="OSC UDP port on localhost (default: 8000)")
    parser.add_argument("--scan-time", type=float, default=8.0)
    parser.add_argument("--all", action="store_true", dest="show_all",
                        help="if no Jabra is found, list all BLE devices to pick from")
    parser.add_argument("--account-key", metavar="HEX",
                        help="16-byte Fast Pair account key (32 hex chars) for the "
                             "experimental FMDN unlock (see docs/CAPTURE.md)")
    args = parser.parse_args()

    account_key = None
    if args.account_key:
        account_key = bytes.fromhex(args.account_key)
        if len(account_key) != 16:
            print("[error] --account-key must be 16 bytes (32 hex chars).")
            sys.exit(1)

    async def main_async():
        address = args.device
        if not address:
            address = await scan_and_pick(args.scan_time, show_all=args.show_all)
            if not address:
                print("No device selected. Exiting.")
                return
        await run(address, args.port, account_key)

    try:
        asyncio.run(main_async())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[exit] stopping and disconnecting...")


if __name__ == "__main__":
    main()
