#!/usr/bin/env python3
"""
jabra_mitm_prep.py - Stage D: man-in-the-middle / capture preparation.

Goal: observe exactly what Jabra Sound+ writes to the Fast Pair / head-tracking
characteristics so we can replicate the authentication (see docs/PROTOCOL.md and
docs/CAPTURE.md).

The classic approach is a transparent BLE proxy: the Mac connects to the real
buds as a CENTRAL and simultaneously advertises a clone to which Sound+ connects
as a PERIPHERAL, forwarding and logging every operation. This script:

  * Implements and verifies the CENTRAL half with bleak (this works on macOS).
  * Detects whether a PERIPHERAL-role backend is available and, if not, prints a
    clear explanation of why a transparent MitM is impractical on macOS and what
    to do instead (passive HCI capture, or a Linux/Raspberry-Pi proxy).
  * Prints the exact service/characteristic "mirror map" a clone would need.

    python tools/jabra_mitm_prep.py            # probe roles + print plan
    python tools/jabra_mitm_prep.py --central  # just verify the central link

Why a macOS MitM does not really work (summary; full detail in docs/CAPTURE.md):
  - bleak is CENTRAL-only; it cannot act as a GATT server/peripheral at all.
  - The one peripheral-role option on macOS (`bless`, via CBPeripheralManager)
    cannot fully clone arbitrary services: CoreBluetooth ignores the requested
    attribute handles, won't reproduce the LE-Audio/CSIS services, and cannot
    present a matching BR/EDR (Classic) audio profile.
  - Crucially, the phone is already BONDED to the real buds and uses Fast Pair to
    recognise them; it will not transparently connect to a Mac clone, and the
    head-tracking link is per-bond. So a clone gets no traffic to forward.
  => The reliable capture is PASSIVE: log the phone<->buds link directly
     (Android btsnoop HCI / iOS PacketLogger), or use a Linux box / Raspberry Pi
     (BlueZ supports the peripheral role) if an active proxy is truly needed.
"""

import argparse
import asyncio

from bleak import BleakClient
from bleak.uuids import normalize_uuid_str

JABRA_ADDRESS = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

# Characteristics a proxy/clone must mirror and log writes to. These are the
# Fast Pair + head-tracking attributes that matter for authentication.
MIRROR = [
    ("fe2c1234", "Fast Pair Key-based Pairing (seeker writes encrypted request)"),
    ("fe2c1235", "Fast Pair Passkey"),
    ("fe2c1236", "Fast Pair Account Key (write)"),
    ("fe2c1237", "Fast Pair Additional Data"),
    ("fe2c123a", "FMDN Beacon Actions (read nonce, write HMAC-authed command)"),
    ("20231219-1730-0000-0000-000000000001", "head-tracking notify"),
    ("20231219-1730-0000-0000-000000000002", "head-tracking write/command"),
    ("20231219-1730-0000-0000-000000000003", "head-tracking notify/read"),
]


def sid(uuid):
    return normalize_uuid_str(uuid).split("-")[0]


def peripheral_backend():
    """Return the name of an available BLE peripheral-role backend, or None."""
    try:
        import bless  # noqa: F401
        return "bless"
    except Exception:
        return None


async def verify_central(address):
    """Confirm the central half works and the mirror targets exist."""
    print(f"[central] connecting to {address} ...")
    try:
        async with BleakClient(address, timeout=20.0) as client:
            print(f"[central] connected: {client.is_connected}")
            present = {}
            for service in client.services:
                for ch in service.characteristics:
                    present[ch.uuid.lower()] = ch.properties
            print("[central] mirror-map characteristics on the real device:")
            for needle, role in MIRROR:
                hit = next((u for u in present if needle.lower() in u), None)
                if hit:
                    print(f"    OK  {sid(hit):>10}  [{','.join(present[hit])}]  {role}")
                else:
                    print(f"    --  {needle}: not found  ({role})")
            return True
    except Exception as e:
        print(f"[central] connection failed: {e}")
        return False


def print_plan(have_peripheral):
    print("\n" + "=" * 72)
    print("MitM FEASIBILITY ON THIS HOST")
    print("=" * 72)
    print(f"  central role (bleak)      : available")
    print(f"  peripheral role backend   : "
          f"{have_peripheral or 'NOT available (no bless installed)'}")
    print()
    if not have_peripheral:
        print("  A transparent BLE MitM needs a GATT-server (peripheral) role to")
        print("  impersonate the buds to Sound+. bleak cannot do this; install")
        print("  `bless` for a CoreBluetooth peripheral, but see the caveats below.")
    print("""
  Even with a peripheral backend, a transparent MitM on macOS is impractical:
    * CoreBluetooth won't let you fix attribute handles or clone the LE-Audio /
      CSIS services, so the clone is not a faithful copy.
    * The phone is already BONDED to the real buds (Fast Pair); it recognises the
      buds by identity and will not connect to a Mac clone without re-pairing,
      and head tracking is gated per-bond. The clone receives nothing to forward.

  RECOMMENDED INSTEAD (see docs/CAPTURE.md):
    1. PASSIVE capture of the real phone<->buds link while you toggle head
       tracking in Sound+:
         - Android: Developer Options -> enable "Bluetooth HCI snoop log",
           reproduce, pull btsnoop_hci.log, open in Wireshark, filter on the
           fe2c / 20231219 handles.
         - iOS: install Apple's Bluetooth logging profile (PacketLogger, from
           "Additional Tools for Xcode") on the iPhone via a Mac, capture, export.
       This shows the EXACT bytes Sound+ writes to unlock head tracking.
    2. If an ACTIVE proxy is genuinely required, run it on Linux / a Raspberry Pi:
       BlueZ supports the peripheral role properly (e.g. `bluezero`/`python-gatt`
       server, or `gattacker`/`btlejack`-style tooling). The Pi connects to the
       buds as central and re-advertises a clone for the phone.
    3. App-side instrumentation: hook Sound+ with Frida (rooted Android / emulator)
       on the BLE write + the HMAC/crypto call to read the account key directly.
  """)


async def main(args):
    have_peripheral = peripheral_backend()
    if args.central:
        await verify_central(args.address)
        return
    await verify_central(args.address)
    print_plan(have_peripheral)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stage D: MitM/capture prep (Jabra)")
    ap.add_argument("address", nargs="?", default=JABRA_ADDRESS)
    ap.add_argument("--central", action="store_true",
                    help="only verify the central link + mirror map, then exit")
    args = ap.parse_args()
    asyncio.run(main(args))
