#!/usr/bin/env python3
"""
stage1_scan.py - Stage 1: BLE device discovery (Jabra Elite 10 Gen 2).

Scans for BLE devices and prints, for each one found: advertised name, the
CoreBluetooth UUID (macOS) or MAC address (Linux/Windows), RSSI, all advertised
service UUIDs, and any manufacturer data. Highlights likely Jabra devices.

Note its UUID/address from the output for the later stages.

    python tools/stage1_scan.py                # 10 s scan
    python tools/stage1_scan.py --scan-time 15

NOTE: the Jabra advertises over BLE only in certain states. When it is connected
to a phone over Bluetooth Classic (for audio) it may not show a BLE advertisement
at all. Quit Jabra Sound+, disconnect the buds from the phone, take one bud out
of the case, and re-scan.
"""

import argparse
import asyncio

from bleak import BleakScanner

# Substrings the Jabra is known/likely to advertise. Matching is
# case-insensitive and substring-based so minor firmware naming differences hit.
NAME_HINTS = ("jabra", "elite 10")

# Custom service UUIDs that mark this as the head-tracking-capable Jabra.
SERVICE_HINTS = (
    "0000fe2c-0000-1000-8000-00805f9b34fb",   # Jabra proprietary service
    "20231219-1730-0000-0000-000000000001",   # head-tracking service
)


def looks_like_jabra(name, service_uuids, mfg_data):
    n = (name or "").lower()
    if any(h in n for h in NAME_HINTS):
        return True
    uuids = [u.lower() for u in (service_uuids or [])]
    return any(h in uuids for h in SERVICE_HINTS)


async def main(scan_time):
    print(f"[scan] scanning {scan_time:.0f}s for BLE devices "
          f"(quit Jabra Sound+ and disconnect the buds from your phone)...\n")

    # return_adv=True yields (BLEDevice, AdvertisementData) tuples, exposing
    # service UUIDs, manufacturer data and the live RSSI, not just the name.
    discovered = await BleakScanner.discover(timeout=scan_time, return_adv=True)
    items = list(discovered.values())

    if not items:
        print("[scan] no BLE devices found at all. Bluetooth off, or no devices "
              "advertising?")
        return

    # Strongest signal first; a nearby device sorts near the top.
    items.sort(key=lambda da: -(da[1].rssi if da[1].rssi is not None else -999))

    print(f"Found {len(items)} device(s):\n")
    candidates = []
    for dev, adv in items:
        name = adv.local_name or dev.name or "(no name)"
        rssi = adv.rssi
        svc = adv.service_uuids or []
        mfg = adv.manufacturer_data or {}

        is_jabra = looks_like_jabra(name, svc, mfg)
        if is_jabra:
            candidates.append((dev, adv))

        marker = "  <-- LIKELY JABRA" if is_jabra else ""
        print(f"{'='*70}")
        print(f"  name     : {name}{marker}")
        print(f"  address  : {dev.address}")
        print(f"  rssi     : {rssi} dBm")
        if svc:
            print(f"  services : ")
            for u in svc:
                print(f"             {u}")
        else:
            print(f"  services : (none advertised)")
        if mfg:
            print(f"  mfg data : ")
            for cid, payload in mfg.items():
                # company id is little-endian in the advertisement
                print(f"             company 0x{cid:04x}: {payload.hex()}")
        sd = adv.service_data or {}
        if sd:
            print(f"  svc data : ")
            for u, payload in sd.items():
                print(f"             {u}: {payload.hex()}")
        if adv.tx_power is not None:
            print(f"  tx power : {adv.tx_power}")

    print(f"{'='*70}\n")

    if candidates:
        print(f"[scan] {len(candidates)} likely Jabra device(s):")
        for dev, adv in candidates:
            name = adv.local_name or dev.name or "(no name)"
            print(f"        {name}   address = {dev.address}   rssi {adv.rssi}")
        print("\n[next] Copy the address above into stage2_enumerate.py "
              "(JABRA_ADDRESS).")
    else:
        print("[scan] No obvious Jabra by name/service. The buds advertise over "
              "BLE only in certain states;\n       take one bud out of the case, "
              "make sure it is not connected to a phone, and re-scan.\n"
              "       Custom 128-bit service UUIDs (fe2c, 20231219-...) are the "
              "reliable clue.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stage 1: BLE device discovery (Jabra)")
    ap.add_argument("--scan-time", type=float, default=10.0,
                    help="scan duration in seconds (default: 10)")
    args = ap.parse_args()
    asyncio.run(main(args.scan_time))
