#!/usr/bin/env python3
"""
stage2_enumerate.py - Stage 2: GATT enumeration (Jabra Elite 10 Gen 2).

Connects to a device by address/UUID and prints the complete GATT map: every
service, every characteristic with its properties (read/write/notify/indicate),
and the raw value of everything readable (hex + UTF-8 attempt). Descriptors are
listed too, with the Client Characteristic Configuration and User Description
read when present.

This is the full inventory of what the device exposes.

    python tools/stage2_enumerate.py <ADDRESS-OR-UUID>
    python tools/stage2_enumerate.py            # uses JABRA_ADDRESS below

HANG FIX (this version): the Jabra exposes a characteristic in the `feff`
service (`8b5b80c0-...`) whose descriptor read never returns on macOS
CoreBluetooth, which froze the original enumeration indefinitely. Every read
here (characteristic value AND descriptor) is wrapped in a 2-second
asyncio.wait_for, so a stuck read is reported as `<timeout>` and enumeration
continues instead of hanging.
"""

import argparse
import asyncio
import sys

from bleak import BleakClient
from bleak.uuids import normalize_uuid_str

# The Jabra Elite 10 Gen 2 as it enumerates on this Mac. macOS CoreBluetooth
# addresses peripherals by a per-host UUID (not a MAC); this value differs on
# other machines. Re-run tools/stage1_scan.py to obtain it for another host.
JABRA_ADDRESS = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"  # set to your device address (per-Mac UUID on macOS, shown during a scan)

# How long to wait on any single read before giving up and moving on. The feff
# descriptor read hangs forever without this.
READ_TIMEOUT = 2.0

# A few well-known UUIDs (16-bit assigned numbers + Jabra/head-tracking customs)
# so the output is readable without a lookup.
KNOWN = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002902-0000-1000-8000-00805f9b34fb": "Client Characteristic Config",
    "00002901-0000-1000-8000-00805f9b34fb": "Characteristic User Description",
    # Jabra proprietary service + head-tracking service (working hypotheses).
    "0000fe2c-0000-1000-8000-00805f9b34fb": "Jabra proprietary (fe2c)",
    "20231219-1730-0000-0000-000000000001": "HeadTracking data? (notify)",
    "20231219-1730-0000-0000-000000000003": "HeadTracking data? (read,notify)",
}


def label(uuid):
    return KNOWN.get(normalize_uuid_str(uuid), "")


def show_value(raw):
    hexs = raw.hex(" ")
    try:
        txt = raw.decode("utf-8")
        printable = "".join(c if 32 <= ord(c) < 127 else "." for c in txt)
        return f"{hexs}   utf8={printable!r}   len={len(raw)}"
    except Exception:
        return f"{hexs}   len={len(raw)}"


async def read_char(client, ch):
    """Read a characteristic value with a hard timeout. Returns (ok, payload)."""
    try:
        raw = await asyncio.wait_for(client.read_gatt_char(ch), READ_TIMEOUT)
        return True, show_value(raw)
    except asyncio.TimeoutError:
        return False, f"<timeout: no response in {READ_TIMEOUT:.0f}s>"
    except Exception as e:
        return False, f"<read failed: {e}>"


async def read_descriptor(client, handle):
    """Read a descriptor value with a hard timeout. Returns (ok, payload)."""
    try:
        raw = await asyncio.wait_for(
            client.read_gatt_descriptor(handle), READ_TIMEOUT)
        return True, show_value(raw)
    except asyncio.TimeoutError:
        return False, f"<timeout: no response in {READ_TIMEOUT:.0f}s>"
    except Exception as e:
        return False, f"<read failed: {e}>"


async def main(address):
    print(f"[gatt] connecting to {address} ...")
    async with BleakClient(address, timeout=20.0) as client:
        print(f"[gatt] connected: {client.is_connected}\n")

        for service in client.services:
            slabel = label(service.uuid)
            print("=" * 78)
            print(f"SERVICE  {service.uuid}  {slabel}")
            print("=" * 78)

            for ch in service.characteristics:
                props = ",".join(ch.properties)
                clabel = label(ch.uuid)
                print(f"  CHAR   {ch.uuid}  [{props}]"
                      + (f"  {clabel}" if clabel else ""))
                print(f"         handle={ch.handle}")

                if "read" in ch.properties:
                    ok, payload = await read_char(client, ch)
                    print(f"         value: {payload}")

                for d in ch.descriptors:
                    dlabel = label(d.uuid)
                    ok, payload = await read_descriptor(client, d.handle)
                    print(f"         desc {d.uuid}"
                          + (f" ({dlabel})" if dlabel else "")
                          + f": {payload}")
            print()

        print("[gatt] enumeration complete.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stage 2: GATT enumeration (Jabra)")
    ap.add_argument("address", nargs="?", default=JABRA_ADDRESS,
                    help="device address / CoreBluetooth UUID")
    args = ap.parse_args()
    if not args.address:
        print("Provide an address: python tools/stage2_enumerate.py <ADDRESS>")
        sys.exit(1)
    asyncio.run(main(args.address))
