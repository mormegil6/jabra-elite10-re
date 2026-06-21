#!/usr/bin/env python3
"""
jabra_hci_parse.py - parse an Android btsnoop HCI log for the Jabra handshake.

Reads a `btsnoop_hci.log` captured on the phone and prints the ATT operations on
the Jabra's Fast Pair (`fe2c...`) and head-tracking (`20231219-...`) characteristics,
so we can see the authentication handshake and the orientation packet format.

Two important realities this parser handles:

  * Multiple devices share one capture (earbuds L+R, watches, etc.), each on its
    own ACL connection handle with an INDEPENDENT attribute-handle space. We group
    by ACL handle and auto-identify the Jabra connection(s).
  * GATT handles are device-side and are NOT the synthetic handles bleak reports
    on macOS. So we build the handle->UUID map from the capture's own GATT
    DISCOVERY (ReadByGroupType / ReadByType / FindInformation responses). This
    only works if the capture includes discovery -- i.e. a FRESH PAIRING, not a
    bonded reconnect (Android caches the GATT of bonded devices and skips it).

    python tools/jabra_hci_parse.py btsnoop_hci.log
    python tools/jabra_hci_parse.py btsnoop_hci.log --all      # all connections
    python tools/jabra_hci_parse.py btsnoop_hci.log --map      # just the handle map

No external dependencies; self-contained btsnoop + HCI/ACL/L2CAP/ATT parser.
"""

import argparse
import struct
import sys

# Known UUIDs -> human label (16-bit normalised to the full base for matching).
def norm(u):
    u = u.lower()
    return u

KNOWN_UUID = {
    "2a19": "Battery Level",
    "fe2c1233-8366-4814-8eb0-01de32100bea": "FastPair Model ID",
    "fe2c1234-8366-4814-8eb0-01de32100bea": "FastPair Key-based Pairing",
    "fe2c1235-8366-4814-8eb0-01de32100bea": "FastPair Passkey",
    "fe2c1236-8366-4814-8eb0-01de32100bea": "FastPair Account Key",
    "fe2c1237-8366-4814-8eb0-01de32100bea": "FastPair Additional Data",
    "fe2c1239-8366-4814-8eb0-01de32100bea": "FastPair/FMDN ext (1239)",
    "fe2c123a-8366-4814-8eb0-01de32100bea": "FMDN Beacon Actions (nonce/auth)",
    "20231219-1730-0000-0000-000000000000": "HEAD-TRACKING service",
    "20231219-1730-0000-0000-000000000001": "HEAD-TRACKING notify (0001)",
    "20231219-1730-0000-0000-000000000002": "HEAD-TRACKING write (0002)",
    "20231219-1730-0000-0000-000000000003": "HEAD-TRACKING notify/read (0003)",
    "2902": "CCCD (subscribe)",
}
# Substrings that mark a connection as the Jabra.
JABRA_MARKERS = ("fe2c123", "20231219-1730")

ATT_OPCODES = {
    0x01: "ErrorRsp", 0x04: "FindInfoReq", 0x05: "FindInfoRsp",
    0x08: "ReadByTypeReq", 0x09: "ReadByTypeRsp",
    0x0A: "ReadReq", 0x0B: "ReadRsp", 0x0C: "ReadBlobReq", 0x0D: "ReadBlobRsp",
    0x10: "ReadByGroupReq", 0x11: "ReadByGroupRsp",
    0x12: "WriteReq", 0x13: "WriteRsp", 0x52: "WriteCmd",
    0x1B: "Notify", 0x1D: "Indicate", 0x1E: "Confirm",
}
CHAR_DECL_UUID = 0x2803   # Characteristic declaration


def uuid_from_le(b):
    """ATT UUID bytes (LE) -> canonical string (16-bit short or full 128-bit)."""
    if len(b) == 2:
        return f"{b[1]:02x}{b[0]:02x}"
    if len(b) == 16:
        r = b[::-1]
        return (f"{r[0:4].hex()}-{r[4:6].hex()}-{r[6:8].hex()}-"
                f"{r[8:10].hex()}-{r[10:16].hex()}")
    return b.hex()


def label_uuid(u):
    return KNOWN_UUID.get(u, "")


def read_btsnoop(path):
    with open(path, "rb") as fh:
        hdr = fh.read(16)
        if hdr[:8] != b"btsnoop\x00":
            print(f"[error] not a btsnoop file: {hdr[:8]!r}")
            sys.exit(1)
        _, datalink = struct.unpack(">II", hdr[8:16])
        while True:
            rec = fh.read(24)
            if len(rec) < 24:
                break
            orig, incl, flags, drops, ts = struct.unpack(">IIIIq", rec)
            data = fh.read(incl)
            if len(data) < incl:
                break
            yield ts, flags, datalink, data


class L2Reasm:
    def __init__(self):
        self.buf = {}

    def feed(self, h, pb, payload):
        out = []
        if pb in (0x00, 0x02):
            if len(payload) < 4:
                return out
            l2len, cid = struct.unpack_from("<HH", payload, 0)
            body = payload[4:]
            if len(body) >= l2len:
                out.append((cid, body[:l2len]))
            else:
                self.buf[h] = [l2len - len(body), cid, bytearray(body)]
        elif pb == 0x01:
            st = self.buf.get(h)
            if st:
                need, cid, acc = st
                acc += payload[:need]
                need -= len(payload[:need])
                if need <= 0:
                    out.append((cid, bytes(acc)))
                    self.buf.pop(h, None)
                else:
                    st[0] = need
        return out


def iter_att(path):
    """Yield (rel_t, acl_handle, direction, att_pdu)."""
    reasm = L2Reasm()
    t0 = None
    for ts, flags, datalink, data in read_btsnoop(path):
        if t0 is None:
            t0 = ts
        if not data:
            continue
        if datalink == 1002:
            ptype, body = data[0], data[1:]
        else:
            ptype, body = 0x02, data
        if ptype != 0x02 or len(body) < 4:
            continue
        hf, alen = struct.unpack_from("<HH", body, 0)
        acl = hf & 0x0FFF
        pb = (hf >> 12) & 0x3
        for cid, l2 in reasm.feed(acl, pb, body[4:4 + alen]):
            if cid == 0x0004 and l2:
                direction = "C>H" if (flags & 0x01) else "H>C"
                yield (ts - t0) / 1e6, acl, direction, l2


def build_maps(path):
    """First pass: per-ACL handle->UUID map from discovery; flag Jabra conns."""
    val_uuid = {}       # acl -> {value_handle: uuid}
    cccd = {}           # acl -> {cccd_handle: char_value_handle}
    jabra = set()
    pending_decl = {}   # acl -> last char declaration's value handle (for FindInfo CCCDs)

    for rel, acl, d, l2 in iter_att(path):
        op = l2[0]
        m = val_uuid.setdefault(acl, {})
        if op == 0x09:                       # ReadByType Rsp (char declarations)
            ln = l2[1]
            for i in range(2, len(l2), ln):
                ent = l2[i:i + ln]
                if len(ent) < ln:
                    break
                # char decl value = [props(1), value_handle(2), uuid(2/16)]
                vhandle = struct.unpack_from("<H", ent, 1)[0]
                u = uuid_from_le(ent[3:])
                m[vhandle] = u
                if any(k in u for k in JABRA_MARKERS):
                    jabra.add(acl)
        elif op == 0x05:                     # FindInfo Rsp (handle+uuid incl CCCDs)
            fmt = l2[1]
            step = 4 if fmt == 0x01 else 18
            for i in range(2, len(l2), step):
                ent = l2[i:i + step]
                if len(ent) < step:
                    break
                h = struct.unpack_from("<H", ent, 0)[0]
                u = uuid_from_le(ent[2:])
                if u == "2902":
                    cccd.setdefault(acl, {})[h] = None
                else:
                    m.setdefault(h, u)
                if any(k in u for k in JABRA_MARKERS):
                    jabra.add(acl)
        elif op == 0x11:                     # ReadByGroupType Rsp (services)
            ln = l2[1]
            for i in range(2, len(l2), ln):
                ent = l2[i:i + ln]
                if len(ent) < ln:
                    break
                u = uuid_from_le(ent[4:])
                if any(k in u for k in JABRA_MARKERS):
                    jabra.add(acl)
    return val_uuid, cccd, jabra


def main():
    ap = argparse.ArgumentParser(description="Parse btsnoop for the Jabra handshake")
    ap.add_argument("logfile")
    ap.add_argument("--all", action="store_true",
                    help="show every connection, not just identified Jabra ones")
    ap.add_argument("--map", action="store_true",
                    help="only print the discovered handle->UUID map, then exit")
    args = ap.parse_args()

    val_uuid, cccd, jabra = build_maps(args.logfile)

    if not jabra and not args.all:
        print("[warn] no Jabra connection identified by UUID. This usually means")
        print("       the capture is a BONDED RECONNECT (cached GATT, no discovery).")
        print("       Re-capture during a FRESH PAIRING (forget + re-pair) so the")
        print("       fe2c / 20231219 UUIDs and the auth handshake are recorded.")
        print("       Showing all connections anyway:\n")
        args.all = True

    if args.map:
        for acl in sorted(val_uuid):
            tag = "  <-- JABRA" if acl in jabra else ""
            print(f"\nACL 0x{acl:04x}{tag}")
            for h in sorted(val_uuid[acl]):
                u = val_uuid[acl][h]
                print(f"  h0x{h:04x} ({h:5d}): {u}  {label_uuid(u)}")
        return

    def name_for(acl, handle):
        u = val_uuid.get(acl, {}).get(handle)
        if u:
            lab = label_uuid(u)
            return f"{u} {('['+lab+']') if lab else ''}".strip()
        # maybe a CCCD just after a known value handle
        u2 = val_uuid.get(acl, {}).get(handle - 1)
        if u2:
            return f"CCCD of {u2} {('['+label_uuid(u2)+']') if label_uuid(u2) else ''}".strip()
        return f"handle 0x{handle:04x}"

    pending_read = {}
    nonce = {}
    targets = jabra if not args.all else None
    for rel, acl, d, l2 in iter_att(args.logfile):
        if targets is not None and acl not in targets:
            continue
        op = l2[0]
        opn = ATT_OPCODES.get(op, f"op0x{op:02x}")
        handle = None
        val = b""
        if op in (0x0A, 0x0C):
            handle = struct.unpack_from("<H", l2, 1)[0]
            pending_read[acl] = handle
        elif op in (0x0B, 0x0D):
            handle = pending_read.get(acl)
            val = l2[1:]
        elif op in (0x12, 0x52):
            handle = struct.unpack_from("<H", l2, 1)[0]
            val = l2[3:]
        elif op in (0x1B, 0x1D):
            handle = struct.unpack_from("<H", l2, 1)[0]
            val = l2[3:]
        else:
            continue
        if handle is None:
            continue
        u = val_uuid.get(acl, {}).get(handle, "")
        label = name_for(acl, handle)

        extra = ""
        if "fe2c123a" in u and op in (0x0B, 0x0D):
            nonce[acl] = val
            extra = "   <== FMDN NONCE"
        elif "fe2c123a" in u and op in (0x12, 0x52):
            extra = f"   <== AUTH RESPONSE (nonce {nonce.get(acl, b'').hex()})"
        elif "fe2c1234" in u or "fe2c1236" in u:
            extra = "   <== FAST PAIR handshake"
        elif "20231219-1730" in u and op in (0x12, 0x52) and val in (b"\x01\x00", b"\x02\x00"):
            extra = "   <== HEAD-TRACKING SUBSCRIBE"
        elif "20231219-1730-0000-0000-000000000002" in u and op in (0x12, 0x52):
            extra = "   <== HEAD-TRACKING START COMMAND"
        elif "20231219-1730" in u and op in (0x1B, 0x1D):
            extra = "   <== ORIENTATION PACKET"

        vhex = val.hex(' ') if val else ""
        print(f"  {rel:9.3f} [acl {acl:#06x}] {d} {opn:9} {label}"
              + (f" = {vhex}" if vhex else "") + extra)


if __name__ == "__main__":
    main()
