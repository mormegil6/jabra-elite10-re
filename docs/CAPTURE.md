# Capturing the Jabra head-tracking authentication handshake

The head-tracking service `20231219-...` is locked behind a Fast Pair / FMDN
account-key challenge-response (see [PROTOCOL.md](PROTOCOL.md)). To replicate it
we need to see exactly what Jabra Sound+ writes to the buds when head tracking is
enabled. This document covers the practical ways to capture that, in rough order
of effort.

## Why not a macOS BLE man-in-the-middle?

`tools/jabra_mitm_prep.py` checks this on your host and prints the verdict. In
short: bleak is central-only; the only macOS peripheral-role option (`bless` via
CoreBluetooth) cannot faithfully clone the buds (handles, LE-Audio/CSIS services,
the BR/EDR audio profile), and the phone is already **bonded** to the real buds
via Fast Pair, so it won't connect to a Mac clone and there is nothing to forward.
Capture the real phone-buds link instead.

## Option 1 - Android Bluetooth HCI snoop log (easiest, decisive)

Best if the phone running Sound+ is Android.

> **Capture a FRESH PAIRING, not a reconnect.** Android caches the GATT database
> of bonded devices, so a normal reconnect skips service discovery *and* re-auth -
> the log then contains only LE-Audio setup, no `fe2c` nonce and no `20231219`
> UUIDs (confirmed on a first capture here). Before capturing, **forget the buds**
> in Android Bluetooth settings *and* remove them in Sound+, then pair from
> scratch with the snoop log running. That records the Fast Pair handshake and the
> full handle-UUID discovery the parser needs. For the orientation stream, also
> **play spatial/Dolby Atmos audio** while head tracking is on and move your head.

1. Settings → About phone → tap **Build number** 7x to enable Developer options.
2. Developer options → enable **Bluetooth HCI snoop log** (set to "Enabled"/
   "Filtered"). Toggle Bluetooth off/on so logging starts.
3. In **Jabra Sound+**, turn head tracking / spatial sound **off, then on** (and
   move your head a little) so the unlock handshake and a few data packets are
   captured. Keep it short.
4. Pull the log:
   - `adb bugreport bugreport.zip` then find `FS/data/misc/bluetooth/logs/btsnoop_hci.log`
     inside it, **or** the path shown under the HCI-snoop setting on your phone.
5. Parse it with our bundled parser (no Wireshark needed):
   ```bash
   python tools/jabra_hci_parse.py btsnoop_hci.log
   ```
   It names the ATT ops via the Stage-A handle map and flags the **nonce read**,
   the **auth response write**, the **head-tracking subscribe**, the **start
   command** to `20231219-...0002`, and the first **orientation packets**. Use
   `--all` to see every handle, `--raw` for non-ATT fragments. (Wireshark with
   filter `btatt` works too.)

**Tip - capture a *fresh* connection.** The unlock handshake may happen at
connection time, not when you toggle the app switch. So: enable the HCI snoop log,
turn Bluetooth **off then on** (or "forget"+reconnect the buds), let the buds
reconnect, open Sound+, toggle head tracking on, move your head ~10 s, then stop.
That captures both the connection-time Fast Pair/FMDN auth and the app's
start-stream command.

The nonce changes per read, so the captured write won't replay directly, but the
captured (nonce → write) pair lets you identify the HMAC input layout, and
confirms which characteristic actually gates `20231219-...`.

## Option 2 - iOS PacketLogger (if the phone is an iPhone)

1. On a Mac, install **Additional Tools for Xcode** (Apple Developer downloads);
   it includes **PacketLogger**.
2. Install the **Bluetooth logging configuration profile** on the iPhone (Apple's
   "Bluetooth" profile from the Additional Tools, or via the Mac while the iPhone
   is attached). This raises iOS HCI logging.
3. Start PacketLogger → iOS device, reproduce the head-tracking toggle in Sound+,
   stop, and inspect the ATT writes/notifications exactly as in Option 1.

## Option 3 - Recover the Fast Pair account key directly

The challenge-response is `HMAC-SHA256(account_key, ...)`. If you can obtain the
**16-byte account key**, you can compute the response yourself with no capture:

- **Rooted Android**: the account keys Google Play Services stored for these buds
  live in its Fast Pair storage; extract the 16-byte key for Model ID `35 d6 76`.
- **Fresh pairing as a Seeker**: if you implement (or run) a Fast Pair seeker and
  pair the buds yourself, you generate the account key and therefore know it.
  Initial pairing needs the device's **anti-spoofing public key** for Model ID
  `35 d6 76`, which Google serves to authorised seekers; this is the gated part.
- **Frida** on Sound+ (rooted Android / emulator): hook the BLE write to the
  Beacon Actions characteristic, or the `Mac`/`HMAC`/`SecretKeySpec` call, and
  print the key and the cleartext command.

## Option 4 - Active proxy on Linux / Raspberry Pi

If a live MitM is genuinely needed (e.g. to fuzz the device), BlueZ on Linux
supports the peripheral role properly. A Pi connects to the buds as a central and
re-advertises a clone to the phone, logging and forwarding GATT operations. This
still has to defeat Fast Pair bonding, so it is more involved than the passive
options above; prefer Options 1-3.

## What to bring back

For each captured operation, record:
- the **characteristic** (handle + UUID),
- the **direction** (seeker write vs provider notify),
- the **raw bytes**, and
- for `fe2c123a`: the **nonce that was read immediately before** the write.

Drop the capture (or the relevant hex) into `captures/` and we can decode the
auth and fill in `jabra_osc.py`'s `authenticate()` hook.
