[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)]() [![bleak](https://img.shields.io/badge/bleak-BLE-1F6FEB.svg)]() [![python-osc](https://img.shields.io/badge/python--osc-OSC-1F6FEB.svg)]() [![macOS](https://img.shields.io/badge/macOS-Apple%20Silicon-000000.svg?logo=apple&logoColor=white)]() [![Device](https://img.shields.io/badge/device-Jabra%20Elite%2010%20Gen%202-8A2BE2.svg)]() [![Status](https://img.shields.io/badge/status-dead%20end%3A%20on--device%20tracking-red.svg)](docs/PROTOCOL.md) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

# jabra-elite10-re - Jabra Elite 10 Gen 2 head-tracking reverse engineering

A reverse-engineering writeup of the **Jabra Elite 10 Gen 2** earbuds' on-board
head tracking over Bluetooth LE. The goal was to drive spatial-audio plugins from
the buds on **macOS** with OSC, the way the sibling
[OpenNx](https://github.com/mormegil6/opennx) and
[mmrl-osc](https://github.com/mormegil6/mmrl-osc) trackers do.

The result is a **confirmed dead end**: the buds do head tracking entirely
on-device, and the orientation never reaches a host over any channel (verified on
a rooted Android - see [Status](#status)). `jabra_osc.py` is a runnable
**skeleton** (it stops at the auth step no host can satisfy); the
reverse-engineering is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

**Protocol and analysis:** the full reverse-engineered GATT map, the Fast Pair
finding, and the capture evidence are in **[docs/PROTOCOL.md](docs/PROTOCOL.md)**.

## Status

**Confirmed dead end.** The GATT interface is
fully mapped and the orientation service is located (`20231219-1730-...`), but the
buds do head tracking **entirely on-device** and never send orientation to a host
over any channel. This was settled on a **rooted Android (OnePlus 5T)** with
Frida: across a system-wide Bluetooth-stack hook (`com.android.bluetooth`), Sound+
on every transport (BLE GATT and Classic RFCOMM), and `dumpsys`, **nothing streams
orientation to anyone** - Sound+ holds no GATT link at all (only Google Play
Services does, for Fast Pair), and audio is Classic A2DP. It is confirmed
independently by head tracking working on a **Mac with zero Jabra software** and
on this **Atmos-incapable phone**. `jabra_osc.py` is a **skeleton** (scan,
connect, battery, `authenticate()` hook, subscribe, decode, OSC, tare, reconnect);
it runs and stops at the auth step, which no host can satisfy because the feed
does not exist.

Key findings:

- The gating `fe2c` service is **Google Fast Pair**, not a Jabra blob. The buds
  re-run Fast Pair on every reconnect; the handshake was captured on the wire but
  is AES-encrypted under the **account key**, so a passive capture cannot reveal
  it.
- Across three Android `btsnoop` captures and a live Dolby Atmos test, the phone
  **never subscribes to `20231219-...`** and orientation **never crosses GATT**.
  The Elite 10 does head tracking **on-device** (it works with any source, e.g.
  Apple Music, with no Jabra software running), so, unlike the Nx / MMRL
  trackers, it does **not** expose a host orientation feed.
- **The rooted-Android test is done** (it was the one outstanding experiment):
  the system-wide stack hook and Sound+ transport hooks were silent across five
  runs; the Fast Pair account key is not locally extractable (cloud "Footprints"),
  and `20231219-...` is a dormant, auth-gated service no client ever uses. See
  [docs/ROOT_EXTRACTION.md](docs/ROOT_EXTRACTION.md) for the executed procedure
  and outcome, and **[what is and is not feasible](docs/PROTOCOL.md#getting-orientation-off-the-device-feasibility)**.

How the handshake was captured: **[docs/CAPTURE.md](docs/CAPTURE.md)**.

## What was discovered (short version)

- **Identity:** `Jabra Elite 10 Gen 2`, firmware `2.6.0`, Fast Pair Model ID
  `35 d6 76`.
- **Head-tracking service** `20231219-1730-0000-0000-000000000000` (the service
  base UUID ends in `...0000`) exposes three characteristics: `...0001` (notify),
  `...0002` (write, found only after fixing the enumeration hang), and `...0003`
  (notify, read). Subscribing to the notify characteristics fails with
  `value's length is invalid` on an unauthenticated link.
- **`fe2c` is Google Fast Pair:** `fe2c1233` Model ID, `1234` Key-based Pairing,
  `1235` Passkey, `1236` Account Key, `1237` Additional Data, and **`123a` =
  FMDN Beacon Actions**, a 16-byte nonce that changes on every read.
- **The nonce is cryptographically random** (entropy maximal, Hamming about
  50 percent, no structure): no replay, no prediction.
- **The unlock is per-link and application-layer:** bonding the Mac to the buds
  did not help, and a second (multipoint) link stayed locked while the phone
  streamed head tracking.
- **A macOS BLE man-in-the-middle is impractical** (bleak is central-only;
  CoreBluetooth cannot faithfully clone the buds; the phone is bonded). Capture
  the phone-to-buds link passively instead (Android `btsnoop`).

## Usage (from source)

Requires Python 3.9 or newer. The bridge skeleton uses `bleak` and is
cross-platform in principle, but every finding here is macOS-specific
(CoreBluetooth handle quirks, the descriptor-read hang, the Android captures).

```bash
python3 -m venv jabra-venv
source jabra-venv/bin/activate
pip install -r requirements.txt

python jabra_osc.py                        # scan, connect; reports the auth lock
python jabra_osc.py --account-key <32-hex> # experimental FMDN unlock (needs the key)
```

`osc_monitor.py` prints whatever arrives on the OSC port for testing:

```bash
python osc_monitor.py --port 8000          # in a second terminal
```

## Reverse-engineering tools

The `tools/` directory holds the staged scripts used to map the protocol (same
layout as the Nx and MMRL repos): device discovery, GATT enumeration (with the
descriptor-read timeout that fixes the hang), a notification sniffer, the
blind-write probe, the nonce analysis, a live listener and decoder, the MitM-prep
check, and an Android `btsnoop` parser. They are not needed to run the bridge;
they document how each finding was obtained. See [tools/README.md](tools/README.md).

## Files

| File | Purpose |
|---|---|
| `jabra_osc.py` | the head-tracker bridge (skeleton; `authenticate()` hook open) |
| `osc_monitor.py` | OSC listener for testing |
| `requirements.txt` | bleak, python-osc |
| `docs/PROTOCOL.md` | full reverse-engineered GATT map, auth analysis, capture evidence |
| `docs/CAPTURE.md` | how to capture the Sound+ handshake (Android btsnoop / iOS) |
| `docs/ROOT_EXTRACTION.md` | resume plan: account-key extraction on rooted Android |
| `tools/` | staged RE scripts, `jabra_hci_parse.py`, `pull_btsnoop.sh` |

## Related projects

Part of a set of open head-tracking tools for spatial audio:

- **Busola** ([GitLab](https://git.pg.edu.pl/p829296/busola-app) / [GitHub](https://github.com/mormegil6/busola-app)) - the menu-bar **app**: one GUI for several head trackers (MetaMotion RL, Waves Nx, Supperware, MrHeadTracker), with device discovery, remembered devices, live profile-switching and CSV logging - the conveniences these CLI bridges leave out
- **OpenNx** ([GitLab](https://git.pg.edu.pl/p829296/opennx) / [GitHub](https://github.com/mormegil6/opennx)) - Waves Nx head tracker → OSC bridge, cross-platform (macOS / Windows / Linux)
- **mmrl-osc** ([GitLab](https://git.pg.edu.pl/p829296/mmrl-osc) / [GitHub](https://github.com/mormegil6/mmrl-osc)) - Mbientlab MetaMotion RL → OSC head tracker with host-side VQF sensor fusion

## License

MIT. See [LICENSE](LICENSE). Independent, clean-room reverse-engineering for
interoperability; not affiliated with, endorsed by, or supported by Jabra /
GN Audio A/S. "Google Fast Pair" is a trademark of Google LLC; this project only
documents the publicly specified protocol the device exposes.

## Contact

Bartłomiej Mróz · bartlomiej.mroz@pg.edu.pl · Department of Multimedia Systems, Gdańsk University of Technology · [bmroz.eu](https://bmroz.eu)
