[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)]() [![bleak](https://img.shields.io/badge/bleak-BLE-1F6FEB.svg)]() [![python-osc](https://img.shields.io/badge/python--osc-OSC-1F6FEB.svg)]() [![macOS](https://img.shields.io/badge/macOS-Apple%20Silicon-000000.svg?logo=apple&logoColor=white)]() [![Device](https://img.shields.io/badge/device-Jabra%20Elite%2010%20Gen%202-8A2BE2.svg)]() [![Status](https://img.shields.io/badge/status-blocked%3A%20Fast%20Pair%20auth-red.svg)](docs/PROTOCOL.md) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

# jabra-elite10-re - Jabra Elite 10 Gen 2 head-tracking reverse engineering

A reverse-engineering writeup of the **Jabra Elite 10 Gen 2** earbuds' on-board
head tracking over Bluetooth LE. The goal was to drive spatial-audio plugins from
the buds on **macOS**, the way the sibling
[OpenNx](https://git.pg.edu.pl/p829296/opennx) and
[mmrl-headtracker](https://git.pg.edu.pl/p829296/mmrl-headtracker) trackers do,
with the same OSC output:

| OSC address | Arguments | Target |
|---|---|---|
| `/SceneRotator/quaternions` | `qw qx qy qz` | IEM Plugin Suite (SceneRotator) |
| `/ypr` | `yaw pitch roll` (degrees) | SPARTA, Atmoky, dearVR |
| `/Virtuoso/quat` | `qw qx qy qz` | APL Virtuoso |

The result is a **documented dead end**: the orientation is gated behind Google
Fast Pair authentication and most likely never crosses GATT to a host at all (see
[Status](#status)). `jabra_osc.py` is an honest, runnable **skeleton**; the
write-up is the deliverable.

**Protocol and analysis:** the full reverse-engineered GATT map, the Fast Pair
finding, and the capture evidence are in **[docs/PROTOCOL.md](docs/PROTOCOL.md)**.

## Status

This project is **blocked, and probably a dead end**; the analysis is the
deliverable. The GATT interface is fully mapped and the orientation service is
located (`20231219-1730-...`), but it refuses subscription on an unauthenticated
link, and three packet captures indicate the data likely never reaches a host at
all. `jabra_osc.py` is an honest working **skeleton**: scan, connect, battery,
`authenticate()` (the open hook), subscribe, decode, OSC, tare, reconnect.
Everything except `authenticate()` is in place; the bridge runs and stops with a
clear message at the auth step.

Key findings:

- The gating `fe2c` service is **Google Fast Pair**, not a Jabra blob. The buds
  re-run Fast Pair on every reconnect; the handshake was captured on the wire but
  is AES-encrypted under the **account key**, so a passive capture cannot reveal
  it.
- Across three Android `btsnoop` captures and a live Dolby Atmos test, the phone
  **never subscribes to `20231219-...`** and orientation **never crosses GATT**.
  The Elite 10 does head tracking **on-device** (it works with any source, e.g.
  Apple Music, with no Jabra software running), so, unlike the Nx / MMRL
  trackers, it appears not to expose a host orientation feed.

The one experiment that would settle it is extracting the Fast Pair account key
from a **rooted** Android and testing whether `20231219-...`, once authenticated,
emits anything. Procedure: **[docs/ROOT_EXTRACTION.md](docs/ROOT_EXTRACTION.md)**.
How to capture the handshake: **[docs/CAPTURE.md](docs/CAPTURE.md)**.

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

## License

MIT. See [LICENSE](LICENSE). Independent, clean-room reverse-engineering for
interoperability; not affiliated with, endorsed by, or supported by Jabra /
GN Audio A/S. "Google Fast Pair" is a trademark of Google LLC; this project only
documents the publicly specified protocol the device exposes.

## Contact

Bartłomiej Mróz · bartlomiej.mroz@pg.edu.pl · Department of Multimedia Systems, Gdańsk University of Technology · [bmroz.eu](https://bmroz.eu)
