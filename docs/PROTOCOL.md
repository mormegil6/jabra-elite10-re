# Jabra Elite 10 Gen 2 - BLE GATT Protocol (head tracking)

Reverse-engineering notes for getting head-orientation data out of the **Jabra
Elite 10 Gen 2** earbuds over Bluetooth LE, for use as a spatial-audio head
tracker. All findings were obtained empirically with `bleak` on macOS (Apple
Silicon, macOS 14) and are documented with the raw evidence that produced them.

> Status: **GATT fully mapped; head-tracking stream identified but locked.**
> The orientation service refuses subscription on an unauthenticated link. The
> authentication is **not** a custom Jabra blob - the `fe2c` service is **Google
> Fast Pair**, and the lock is keyed by the **Fast Pair account key** your phone
> obtained when it paired the buds. See [Authentication](#authentication-the-real-blocker).

---

## Device identity

| Field | Value |
|-------|-------|
| Advertised name | `Jabra Elite 10 Gen 2` |
| Model Number (0x2A24) | `Jabra Elite 10 Gen 2` |
| Manufacturer (0x2A29) | `Jabra` |
| Serial Number (0x2A25) | `6CFBED******` (per-unit, redacted; equals the device's BLE MAC, prefix `6CFBED` is GN Audio's OUI; also embedded in service `32bf2fe6...`) |
| Firmware Revision (0x2A26) | `2.6.0` |
| Hardware Revision (0x2A27) | `Version1.0` |
| Fast Pair Model ID (0xFE2C / `fe2c1233`) | `35 d6 76` |
| Advertised LE-Audio services | `184e 184f 1850 1844 184d` (ASCS/PACS/VCS/CSIS family) |

### Addressing
- macOS addresses BLE peripherals by a per-host **CoreBluetooth UUID**, not a MAC.
  This unit enumerates as `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` on this Mac; the
  value differs on other machines. On Linux/Windows the address is the MAC.
- The buds advertise over BLE in certain states only; take one out of the case
  and make sure it is awake. They support **multipoint** (dual connection), so the
  Mac can connect while a phone is also connected - see the experiment below.

---

## GATT map (full)

Captured with `tools/stage2_enumerate.py` (see `captures/stageA_enumerate_clean.txt`).
Only the parts relevant to head tracking and authentication are summarised here;
the LE-Audio services (`184e/184f/1850/1844/184d/1846/1853/1855`) are standard
Bluetooth SIG audio-control services and are not reproduced in full.

### Service `0xFE2C` - **Google Fast Pair Service** (not Jabra-proprietary!)
Base UUID `0000XXXX-8366-4814-8eb0-01de32100bea`. This is the published
[Google Fast Pair](https://developers.google.com/nearby/fast-pair) GATT layout,
extended with Find My Device Network (FMDN) characteristics.

| Char | Handle | Props | Fast Pair role | Observed |
|------|--------|-------|----------------|----------|
| `fe2c1233` | 257 | read | **Model ID** | `35 d6 76` |
| `fe2c1234` | 259 | notify,write | **Key-based Pairing** | - |
| `fe2c1235` | 262 | notify,write | **Passkey** | - |
| `fe2c1236` | 265 | write | **Account Key** | - |
| `fe2c1237` | 267 | notify,write | **Additional Data** | - |
| `fe2c1239` | 270 | read | FMDN/version (ext.) | `02 00 90` |
| `fe2c123a` | 272 | notify,read,write | **FMDN Beacon Actions** | 16-byte random, **changes every read** |

### Service `20231219-1730-0000-0000-000000000000` - **head tracking** (target)
The service UUID looks like a date+time stamp (2023-12-19, 17:30). This is the
orientation service. **All three characteristics; the write channel `...0002` was
only found after fixing the enumeration hang (see below).**

| Char | Handle | Props | Purpose (hypothesis) | Observed |
|------|--------|-------|----------------------|----------|
| `...0001` | 354 | notify | orientation stream | subscribe rejected (locked) |
| `...0002` | 357 | write | start/command channel | accepts writes silently |
| `...0003` | 359 | notify,read | orientation/state | read = empty; subscribe rejected (locked) |

### Service `0xF010`
| Char | Handle | Props | Observed |
|------|--------|-------|----------|
| `3a00` | 130 | notify,read | `0x23` |
| `3a01` | 132 | write | CCCD `23 00` |

### Service `0xFEFF`
| Char | Handle | Props | Observed |
|------|--------|-------|----------|
| `8b5b80c0-ac6d-11e4-baef-0002a5d5c51b` | 338 | notify,write | subscribe rejected (locked); its **CCCD read hangs** (see fix) |

### Other notable customs
- `0x2454` / `2455` (notify,read) = `64 64 64` - wear/volume status; `2456` write.
- `32bf2fe6-297c-4ceb-839c-1bf26a1155ac` / `5ab184f5...` = `6c fb ed xx xx xx ...`
  (the serial-number / BLE-MAC bytes, unit part redacted; a device-identity blob).
- `0x1846` CSIS exposes a 16-byte SIRK (coordinated-set membership for L/R buds).

---

## The enumeration hang (and the fix)

`feff/8b5b80c0`'s **CCCD descriptor read never returns** on macOS CoreBluetooth,
which froze the original enumeration indefinitely. `tools/stage2_enumerate.py`
wraps **every** characteristic and descriptor read in a 2-second
`asyncio.wait_for`, so a stuck read prints `<timeout>` and enumeration continues.
This is what revealed the head-tracking write channel `20231219-...0002` and the
full service list. (The `AssertionError` lines bleak prints during the run are
its CoreBluetooth backend firing the timed-out descriptor callbacks late with a
`None` value - harmless; the helper scripts filter them out.)

---

## Authentication: the real blocker

The head-tracking service `20231219-...` refuses `start_notify` on an
unauthenticated link:

```
Failed to update the notification status for characteristic 354:
CBATTErrorDomain Code=13 "The value's length is invalid."
```

(`feff/8b5b80c0` fails identically.) What we established:

### 1. It is not a blind/trivial command - `tools/jabra_probe.py` (Stage B)
Every notify channel was subscribed and a sequence of blind writes was tried:
`01`, `00 01`, `01 00`, the echoed nonce, `00x16` to `fe2c1236`; `01`/`23 01`
to `3a01`; `01`/`01 00` to `20231219-...0002`. **All were silently accepted and
produced zero notifications**, and head tracking stayed locked. The fe2c notify
channels (`1234/1235/1237/123a`) *do* subscribe fine but carried no data - so the
orientation data does **not** flow over fe2c.

### 2. It is not per-connection replayable - `tools/jabra_nonce_analysis.py` (Stage C)
`fe2c123a` returns a fresh **cryptographically random 16-byte** value **on every
read** (2nd read in the same session differed 10/10 times). Over 15 samples:
per-byte entropy is maximal for the sample size, consecutive Hamming distance
averages **63.4/128 ~ 50 %**, no byte is constant, and there is no
counter/timestamp structure. So: no replay, no prediction.

### 3. It is not device-wide - multipoint experiment (`tools/jabra_listen.py`)
With Jabra Sound+ on the phone **actively running head tracking**, the Mac
connected as a second (multipoint) central and still got `value's length is
invalid` on `20231219-...`, and zero fe2c data. **The unlock is per-link**: each
central must authenticate its own connection; you cannot piggyback on the
phone's authenticated session.

### 3b. It is not merely an unencrypted-link problem - bonding test
Pairing the buds to the Mac as a normal Bluetooth audio device (establishing a
bond/LTK, the way LE Audio requires) did **not** change anything: `20231219-...`
still returned `value's length is invalid`. So the lock is **application-layer
authorisation**, not a missing link encryption.

### 3c. The data does not leak when head tracking is active
With head tracking **audibly running** (Apple Music Dolby Atmos, on-device
spatialisation, no Jabra software involved), subscribing to all 22 accessible
notify characteristics for 15 s of head movement produced **nothing** but a
battery tick and the wear byte. So the orientation is computed and applied
**on-device** and is exposed over GATT **only** on the locked `20231219-...`
service - there is no open side channel. Authenticating that service is the only
way to read it from a host.

### 4. What it actually is: Fast Pair / FMDN account-key auth
`fe2c123a` matches the **FMDN Beacon Actions** characteristic exactly:

> *"Each read operation should result in a different nonce... The Seeker then
> calculates a one-time authentication key... authentication segment = first 8
> bytes of `HMAC-SHA256(account_key, version || last_nonce || data_id ||
> data_length || ... || 0x01)`."*
> - [FMDN spec](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn)

So the secret gating these operations is the **16-byte Fast Pair account key**
your phone received from the buds during Fast Pair pairing (stored by Google Play
Services, tied to your Google account; the device keeps a list of account keys).
The challenge-response is standard **HMAC-SHA256 keyed by the account key** - a
documented protocol, not an unguessable bespoke blob.

Whether the head-tracking service `20231219-...` is gated by the *same* account-key
proof, or simply by an authenticated/bonded link that Fast Pair establishes, is
not yet confirmed - that is the next experiment (capture the phone-buds handshake;
see [CAPTURE.md](CAPTURE.md)).

---

## Capture evidence (Android btsnoop, Sound+)

Three captures were taken on the paired Android phone (`tools/jabra_hci_parse.py`,
`tools/pull_btsnoop.sh`). Findings:

- **The Jabra connection re-runs Google Fast Pair on every reconnect.** On the
  Jabra ACL connection (identified by a `ReadByType` returning
  `"Jabra Elite 10 Gen 2"`), the handshake is visible:
  ```
  phone→buds WRITE  fe2c1234 (Key-based Pairing) = <80 bytes: 16 enc + 64 pubkey>
  buds→phone NOTIFY fe2c1234                      = <16 bytes encrypted response>
  phone→buds WRITE  fe2c1236 (Account Key)        = <16 bytes encrypted>
  ```
  This is standard Fast Pair, but every field is **AES-encrypted under the
  account-key/anti-spoofing shared secret**, so a passive capture does **not**
  reveal the account key. (Real device-side handles on this unit: Key-based
  Pairing `0x0104`, Account Key `0x010a`; they differ from the synthetic handles
  bleak shows on macOS.)
- **The orientation never appears over GATT.** In none of the captures - nor in a
  live test with Apple Music Dolby Atmos head tracking audibly running - does the
  phone subscribe to `20231219-...` or any characteristic carry a head-tracking
  stream. The buds spatialise on-device; Sound+ only toggles the feature.

**Feasibility implication:** the head-tracking service is real and auth-gated, but
there is currently **no evidence it streams orientation to a subscriber** - the
normal phone flow never reads it. Unlocking it (which needs the Fast Pair account
key, obtainable only by phone-side instrumentation - Frida/root) is therefore a
**gamble** on whether `20231219-...` actually yields orientation once subscribed.
Unlike the Waves Nx / MMRL trackers (purpose-built orientation streamers), the
Jabra may simply not expose a usable head-orientation feed to hosts.

## Rooted-Android test (executed)

The plan above was carried out on a rooted **OnePlus 5T** (Android 10, Frida 17).
Result: **definitive negative.**

- **System-wide GATT** (`com.android.bluetooth`, `onNotify` +
  `registerForNotification`): **zero** head-tracking notifications or subscribes
  during head movement - nothing streams to any app.
- **Sound+ uses no buds channel we can see**: five Frida runs hooking connectGatt,
  GATT writes/subscribes, `createRfcommSocket` and `BluetoothSocket` read/write
  stayed silent, even on a forced reconnect. `dumpsys` confirms Sound+ holds **no
  GATT link**; the only GATT client is **Google Play Services** (Fast Pair). Audio
  is **Classic A2DP**.
- The Fast Pair **account key is not locally extractable**: GMS keeps it in
  cloud-synced "Footprints", not the on-disk Fast Pair caches (empty here).
- Independently, head tracking works on a **Mac with no Jabra software** and on
  this **Atmos-incapable phone** - so the binauralisation + tracking are entirely
  on the buds.

Conclusion: `20231219-...` is a **dormant, auth-gated service no client ever
uses**, and the orientation is **never transmitted off the buds**. Hook scripts:
[../tools/frida/](../tools/frida/).

## Observed behaviour: it auto-recenters (an effect, not a sensor output)

The head tracking **auto-recenters**: hold your head still facing a new direction
for a few seconds and the soundstage "front" drifts to that new direction. That
fingerprints the algorithm and, more importantly, the *nature* of the value the
buds compute:

- **Yaw (left/right) is relative gyro integration with slow recentering.** A
  gyroscope measures rotation rate, so absolute heading drifts; the recentering
  cancels that drift and produces the consumer "soundstage stays in front of me"
  effect. There is no absolute compass reference (no magnetometer, or it is
  ignored to avoid magnetic interference).
- **Pitch and roll are almost certainly gravity-referenced (absolute)** - the
  accelerometer feels "down", so up/down and tilt neither drift nor recenter. Only
  yaw wanders. This is the standard 6-axis-IMU earbud tracker, the same model as
  AirPods "Spatialize Stereo".

Implication for spatial-audio production: **even if `20231219-...` could be
unlocked and it did emit orientation, the most important axis for the work, yaw,
would be a recentering, drifting estimate** - not the stable absolute heading a
purpose-built tracker (Waves Nx, MMRL) provides. The buds deliberately discard
absolute heading in favour of "always sounds like it is in front of you".

So there was never a clean orientation feed to expose: what the buds compute is a
post-processed, recentered, consumer-tuned estimate baked into the audio
rendering - an **effect, not a sensor output**. That is the deeper reason it lives
only on the buds.

## Getting orientation off the device: feasibility

What it would take to use the Elite 10 Gen 2 as a host head tracker, ranked by
feasibility.

### Feasible
- **Use a different tracker.** The sibling openNx (Waves Nx) and openMMRL
  (MetaMotion RL) repos already stream orientation as OSC. This is the practical
  answer if you want head tracking today; it just is not the Jabra.
- **Ask Jabra to expose it.** A firmware/SDK feature publishing orientation on an
  open (or documented, authable) characteristic would make this trivial. There is
  no technical blocker on the buds - they compute the orientation already; it is a
  product decision. A feature request is the only "feasible" path that ends with
  *the Jabra* working.

### Long shot (low odds, high effort, uncertain payoff)
- **Unlock `20231219-...`.** It is the buds' own orientation/state port, just
  locked and unused. Requires (a) the Fast Pair account key - recoverable only by
  a runtime Frida capture in GMS, or by exporting it from the Google account's
  Footprints, not from disk - and (b) the *unlock command*, which is
  **undocumented and demonstrated by no client** (not even Sound+ or GMS touch
  it). Even if unlocked, there is no evidence it emits live orientation. Odds: low.

### Not feasible
- **Sniff an existing stream.** There is none - proven across GATT and RFCOMM. You
  cannot intercept traffic that does not exist.
- **macOS / iOS CoreMotion** (`CMHeadphoneMotionManager`): Apple gates
  head-tracked motion to AirPods / Beats with Apple silicon; third-party headsets
  including Jabra are not supported.
- **Android Spatializer / head-tracking HAL** (Android 13+): needs the headset to
  report orientation through a standard LE-Audio/HAL path. The Jabra keeps it
  internal, so the OS framework never sees it either.
- **BLE man-in-the-middle / proxy.** Nothing to relay; the orientation is not on
  the wire.
- **Patch the firmware** to stream orientation out: Jabra firmware images are
  **signed**, so a modified image cannot be flashed. Static RE could locate the
  fusion code but yields no live feed.
- **JTAG / SWD on the bud's PCB.** Destructive (you must open a sealed earbud), the
  debug port on production Qualcomm silicon is typically fused/locked, and there is
  no spare radio to stream the value to a host. High risk of bricking the buds for
  no usable result.

**Bottom line:** with the hardware as shipped, there is no non-destructive,
reasonable-effort path to a live orientation feed. The buds keep the data to
themselves by design.

---

## Packet format

**Unknown - the stream is still locked.** Once unlocked, `tools/jabra_listen.py`
prints every candidate decoding of each `20231219` packet (4xfloat32, 4xint16
scaled to a unit quaternion with `|q|` check, 3xint16/float Euler), which is how
the Waves Nx and MMRL formats were nailed down. Cross-check the axis/sign mapping
against a known-good tracker (Waves Nx or MMRL) streaming simultaneously, the way
the openNx repo's `tools/stage4_dual.py` does.

---

## References
- [Google Fast Pair - characteristics](https://developers.google.com/nearby/fast-pair/specifications/characteristics)
- [Fast Pair Find My Device Network (FMDN) extension](https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn) - the account-key HMAC-SHA256 Beacon Actions auth
- [Nordic nRF Connect SDK - Google Fast Pair integration](https://docs.nordicsemi.com/bundle/ncs-3.0.1/page/nrf/external_comp/bt_fast_pair.html) - a working provider-side implementation
- Jabra Elite 10 Gen 2 user manual (pairing/LED/charging) - Jabra support site
