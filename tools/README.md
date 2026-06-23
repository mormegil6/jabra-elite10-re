# Reverse-engineering tools

Staged scripts used to work out the Jabra Elite 10 Gen 2 BLE protocol. They are
**not needed to run the bridge** (`../jabra_osc.py`); they document how each
finding in [../docs/PROTOCOL.md](../docs/PROTOCOL.md) was obtained. The hard-coded
device address in each script is the author's macOS CoreBluetooth UUID; pass your
own as an argument (every script accepts one) or edit the constant.

| Script | Stage | What it does |
|--------|-------|--------------|
| `stage1_scan.py` | 1 | Scan BLE; print name / address / RSSI / service UUIDs / mfg data. Highlights the Jabra. |
| `stage2_enumerate.py` | 2 | Full GATT dump. **Wraps every read in a 2 s timeout** so the `feff` descriptor read can't hang it - this is what revealed the `20231219-...0002` write channel. |
| `stage3_sniff.py` | 3 | Subscribe to every notify/indicate char and log `timestamp \| id \| hex \| len`. `--init target:hex` writes a candidate command first. |
| `jabra_probe.py` | B | Subscribe-all + a sequence of blind writes (3a01 / fe2c1236 / 20231219-0002), re-testing the locked head-tracking subscription after each. Concluded: challenge-response, not a blind command. |
| `jabra_nonce_analysis.py` | C | Connect N times, read `fe2c123a` per connection (and twice per session); entropy / Hamming / counter analysis. Concluded: the nonce is crypto-random and changes every read (FMDN). |
| `jabra_listen.py` | - | Live listener/decoder: subscribe to head-tracking + fe2c channels and print every candidate orientation decoding (float32 / int16-quaternion / Euler). Used to test the multipoint piggyback (failed) and will decode the stream once unlocked. |
| `jabra_mitm_prep.py` | D | Verify the central role + print the clone "mirror map"; detect the (absent) peripheral role and explain why a macOS MitM is impractical, with capture alternatives. |
| `jabra_hci_parse.py` | D | Parse an Android `btsnoop_hci.log` and print the Fast Pair / head-tracking ATT ops (nonce read, auth write, subscribe, start command, orientation packets), named via the Stage-A handle map. No dependencies. |
| [`frida/`](frida/) | E | Rooted-Android Frida hooks (Bluetooth stack, Sound+ transports, GMS crypto) used to confirm the buds never send orientation to a host. See [frida/README.md](frida/README.md). |

## Typical flow

```bash
python stage1_scan.py
python stage2_enumerate.py <ADDRESS>          # full GATT map (no hang)
python jabra_probe.py <ADDRESS>               # Stage B blind-write probe
python jabra_nonce_analysis.py <ADDRESS>      # Stage C nonce analysis
python jabra_listen.py <ADDRESS> --secs 30    # listen/decode (locked until auth)
python jabra_mitm_prep.py <ADDRESS>           # Stage D capture-prep verdict
```

Captures are written to `../captures/` (git-ignored; representative samples and
conclusions live in [../docs/PROTOCOL.md](../docs/PROTOCOL.md)).
