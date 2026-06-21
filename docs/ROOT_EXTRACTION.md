# Resume plan: account-key extraction (rooted Android) → unlock test

This is the one remaining experiment that settles whether the Jabra Elite 10
Gen 2 exposes head orientation to a host at all. Everything else is done and
documented (see [PROTOCOL.md](PROTOCOL.md)). Current best guess: **~80% likely
there is no usable orientation stream** (on-device spatialisation; the phone
never subscribes to `20231219-...` in any capture). This procedure confirms it
either way.

## Goal

Obtain the **16-byte Fast Pair account key** the buds trust, then (a) decrypt the
handshake we already captured to validate it, and (b) use it from the Mac to
authenticate and try to subscribe to `20231219-...`. If that subscribe yields a
notification stream → we win, decode it and finish `jabra_osc.py`. If it stays
silent / returns nothing useful → the conclusion stands and we stop.

Any rootable Android works - it does **not** have to be your main phone or Google
account. When that phone pairs the buds, it writes *its* account key into the
buds' on-device key list, so the buds will trust the key we extract from it.

## Steps

1. **Root a spare Android phone** (Magisk, etc.) and push a matching
   **`frida-server`** to `/data/local/tmp`, run it as root.
2. Install **Jabra Sound+** and **pair the Elite 10 Gen 2 via Fast Pair**
   (the "Tap to connect" sheet). This stores a 16-byte account key in Google
   Play Services and in the buds.
3. **Extract the account key.** Two ways:
   - *Frida (recommended)* - attach to Google Play Services and log 16-byte AES
     keys as Fast Pair uses them. Starting hook (adapt to the GMS version):
     ```js
     // frida -U -n com.google.android.gms.persistent -l fastpair_key.js
     Java.perform(function () {
       var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
       SKS.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
         if (algo.toUpperCase().indexOf('AES') >= 0 && key.length === 16) {
           console.log('[AES-128 key] ' +
             Array.from(key).map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join(''));
         }
         return this.$init(key, algo);
       };
     });
     ```
     There will be several 16-byte keys; identify the account key by the verify
     step below.
   - *Direct DB (alternative)* - with root, the Fast Pair account keys live in
     GMS storage under `/data/data/com.google.android.gms/` (a `fastpair*` /
     `nearby*` database; path varies by GMS version). Dump and read the 16-byte
     key for Model ID `35 d6 76`.
4. **Verify the key by decrypting the captured handshake.** Our
   `captures/btsnoop_hci-02.log` contains the Fast Pair Key-based Pairing
   exchange (Account Key write `cd d7 f1 dc ... 49`, KBP response `11 f4 6a 0a ... 23`).
   The account key is the AES key; a correct candidate decrypts the Account-Key
   write to a value that begins with the account-key type byte `0x04` and matches
   the Fast Pair format. (A small `tools/jabra_fp_decrypt.py` can be written for
   this once a candidate key exists.)
5. **Test the unlock from the Mac.** Pass the verified key to the bridge:
   ```bash
   python jabra_osc.py --account-key <32-hex-chars>
   ```
   `authenticate()` reads the `fe2c123a` nonce, derives the FMDN HMAC / Fast Pair
   auth, writes it, and attempts `20231219-...` subscription. Watch for orientation
   notifications (decode candidates print via `tools/jabra_listen.py`).
6. **Also settle the gamble directly on the rooted phone:** while in Sound+ with
   head tracking on and spatial audio playing, Frida-log the app's GATT calls (or
   take a fresh-pairing btsnoop) and check whether **anything ever subscribes to
   `20231219-...`**. If the official app never reads it, that is strong evidence the
   orientation is not exposed, regardless of auth.

## Two possible outcomes

- **`20231219` streams once authenticated** → decode the packets (float32 /
  int16-quaternion / Euler - `tools/jabra_listen.py`), verify axes against a
  Waves Nx / MMRL tracker streaming alongside, and wire up `jabra_osc.py`. Done.
- **It stays silent / the app never subscribes** → the Elite 10 does head
  tracking on-device only and does **not** expose a host orientation feed. Record
  the negative result; the repo stands as a complete protocol write-up.
