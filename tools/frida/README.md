# Frida hooks (rooted-Android investigation)

These are the [Frida](https://frida.re) scripts used to settle, on a rooted phone,
whether the Jabra Elite 10 Gen 2 ever sends head orientation to a host. The
answer was **no** - see [../../docs/ROOT_EXTRACTION.md](../../docs/ROOT_EXTRACTION.md)
and the [feasibility breakdown](../../docs/PROTOCOL.md#getting-orientation-off-the-device-feasibility).
They are RE artifacts, not part of the bridge; nothing here is needed to run
`jabra_osc.py`.

Tested on a rooted **OnePlus 5T** (Android 10) with **frida-server 17.x**.

| Script | Attach to | What it shows |
|--------|-----------|----------------|
| `jabra_stack_hook.js` | `com.android.bluetooth` | **System-wide** GATT: every `onNotify` + `registerForNotification`, for all apps. The decisive instrument - if anything streamed over BLE GATT, it would appear here. It did not. |
| `jabra_gatt_hook.js` | `Sound+` | Sound+'s own GATT ops (subscribe / write / read) + a best-effort hook of its `BluetoothGattCallback` for notifications. |
| `jabra_rfcomm_hook.js` | `Sound+` | Classic **RFCOMM** I/O (`BluetoothSocket` read/write) - the channel Sound+ would use, since it holds no GATT link. Silent. |
| `jabra_full_hook.js` | `Sound+` (spawn) | All transports at once: `connectGatt`, GATT writes/subscribes, `createRfcommSocket`, socket connect/read/write. |
| `gms_crypto_hook.js` | `com.google.android.gms` | Captures 16-byte AES / HMAC-SHA256 keys as Fast Pair uses them (the account-key extraction attempt). |

## Running them

Frida **17** removed the built-in `Java` bridge from the bare script runtime, so a
raw `session.create_script()` fails with `'Java' is not defined`. The **frida CLI**
(from `frida-tools`) still bundles the bridge, so run the hooks through it.

The CLI is a REPL; to capture a fixed window non-interactively, keep stdin open
with a `sleep` and let it close to detach:

```bash
# attach to a running process for 45 s while you interact on the phone
( sleep 45 ) | frida -U -n "Sound+" -l jabra_stack_hook.js -q

# or attach to the Bluetooth stack (system-wide view)
( sleep 45 ) | frida -U -n "com.android.bluetooth" -l jabra_stack_hook.js -q

# spawn fresh (catches the full connection lifecycle); may need a retry on
# OxygenOS, where Frida's spawn-wait can time out
( sleep 70 ) | frida -U -f com.jabra.moments -l jabra_full_hook.js -q
```

Prerequisites: a rooted phone with a matching `frida-server` running as root, USB
debugging, and the host `frida` tools (`pip install frida-tools`). The Jabra
Sound+ package is `com.jabra.moments` (process label `Sound+`).
