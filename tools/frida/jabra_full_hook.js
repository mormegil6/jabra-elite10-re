// jabra_full_hook.js  (SPAWN Sound+: frida -U -f com.jabra.moments)
// Catch the buds control channel from app start, across every transport:
//   - BLE GATT (connectGatt + writes/subscribes)
//   - Classic RFCOMM (createRfcommSocket + BluetoothSocket read/write)
// Reveals which transport Sound+ uses and the head-tracking enable command.

Java.perform(function () {
    function hex(arr, off, len, max) {
        try {
            var a = Array.from(arr).slice(off, off + len);
            if (max && a.length > max) a = a.slice(0, max);
            return a.map(function (b) { return ("0" + (b & 0xff).toString(16)).slice(-2); }).join(" ");
        } catch (e) { return "?"; }
    }
    function tag(u) { if (u && u.toLowerCase().indexOf("20231219") !== -1) return "  <<<<< HEAD-TRACKING"; return ""; }

    var Device = Java.use("android.bluetooth.BluetoothDevice");
    var Gatt = Java.use("android.bluetooth.BluetoothGatt");
    var Sock = Java.use("android.bluetooth.BluetoothSocket");

    // ---- BLE: connectGatt ----
    Device.connectGatt.overloads.forEach(function (ov) {
        try { ov.implementation = function () {
            var addr = "?"; try { addr = this.getAddress(); } catch (e) {}
            console.log("[connectGatt] addr=" + addr);
            return ov.apply(this, arguments);
        }; } catch (e) {}
    });
    try { Gatt.setCharacteristicNotification.overload("android.bluetooth.BluetoothGattCharacteristic", "boolean")
        .implementation = function (c, en) {
            var u = c.getUuid().toString();
            console.log("[GATT SUBSCRIBE] " + u + " enable=" + en + tag(u));
            return this.setCharacteristicNotification(c, en);
        }; } catch (e) {}
    try { Gatt.writeCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic")
        .implementation = function (c) {
            var u = c.getUuid().toString();
            console.log("[GATT WRITE] " + u + " data=" + hex(c.getValue(), 0, c.getValue() ? c.getValue().length : 0, 40) + tag(u));
            return this.writeCharacteristic(c);
        }; } catch (e) {}

    // ---- Classic: RFCOMM socket creation + I/O ----
    ["createRfcommSocketToServiceRecord", "createInsecureRfcommSocketToServiceRecord"].forEach(function (mn) {
        try { Device[mn].implementation = function (uuid) {
            console.log("[createRfcomm] " + mn + " uuid=" + uuid.toString());
            return this[mn](uuid);
        }; } catch (e) {}
    });
    try { Sock.connect.implementation = function () {
        var info = ""; try { info = "type=" + this.getConnectionType() + " remote=" + this.getRemoteDevice().getAddress(); } catch (e) {}
        console.log("[socket.connect] " + info);
        return this.connect();
    }; } catch (e) {}
    try { Sock.write.overload("[B", "int", "int").implementation = function (b, o, l) {
        console.log("[TX -> buds " + l + "B] " + hex(b, o, l, 48)); return this.write(b, o, l);
    }; } catch (e) {}
    try { Sock.read.overload("[B", "int", "int").implementation = function (b, o, l) {
        var n = this.read(b, o, l);
        if (n > 0) console.log("[RX <- buds " + n + "B] " + hex(b, o, n, 48));
        return n;
    }; } catch (e) {}

    console.log("\n=== Sound+ full-transport hook active (spawned). Let it connect to the buds,");
    console.log("=== then enable head tracking and move your head. ===\n");
});
