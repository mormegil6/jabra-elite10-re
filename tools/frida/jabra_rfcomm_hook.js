// jabra_rfcomm_hook.js  (attach to Sound+)
// Sound+ talks to the buds over Bluetooth Classic RFCOMM, not GATT. Hook the raw
// BluetoothSocket read/write so we see every byte exchanged, regardless of the
// Jabra SDK wrapping. Question: when head tracking is toggled / head moves, does
// the buds -> phone direction carry an orientation stream, or only control?

Java.perform(function () {
    function hex(arr, off, len, max) {
        try {
            var a = Array.from(arr).slice(off, off + len);
            if (max && a.length > max) a = a.slice(0, max);
            return a.map(function (b) { return ("0" + (b & 0xff).toString(16)).slice(-2); }).join(" ");
        } catch (e) { return "?"; }
    }
    var Sock = Java.use("android.bluetooth.BluetoothSocket");
    var rx = 0, tx = 0;

    function hookWrite(sig) {
        try {
            Sock.write.overload.apply(Sock.write, sig.types).implementation = sig.fn;
        } catch (e) {}
    }

    // write([B, int, int)
    try { Sock.write.overload("[B", "int", "int").implementation = function (b, off, len) {
        try { tx++; console.log("[TX -> buds " + len + "B] " + hex(b, off, len, 48)); } catch (e) {}
        return this.write(b, off, len);
    }; } catch (e) { console.log("[hook-fail] write([B,int,int): " + e); }
    // write([B)
    try { Sock.write.overload("[B").implementation = function (b) {
        try { tx++; console.log("[TX -> buds " + b.length + "B] " + hex(b, 0, b.length, 48)); } catch (e) {}
        return this.write(b);
    }; } catch (e) {}

    // read([B, int, int)
    try { Sock.read.overload("[B", "int", "int").implementation = function (b, off, len) {
        var n = this.read(b, off, len);
        try { if (n > 0) { rx++; console.log("[RX <- buds " + n + "B] " + hex(b, off, n, 48)); } } catch (e) {}
        return n;
    }; } catch (e) { console.log("[hook-fail] read([B,int,int): " + e); }
    // read([B)
    try { Sock.read.overload("[B").implementation = function (b) {
        var n = this.read(b);
        try { if (n > 0) { rx++; console.log("[RX <- buds " + n + "B] " + hex(b, 0, n, 48)); } } catch (e) {}
        return n;
    }; } catch (e) {}

    // also log socket connects so we know a channel is in use
    try {
        Sock.connect.implementation = function () {
            try { console.log("[SOCKET connect] type=" + this.getConnectionType() + " remote=" + this.getRemoteDevice().getAddress()); } catch (e) { console.log("[SOCKET connect]"); }
            return this.connect();
        };
    } catch (e) {}

    console.log("\n=== RFCOMM hook active in Sound+. Toggle head tracking OFF/ON and move your head. ===");
    console.log("=== TX = phone->buds (commands), RX = buds->phone (data/replies). ===\n");
});
