// jabra_stack_hook.js  (attach to com.android.bluetooth)
// System-wide view: every GATT subscribe and every notification, for ALL apps.
// If the Jabra streams orientation over GATT, a high-rate [NOTIFY] appears on its
// address while head tracking is on + head moving. If it is on-device only, the
// only notifications are low-rate (battery etc.). Handle-based (stack uses ATT
// handles, not UUIDs); the rate + data settle whether anything streams.

Java.perform(function () {
    function hex(arr, max) {
        if (!arr) return "";
        try {
            var a = Array.from(arr);
            if (max && a.length > max) a = a.slice(0, max);
            return a.map(function (b) { return ("0" + (b & 0xff).toString(16)).slice(-2); }).join(" ");
        } catch (e) { return "?"; }
    }
    var G = Java.use("com.android.bluetooth.gatt.GattService");
    var notifyCount = {};

    try {
        G.registerForNotification.overload("int", "java.lang.String", "int", "boolean")
        .implementation = function (clientIf, addr, handle, enable) {
            console.log("[SUBSCRIBE]  addr=" + addr + " handle=0x" + handle.toString(16) +
                        " (" + handle + ") enable=" + enable + " clientIf=" + clientIf);
            return this.registerForNotification(clientIf, addr, handle, enable);
        };
    } catch (e) { console.log("[hook-fail] registerForNotification: " + e); }

    try {
        G.onNotify.overload("int", "java.lang.String", "int", "boolean", "[B")
        .implementation = function (connId, addr, handle, isNotify, data) {
            var key = addr + "|" + handle;
            var n = (notifyCount[key] = (notifyCount[key] || 0) + 1);
            var len = data ? data.length : 0;
            if (n <= 8)
                console.log("[NOTIFY]     addr=" + addr + " handle=0x" + handle.toString(16) +
                            " (" + handle + ") len=" + len + " data=" + hex(data, 20));
            else if (n % 50 === 0)
                console.log("[NOTIFY x" + n + "] addr=" + addr + " handle=0x" + handle.toString(16) +
                            " (" + handle + ") len=" + len + "  (streaming)");
            return this.onNotify(connId, addr, handle, isNotify, data);
        };
    } catch (e) { console.log("[hook-fail] onNotify: " + e); }

    try {
        G.registerClient.overload("java.util.UUID", "android.bluetooth.IBluetoothGattCallback")
        .implementation = function (uuid, cb) {
            console.log("[REGISTER CLIENT] uuid=" + uuid.toString());
            return this.registerClient(uuid, cb);
        };
    } catch (e) {}

    console.log("\n=== STACK hook active (com.android.bluetooth), system-wide GATT.");
    console.log("=== Toggle head tracking OFF/ON in Sound+ and move your head. ===\n");
});
