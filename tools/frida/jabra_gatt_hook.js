// jabra_gatt_hook.js
// Logs every BLE GATT control op (subscribe / write desc / write char / read)
// AND the data path (onCharacteristicChanged notifications, onCharacteristicRead
// results) that Jabra Sound+ performs, with UUIDs.
//
// Settles: does Sound+ EVER touch 20231219-... (head tracking) over GATT, or only
// fe2c-... (Fast Pair)? If 20231219 notifies, we also capture the orientation bytes.
//
// Works whether spawned or attached: hooks BluetoothGatt methods (fire whenever
// called), hooks connectGatt for future connections, and Java.choose()s any live
// BluetoothGattCallback so an already-connected session's notifications are caught.

Java.perform(function () {
    const TARGET = "20231219";   // head-tracking service prefix
    const FASTPAIR = "fe2c";     // Fast Pair service prefix

    function tag(u) {
        if (!u) return "";
        u = u.toLowerCase();
        if (u.indexOf(TARGET) !== -1) return "  <<<<< HEAD-TRACKING (20231219) !!!";
        if (u.indexOf(FASTPAIR) !== -1) return "  (Fast Pair fe2c)";
        return "";
    }
    function hex(arr) {
        if (!arr) return "";
        try { return Array.from(arr).map(b => ("0" + (b & 0xff).toString(16)).slice(-2)).join(""); }
        catch (e) { return "?"; }
    }
    function uuidOf(o) { try { return o.getUuid().toString(); } catch (e) { return "?"; } }

    const Gatt = Java.use("android.bluetooth.BluetoothGatt");
    const Device = Java.use("android.bluetooth.BluetoothDevice");
    const BGC = Java.use("android.bluetooth.BluetoothGattCallback");

    // ---- control path: subscribe / write desc / write char / read --------------
    try {
        Gatt.setCharacteristicNotification.overload(
            "android.bluetooth.BluetoothGattCharacteristic", "boolean"
        ).implementation = function (c, enable) {
            const u = uuidOf(c);
            console.log("[SUBSCRIBE]  enable=" + enable + "  char=" + u + tag(u));
            return this.setCharacteristicNotification(c, enable);
        };
    } catch (e) { console.log("[hook-fail] setCharacteristicNotification: " + e); }

    function descLog(d, value) {
        let cu = ""; try { cu = d.getCharacteristic().getUuid().toString(); } catch (e) {}
        console.log("[WRITE DESC] desc=" + uuidOf(d) + "  char=" + cu + "  val=" + hex(value) + tag(cu));
    }
    try { Gatt.writeDescriptor.overload("android.bluetooth.BluetoothGattDescriptor")
        .implementation = function (d) { descLog(d, d.getValue()); return this.writeDescriptor(d); }; } catch (e) {}
    try { Gatt.writeDescriptor.overload("android.bluetooth.BluetoothGattDescriptor", "[B")
        .implementation = function (d, v) { descLog(d, v); return this.writeDescriptor(d, v); }; } catch (e) {}

    try { Gatt.writeCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic")
        .implementation = function (c) {
            const u = uuidOf(c);
            console.log("[WRITE CHAR] char=" + u + "  data=" + hex(c.getValue()) + tag(u));
            return this.writeCharacteristic(c);
        }; } catch (e) {}
    try { Gatt.writeCharacteristic.overload("android.bluetooth.BluetoothGattCharacteristic", "[B", "int")
        .implementation = function (c, v, t) {
            const u = uuidOf(c);
            console.log("[WRITE CHAR] char=" + u + "  data=" + hex(v) + tag(u));
            return this.writeCharacteristic(c, v, t);
        }; } catch (e) {}

    try { Gatt.readCharacteristic.implementation = function (c) {
            const u = uuidOf(c);
            console.log("[READ CHAR]  char=" + u + tag(u));
            return this.readCharacteristic(c);
        }; } catch (e) {}

    // ---- data path: hook the app's BluetoothGattCallback subclass ---------------
    const hooked = {};          // class name -> true
    const notifyCount = {};     // uuid -> count (throttle high-rate streams)

    function hookCallback(instance) {
        let cls;
        try { cls = instance.getClass().getName(); } catch (e) { return; }
        if (hooked[cls]) return;
        hooked[cls] = true;
        let CB;
        try { CB = Java.use(cls); } catch (e) { return; }

        function notifyLog(u, data) {
            const n = (notifyCount[u] = (notifyCount[u] || 0) + 1);
            if (n <= 10) console.log("[NOTIFY]     char=" + u + "  data=" + hex(data) + tag(u));
            else if (n % 100 === 0) console.log("[NOTIFY x" + n + "] char=" + u + tag(u));
        }
        // onCharacteristicChanged: legacy (gatt,char) + API33 (gatt,char,value)
        try { CB.onCharacteristicChanged.overload(
                "android.bluetooth.BluetoothGatt", "android.bluetooth.BluetoothGattCharacteristic"
            ).implementation = function (g, c) {
                notifyLog(uuidOf(c), c.getValue()); return this.onCharacteristicChanged(g, c);
            }; } catch (e) {}
        try { CB.onCharacteristicChanged.overload(
                "android.bluetooth.BluetoothGatt", "android.bluetooth.BluetoothGattCharacteristic", "[B"
            ).implementation = function (g, c, v) {
                notifyLog(uuidOf(c), v); return this.onCharacteristicChanged(g, c, v);
            }; } catch (e) {}
        // onCharacteristicRead: legacy (gatt,char,status) + API33 (gatt,char,value,status)
        try { CB.onCharacteristicRead.overload(
                "android.bluetooth.BluetoothGatt", "android.bluetooth.BluetoothGattCharacteristic", "int"
            ).implementation = function (g, c, s) {
                const u = uuidOf(c);
                console.log("[READ RES]   char=" + u + "  data=" + hex(c.getValue()) + "  status=" + s + tag(u));
                return this.onCharacteristicRead(g, c, s);
            }; } catch (e) {}
        try { CB.onCharacteristicRead.overload(
                "android.bluetooth.BluetoothGatt", "android.bluetooth.BluetoothGattCharacteristic", "[B", "int"
            ).implementation = function (g, c, v, s) {
                const u = uuidOf(c);
                console.log("[READ RES]   char=" + u + "  data=" + hex(v) + "  status=" + s + tag(u));
                return this.onCharacteristicRead(g, c, v, s);
            }; } catch (e) {}
        console.log("[hook] data callbacks attached to " + cls);
    }

    // future connections: grab the callback passed to connectGatt (arg index 2)
    Device.connectGatt.overloads.forEach(function (ov) {
        try {
            ov.implementation = function () {
                try { if (arguments.length >= 3 && arguments[2] !== null) hookCallback(arguments[2]); } catch (e) {}
                return ov.apply(this, arguments);
            };
        } catch (e) {}
    });

    // already-connected session (attach mode): find live callbacks on the heap
    try {
        Java.choose("android.bluetooth.BluetoothGattCallback", {
            onMatch: function (inst) { try { hookCallback(inst); } catch (e) {} },
            onComplete: function () {}
        });
    } catch (e) { console.log("[info] Java.choose(callback) skipped: " + e); }

    console.log("\n=== Jabra GATT hook active. Keep Apple Music playing; in Sound+ toggle head");
    console.log("=== tracking OFF then ON, and move your head. Watching 20231219 vs fe2c. ===\n");
});
