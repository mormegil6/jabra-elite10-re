// gms_crypto_hook.js  (attach to com.google.android.gms)
// Capture the 16-byte Fast Pair account key when GMS uses it (subsequent pairing
// / FMDN beacon auth). The FMDN auth is HMAC-SHA256(account_key, ...), so a
// 16-byte HmacSHA256 key during a buds reconnect is the strongest signal.

Java.perform(function () {
    function hex(a) { try { return Array.from(a).map(function (b) { return ("0" + (b & 0xff).toString(16)).slice(-2); }).join(""); } catch (e) { return "?"; } }
    function stackHint() {
        try {
            var st = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
            return st.split("\n").filter(function (l) { return /nearby|fastpair|fast_pair|footprint|beacon|bluetooth/i.test(l); }).slice(0, 3).join(" | ");
        } catch (e) { return ""; }
    }

    try {
        Java.use("javax.crypto.spec.SecretKeySpec").$init.overload("[B", "java.lang.String")
        .implementation = function (key, algo) {
            try {
                if (key && key.length === 16) {
                    console.log("[KEY16 " + algo + "] " + hex(key));
                    var h = stackHint(); if (h) console.log("   ^ " + h);
                }
            } catch (e) {}
            return this.$init(key, algo);
        };
    } catch (e) { console.log("[hook-fail] SecretKeySpec: " + e); }

    try {
        Java.use("javax.crypto.Mac").init.overload("java.security.Key")
        .implementation = function (k) {
            try {
                var enc = k.getEncoded ? k.getEncoded() : null;
                if (enc && enc.length === 16)
                    console.log("[HMAC " + this.getAlgorithm() + " key16] " + hex(enc) + "   <<< FMDN candidate");
            } catch (e) {}
            return this.init(k);
        };
    } catch (e) { console.log("[hook-fail] Mac.init: " + e); }

    console.log("\n=== GMS crypto hook active. Toggle Bluetooth OFF then ON so the buds");
    console.log("=== reconnect and GMS re-validates Fast Pair (account key gets used). ===\n");
});
