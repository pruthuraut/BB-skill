// Traces CommonCrypto and Security crypto calls: algorithm, ECB vs IV modes, key length, zero/NULL IV,
// IV reuse for the same key, PBKDF2 rounds/salt/PRF, MD5/SHA1 use, weak and strong RNG calls, and
// SecKeyCreateRandomKey with or without the Secure Enclave. Keys and IVs are reported only as
// SHA-256 prefixes so reuse is visible without exposing material.
// Usage: frida -U -f <bundle> -l crypto_trace.js
function exp(n) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(n); } catch (e) {}
  try { return Module.findExportByName(null, n); } catch (e) { return null; }
}
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 3).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join(" < "); }
  catch (e) { return ""; }
}
function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (x) { return ("0" + x.toString(16)).slice(-2); }).join(""); }
var CC_SHA256 = new NativeFunction(exp("CC_SHA256"), "pointer", ["pointer", "uint32", "pointer"]);
var inSha = false;
function h(p, len) {
  if (p.isNull() || len <= 0) return null;
  inSha = true;
  var out = Memory.alloc(32); CC_SHA256(p, len, out);
  inSha = false;
  return hex(out.readByteArray(32)).slice(0, 16);
}
function zero(p, len) { var b = new Uint8Array(p.readByteArray(len)); for (var i = 0; i < b.length; i++) if (b[i]) return false; return true; }
var ALG = { 0: "AES", 1: "DES", 2: "3DES", 3: "CAST", 4: "RC4", 5: "RC2", 6: "Blowfish" };
var MODE = { 1: "ECB", 2: "CBC", 3: "CFB", 4: "CTR", 6: "OFB", 7: "RC4", 8: "CFB8", 11: "GCM", 12: "CCM" };
var PRF = { 1: "SHA1", 2: "SHA224", 3: "SHA256", 4: "SHA384", 5: "SHA512" };
var ivSeen = {}, counts = {}, saltSeen = {};
function limited(key, o) { counts[key] = (counts[key] || 0) + 1; if (counts[key] <= 5) emit(o); }
function ivCheck(keyH, ivH) { if (!ivH) return false; var k = keyH + ":" + ivH; ivSeen[k] = (ivSeen[k] || 0) + 1; return ivSeen[k] > 1; }

var cc = exp("CCCrypt");
if (cc) Interceptor.attach(cc, { onEnter: function (a) {
  var op = a[0].toInt32(), alg = a[1].toInt32(), opt = a[2].toInt32(), klen = a[4].toInt32();
  var ecb = (opt & 2) !== 0, kh = h(a[3], klen), ivh = (ecb || a[5].isNull()) ? null : h(a[5], alg === 0 ? 16 : 8);
  var weakIv = !ecb && (a[5].isNull() || zero(a[5], alg === 0 ? 16 : 8));
  var o = { type: "crypto", api: "CCCrypt", op: op ? "decrypt" : "encrypt", alg: ALG[alg] || alg, mode: ecb ? "ECB" : "CBC",
            keyLen: klen, keyHash: kh, ivHash: ivh, ivNullOrZero: weakIv, ivReuse: op === 0 && ivCheck(kh, ivh), caller: bt(this.context) };
  limited("cc" + o.alg + o.mode + o.caller + o.ivReuse, o);
} });
var ccm = exp("CCCryptorCreateWithMode");
if (ccm) Interceptor.attach(ccm, { onEnter: function (a) {
  var op = a[0].toInt32(), mode = a[1].toInt32(), alg = a[2].toInt32(), klen = a[6].toInt32();
  var kh = h(a[5], klen), ivh = a[4].isNull() ? null : h(a[4], 16);
  var o = { type: "crypto", api: "CCCryptorCreateWithMode", op: op ? "decrypt" : "encrypt", alg: ALG[alg] || alg, mode: MODE[mode] || mode,
            keyLen: klen, keyHash: kh, ivHash: ivh, ivNullOrZero: mode !== 1 && (a[4].isNull() || zero(a[4], 16)),
            ivReuse: op === 0 && mode !== 1 && ivCheck(kh, ivh), caller: bt(this.context) };
  limited("ccm" + o.alg + o.mode + o.caller + o.ivReuse, o);
} });
var ccc = exp("CCCryptorCreate");
if (ccc) Interceptor.attach(ccc, { onEnter: function (a) {
  var opt = a[2].toInt32(), klen = a[4].toInt32();
  limited("ccc" + bt(this.context), { type: "crypto", api: "CCCryptorCreate", alg: ALG[a[1].toInt32()] || a[1].toInt32(),
    mode: (opt & 2) ? "ECB" : "CBC", keyLen: klen, keyHash: h(a[3], klen), ivNullOrZero: !(opt & 2) && (a[5].isNull() || zero(a[5], 16)), caller: bt(this.context) });
} });
var kdf = exp("CCKeyDerivationPBKDF");
if (kdf) Interceptor.attach(kdf, { onEnter: function (a) {
  var rounds = a[6].toUInt32(), saltLen = a[4].toInt32(), sh = h(a[3], saltLen);
  saltSeen[sh] = (saltSeen[sh] || 0) + 1;
  limited("kdf" + rounds + sh, { type: "crypto", api: "CCKeyDerivationPBKDF", prf: PRF[a[5].toInt32()] || a[5].toInt32(), rounds: rounds,
    saltLen: saltLen, saltHash: sh, staticSalt: saltSeen[sh] > 1, weak: rounds < 100000 || saltLen < 16, caller: bt(this.context) });
} });
["CC_MD5", "CC_SHA1", "rand", "random", "srand", "arc4random", "arc4random_uniform", "SecRandomCopyBytes", "CCRandomGenerateBytes"].forEach(function (n) {
  var f = exp(n);
  if (f) Interceptor.attach(f, { onEnter: function () { if (inSha) return; counts[n] = (counts[n] || 0) + 1; if (counts[n] === 1) emit({ type: "crypto", api: n, first: true, caller: bt(this.context) }); } });
});
var skr = exp("SecKeyCreateRandomKey");
if (skr) Interceptor.attach(skr, { onEnter: function (a) {
  var d = new ObjC.Object(a[0]).toString();
  emit({ type: "crypto", api: "SecKeyCreateRandomKey", secureEnclave: d.indexOf("com.apple.setoken") >= 0,
         accessControl: d.indexOf("accc") >= 0, permanent: /perm\W*=\W*1/.test(d), caller: bt(this.context) });
} });
setInterval(function () {
  var c = {};
  ["CC_MD5", "CC_SHA1", "rand", "random", "arc4random", "SecRandomCopyBytes", "CCRandomGenerateBytes"].forEach(function (n) { if (counts[n]) c[n] = counts[n]; });
  if (Object.keys(c).length) emit({ type: "crypto-counts", counts: c });
}, 15000);
console.log("[crypto_trace] running");
