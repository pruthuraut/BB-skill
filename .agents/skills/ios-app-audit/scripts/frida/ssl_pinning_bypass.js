// APPROVAL REQUIRED. Authorized testing of your own build on your own test device only.
// Disables TLS trust evaluation so Burp can intercept: SecTrustEvaluate(WithError), BoringSSL custom
// verify callbacks (iOS 12+ network stack), AFNetworking AFSecurityPolicy and TrustKit.
// Usage: frida -U -f <bundle> -l ssl_pinning_bypass.js
function exp(n) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(n); } catch (e) {}
  try { return Module.findExportByName(null, n); } catch (e) { return null; }
}
function modExp(m, n) {
  var mod = Process.findModuleByName(m);
  if (!mod) return null;
  try { return mod.findExportByName(n); } catch (e) { return null; }
}
var hooked = [];
var f = exp("SecTrustEvaluateWithError");
if (f) {
  Interceptor.replace(f, new NativeCallback(function (trust, err) {
    if (!err.isNull()) err.writePointer(NULL);
    return 1;
  }, "bool", ["pointer", "pointer"]));
  hooked.push("SecTrustEvaluateWithError");
}
var g = exp("SecTrustEvaluate");
if (g) {
  Interceptor.replace(g, new NativeCallback(function (trust, result) {
    if (!result.isNull()) result.writeU32(1); // kSecTrustResultProceed
    return 0;
  }, "int", ["pointer", "pointer"]));
  hooked.push("SecTrustEvaluate");
}
var verifyOk = new NativeCallback(function (ssl, alert) { return 0; }, "int", ["pointer", "pointer"]);
["SSL_set_custom_verify", "SSL_CTX_set_custom_verify"].forEach(function (name) {
  var p = modExp("libboringssl.dylib", name);
  if (!p) return;
  var orig = new NativeFunction(p, "void", ["pointer", "int", "pointer"]);
  Interceptor.replace(p, new NativeCallback(function (obj, mode, cb) { orig(obj, mode, verifyOk); }, "void", ["pointer", "int", "pointer"]));
  hooked.push(name);
});
var psk = modExp("libboringssl.dylib", "SSL_get_psk_identity");
if (psk) {
  var fake = Memory.allocUtf8String("notarealPSKidentity");
  Interceptor.replace(psk, new NativeCallback(function (ssl) { return fake; }, "pointer", ["pointer"]));
}
if (ObjC.available) {
  var afs = ObjC.classes.AFSecurityPolicy;
  if (afs && afs["- evaluateServerTrust:forDomain:"]) {
    Interceptor.attach(afs["- evaluateServerTrust:forDomain:"].implementation, { onLeave: function (r) { r.replace(ptr(1)); } });
    hooked.push("AFSecurityPolicy");
  }
  var tsk = ObjC.classes.TSKPinningValidator;
  if (tsk && tsk["- evaluateTrust:forHostname:"]) {
    Interceptor.attach(tsk["- evaluateTrust:forHostname:"].implementation, { onLeave: function (r) { r.replace(ptr(0)); } });
    hooked.push("TrustKit");
  }
}
console.log("[ssl_pinning_bypass] hooked: " + hooked.join(", "));
