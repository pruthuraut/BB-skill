// Traces LocalAuthentication use: evaluatePolicy (policy, reason), canEvaluatePolicy, and whether
// keychain reads carry an operation prompt or LAContext (a sign the secret is bound to biometry).
// BYPASS = true (APPROVAL REQUIRED) forces the evaluatePolicy reply to success. If the protected
// feature then unlocks, the app relies on a boolean-only biometric gate (finding). If it stays
// locked because a keychain item with access control is still required, the gate holds.
// Usage: frida -U -f <bundle> -l biometric_trace.js
var BYPASS = false;
function exp(n) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(n); } catch (e) {}
  try { return Module.findExportByName(null, n); } catch (e) { return null; }
}
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 3).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join(" < "); }
  catch (e) { return ""; }
}
var POLICY = { 1: "biometrics", 2: "deviceOwnerAuthentication", 3: "watch", 4: "biometricsOrWatch" };
var LA = ObjC.classes.LAContext;
if (LA && LA["- evaluatePolicy:localizedReason:reply:"]) {
  Interceptor.attach(LA["- evaluatePolicy:localizedReason:reply:"].implementation, { onEnter: function (a) {
    var policy = a[2].toInt32();
    emit({ type: "biometric", api: "evaluatePolicy", policy: POLICY[policy] || policy, reason: new ObjC.Object(a[3]).toString(),
           bypass: BYPASS, caller: bt(this.context) });
    if (BYPASS) {
      var block = new ObjC.Block(a[4]);
      var orig = block.implementation;
      block.implementation = function (success, error) {
        console.log("[biometric_trace] forcing reply success=YES (was " + success + ")");
        orig(true, null);
      };
    }
  } });
}
if (LA && LA["- canEvaluatePolicy:error:"]) {
  Interceptor.attach(LA["- canEvaluatePolicy:error:"].implementation, {
    onEnter: function (a) { this.p = a[2].toInt32(); },
    onLeave: function (r) { emit({ type: "biometric", api: "canEvaluatePolicy", policy: POLICY[this.p] || this.p, result: r.toInt32() }); }
  });
}
var scm = exp("SecItemCopyMatching");
if (scm) Interceptor.attach(scm, { onEnter: function (a) {
  try {
    var d = new ObjC.Object(a[0]).toString();
    if (d.indexOf("u_OpPrompt") >= 0 || d.indexOf("u_AuthCtx") >= 0 || d.indexOf("u_AuthUI") >= 0) {
      emit({ type: "biometric", api: "SecItemCopyMatching", keychainBound: true, note: "query carries an auth prompt or LAContext", caller: bt(this.context) });
    }
  } catch (e) {}
} });
var acf = exp("SecAccessControlCreateWithFlags");
if (acf) Interceptor.attach(acf, { onEnter: function (a) {
  var f = a[2].toUInt32 ? a[2].toUInt32() : a[2].toInt32();
  var names = [];
  [[1, "userPresence"], [2, "biometryAny"], [8, "biometryCurrentSet"], [16, "devicePasscode"], [32, "watch"], [0x4000, "or"], [0x8000, "and"],
   [0x40000000, "privateKeyUsage"], [0x80000000, "applicationPassword"]].forEach(function (x) { if (f & x[0]) names.push(x[1]); });
  emit({ type: "biometric", api: "SecAccessControlCreateWithFlags", flags: names, caller: bt(this.context) });
} });
console.log("[biometric_trace] " + (BYPASS ? "BYPASS mode" : "trace mode"));
