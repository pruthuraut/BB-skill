// Dumps NSUserDefaults (standard and app group suites) with redacted values: key, type, length,
// sensitive-name flag and tags (jwt, email, card-like digits). Apple and system keys are skipped.
// Set SUITES to the app group ids from ios_static.py (entitlements.app_groups).
// Usage: frida -U -n <App> -l userdefaults_dump.js   (attach after logging in; rerun after logout)
var SUITES = [];
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
var SENS = /pass|pwd|secret|token|session|auth|bearer|cookie|api.?key|private|credential|cvv|card|ssn|pin|otp|refresh|jwt/i;
var SKIP = /^(NS|Apple|AK|com\.apple|WebKit|PK|MSV|INNext|METAL|CK|kCF|AddingEmojiKeybordHandled|_|UI)/;
function red(s) { return s.length <= 8 ? "<redacted>" : s.slice(0, 4) + "..." + s.slice(-2) + " (len " + s.length + ")"; }
function tags(s) {
  var t = [];
  if (/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\./.test(s)) t.push("jwt");
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(s)) t.push("email");
  if (/\b(?:\d[ -]?){13,19}\b/.test(s)) t.push("digits-13-19");
  return t;
}
function dumpDefaults(ud, name) {
  var d = ud.dictionaryRepresentation();
  var keys = d.allKeys();
  var n = 0;
  for (var i = 0; i < keys.count(); i++) {
    var key = keys.objectAtIndex_(i).toString();
    if (SKIP.test(key)) continue;
    var v = d.objectForKey_(keys.objectAtIndex_(i));
    var s = v === null ? "" : v.toString();
    emit({ type: "userdefaults", suite: name, key: key, valueClass: v === null ? null : v.$className, len: s.length,
           preview: red(s), sensitiveName: SENS.test(key), tags: tags(s) });
    n++;
  }
  console.log("[userdefaults] " + name + ": " + n + " app keys");
}
ObjC.schedule(ObjC.mainQueue, function () {
  dumpDefaults(ObjC.classes.NSUserDefaults.standardUserDefaults(), "standard");
  SUITES.forEach(function (s) {
    var ud = ObjC.classes.NSUserDefaults.alloc().initWithSuiteName_(s);
    if (ud) dumpDefaults(ud, s);
  });
});
