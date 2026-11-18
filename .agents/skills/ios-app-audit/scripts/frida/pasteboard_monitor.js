// Logs pasteboard writes and reads by the app: pasteboard name, operation, length, tags and the
// localOnly / expiration options (without them, items sync over Universal Clipboard and stay until
// overwritten). Contents are never printed. Also reports changeCount changes every 5 seconds.
// Usage: frida -U -n <App> -l pasteboard_monitor.js   then copy from sensitive fields and leave the app
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 2).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join(" < "); }
  catch (e) { return ""; }
}
function tags(s) {
  var t = [];
  if (/eyJ[A-Za-z0-9_-]{8,}\.eyJ/.test(s)) t.push("jwt");
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(s)) t.push("email");
  if (/\b(?:\d[ -]?){13,19}\b/.test(s)) t.push("digits-13-19");
  if (/^\d{4,8}$/.test(s)) t.push("otp-like");
  return t;
}
var PB = ObjC.classes.UIPasteboard;
function name(self) { try { return new ObjC.Object(self).name().toString(); } catch (e) { return "?"; } }
var writes = ["- setString:", "- setStrings:", "- setURL:", "- setItems:", "- addItems:", "- setData:forPasteboardType:", "- setValue:forPasteboardType:"];
writes.forEach(function (sel) {
  if (!PB[sel]) return;
  Interceptor.attach(PB[sel].implementation, { onEnter: function (a) {
    var s = ""; try { s = new ObjC.Object(a[2]).toString(); } catch (e) {}
    emit({ type: "pasteboard", op: "write", sel: sel, pasteboard: name(a[0]), len: s.length, tags: tags(s), options: "none (syncs, no expiry)", caller: bt(this.context) });
  } });
});
if (PB["- setItems:options:"]) {
  Interceptor.attach(PB["- setItems:options:"].implementation, { onEnter: function (a) {
    var opts = new ObjC.Object(a[3]).toString();
    var s = new ObjC.Object(a[2]).toString();
    emit({ type: "pasteboard", op: "write", sel: "- setItems:options:", pasteboard: name(a[0]), len: s.length, tags: tags(s),
           localOnly: opts.indexOf("localOnly") >= 0, expiration: opts.indexOf("expirationDate") >= 0, caller: bt(this.context) });
  } });
}
["- string", "- strings", "- items", "- URL", "- dataForPasteboardType:"].forEach(function (sel) {
  if (!PB[sel]) return;
  Interceptor.attach(PB[sel].implementation, { onEnter: function (a) {
    emit({ type: "pasteboard", op: "read", sel: sel, pasteboard: name(a[0]), caller: bt(this.context) });
  } });
});
var last = -1;
setInterval(function () {
  ObjC.schedule(ObjC.mainQueue, function () {
    var c = PB.generalPasteboard().changeCount();
    if (c !== last) { if (last !== -1) emit({ type: "pasteboard", op: "changeCount", value: c }); last = c; }
  });
}, 5000);
console.log("[pasteboard_monitor] running");
