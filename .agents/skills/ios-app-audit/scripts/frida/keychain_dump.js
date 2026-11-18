// Lists the app's own keychain items (only what its access groups can read) with accessibility class
// (pdmn), access control, synchronizable flag and access group. Item values are never printed: only
// length, a SHA-256 prefix and tags (jwt, email, card). Items that need user auth are skipped
// silently (kSecUseAuthenticationUISkip), so no prompt appears.
// Save the console output and feed it to: ios_container_audit.py --keychain-json <file> --bundle <id>
// Usage: frida -U -f <bundle> -l keychain_dump.js   (or attach with -n after logging in)
function exp(n) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(n); } catch (e) {}
  try { return Module.findExportByName(null, n); } catch (e) { return null; }
}
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function k(n) { var p = exp(n); return p ? p.readPointer() : null; }
function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (x) { return ("0" + x.toString(16)).slice(-2); }).join(""); }
var CC_SHA256 = new NativeFunction(exp("CC_SHA256"), "pointer", ["pointer", "uint32", "pointer"]);
function sha(p, len) { if (p.isNull() || !len) return null; var out = Memory.alloc(32); CC_SHA256(p, len, out); return hex(out.readByteArray(32)).slice(0, 16); }
function tags(s) {
  var t = [];
  if (/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\./.test(s)) t.push("jwt");
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(s)) t.push("email");
  if (/\b(?:\d[ -]?){13,19}\b/.test(s)) t.push("digits-13-19");
  return t;
}
function str(d, key) { var v = d.objectForKey_(key); return v === null ? null : v.toString(); }

function dump() {
  var SecItemCopyMatching = new NativeFunction(exp("SecItemCopyMatching"), "int", ["pointer", "pointer"]);
  var NS = ObjC.classes.NSString;
  var classes = [["genp", "kSecClassGenericPassword"], ["inet", "kSecClassInternetPassword"], ["cert", "kSecClassCertificate"],
                 ["keys", "kSecClassKey"], ["idnt", "kSecClassIdentity"]];
  var total = 0;
  classes.forEach(function (c) {
    var q = ObjC.classes.NSMutableDictionary.alloc().init();
    q.setObject_forKey_(k(c[1]), k("kSecClass"));
    q.setObject_forKey_(k("kSecMatchLimitAll"), k("kSecMatchLimit"));
    q.setObject_forKey_(k("kCFBooleanTrue"), k("kSecReturnAttributes"));
    if (c[0] === "genp" || c[0] === "inet") q.setObject_forKey_(k("kCFBooleanTrue"), k("kSecReturnData"));
    q.setObject_forKey_(k("kSecAttrSynchronizableAny"), k("kSecAttrSynchronizable"));
    if (k("kSecUseAuthenticationUI")) q.setObject_forKey_(k("kSecUseAuthenticationUISkip"), k("kSecUseAuthenticationUI"));
    var out = Memory.alloc(Process.pointerSize);
    out.writePointer(NULL);
    var st = SecItemCopyMatching(q, out);
    if (st !== 0 || out.readPointer().isNull()) return;
    var arr = new ObjC.Object(out.readPointer());
    for (var i = 0; i < arr.count(); i++) {
      var d = arr.objectAtIndex_(i);
      var data = d.objectForKey_(NS.stringWithString_("v_Data"));
      var rec = {
        type: "keychain", class: c[0], acct: str(d, NS.stringWithString_("acct")), svce: str(d, NS.stringWithString_("svce")),
        agrp: str(d, NS.stringWithString_("agrp")), pdmn: str(d, NS.stringWithString_("pdmn")),
        sync: str(d, NS.stringWithString_("sync")), labl: str(d, NS.stringWithString_("labl")),
        accc: d.objectForKey_(NS.stringWithString_("accc")) !== null,
        cdat: str(d, NS.stringWithString_("cdat")), mdat: str(d, NS.stringWithString_("mdat"))
      };
      if (rec.accc) { var ac = d.objectForKey_(NS.stringWithString_("accc")).toString(); rec.acccDesc = ac.slice(0, 160); }
      if (data !== null && data.isKindOfClass_(ObjC.classes.NSData)) {
        rec.dataLen = data.length();
        rec.sha256 = sha(data.bytes(), data.length());
        try { rec.tags = tags(data.bytes().readUtf8String(Math.min(data.length(), 8192))); } catch (e) { rec.tags = []; }
      }
      emit(rec);
      total++;
    }
  });
  console.log("[keychain_dump] " + total + " items");
}
ObjC.schedule(ObjC.mainQueue, function () { setTimeout(dump, 1500); });
rpc.exports = { dump: dump };
