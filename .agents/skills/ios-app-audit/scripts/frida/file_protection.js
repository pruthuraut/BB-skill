// Lists every regular file in the app's data container (and app group containers in SUITES) with its
// Data Protection class (NSFileProtectionKey), size, POSIX permissions and backup exclusion flag.
// Save the console output and feed it to: ios_container_audit.py --protection-json <file>
// Usage: frida -U -n <App> -l file_protection.js
var SUITES = [];
var MAX = 20000;
function exp(n) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(n); } catch (e) {}
  try { return Module.findExportByName(null, n); } catch (e) { return null; }
}
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function walk(root, label) {
  var fm = ObjC.classes.NSFileManager.defaultManager();
  var NS = ObjC.classes.NSString;
  var en = fm.enumeratorAtPath_(root);
  if (en === null) return 0;
  var n = 0, p;
  var kType = NS.stringWithString_("NSFileType"), kProt = NS.stringWithString_("NSFileProtectionKey");
  var kSize = NS.stringWithString_("NSFileSize"), kPerm = NS.stringWithString_("NSFilePosixPermissions");
  var kExcl = NS.stringWithString_("NSURLIsExcludedFromBackupKey");
  while ((p = en.nextObject()) !== null && n < MAX) {
    var full = root + "/" + p.toString();
    var attrs = fm.attributesOfItemAtPath_error_(full, NULL);
    if (attrs === null) continue;
    var type = attrs.objectForKey_(kType);
    if (type === null || type.toString() !== "NSFileTypeRegular") continue;
    var prot = attrs.objectForKey_(kProt), size = attrs.objectForKey_(kSize), perm = attrs.objectForKey_(kPerm);
    var excluded = null;
    try {
      var url = ObjC.classes.NSURL.fileURLWithPath_(full);
      var out = Memory.alloc(Process.pointerSize);
      out.writePointer(NULL);
      url.getResourceValue_forKey_error_(out, kExcl, NULL);
      if (!out.readPointer().isNull()) excluded = new ObjC.Object(out.readPointer()).boolValue();
    } catch (e) {}
    emit({ type: "file", root: label, path: full, protection: prot === null ? null : prot.toString(),
           size: size === null ? null : parseInt(size.toString(), 10), perm: perm === null ? null : parseInt(perm.toString(), 10).toString(8),
           excludedFromBackup: excluded });
    n++;
  }
  return n;
}
ObjC.schedule(ObjC.mainQueue, function () {
  var home = new ObjC.Object(new NativeFunction(exp("NSHomeDirectory"), "pointer", [])()).toString();
  var n = walk(home, "data");
  var fm = ObjC.classes.NSFileManager.defaultManager();
  SUITES.forEach(function (g) {
    var u = fm.containerURLForSecurityApplicationGroupIdentifier_(g);
    if (u !== null) n += walk(u.path().toString(), "group:" + g);
  });
  console.log("[file_protection] " + n + " files under " + home);
});
