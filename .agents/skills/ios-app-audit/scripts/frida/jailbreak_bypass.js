// APPROVAL REQUIRED. Hides jailbreak indicators (paths, URL schemes, sandbox writes, fork, injected
// dylib names, DYLD_INSERT_LIBRARIES) so jailbreak-gated behaviour can be tested on your own build.
// Same hooks as jailbreak_detect_trace.js with BYPASS = true; keep the two files in sync.
// Usage: frida -U -f <bundle> -l jailbreak_bypass.js
var BYPASS = true;
function exp(n) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(n); } catch (e) {}
  try { return Module.findExportByName(null, n); } catch (e) { return null; }
}
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 3).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join(" < "); }
  catch (e) { return ""; }
}
var JB = /(Cydia|Sileo|Zebra|Filza|MobileSubstrate|substrate|substitute|libhooker|TweakInject|ElleKit|\/bin\/bash|\/bin\/sh$|\/usr\/sbin\/sshd|\/usr\/bin\/ssh|\/etc\/apt|\/var\/lib\/apt|\/var\/lib\/cydia|\/private\/var\/stash|\/var\/jb|\/\.bootstrapped|\/\.installed_|\/usr\/libexec\/cydia|frida|\/private\/jailbreak|checkra1n|palera1n|Dopamine)/i;
var SCHEMES = /^(cydia|sileo|zbra|filza|undecimus|activator|installer):/i;
var INJECTED = /(frida|substrate|substitute|libhooker|TweakInject|ellekit|cycript|SSLKillSwitch)/i;
var seen = {};
function report(kind, what, ctx) {
  var k = kind + "|" + what;
  if (seen[k]) return;
  seen[k] = 1;
  emit({ type: "jailbreak-check", kind: kind, target: what, blocked: BYPASS, caller: bt(ctx) });
}
if (ObjC.available) {
  var FM = ObjC.classes.NSFileManager;
  ["- fileExistsAtPath:", "- fileExistsAtPath:isDirectory:", "- isReadableFileAtPath:", "- contentsOfDirectoryAtPath:error:"].forEach(function (sel) {
    if (!FM[sel]) return;
    Interceptor.attach(FM[sel].implementation, {
      onEnter: function (a) { this.p = new ObjC.Object(a[2]).toString(); this.hit = JB.test(this.p); if (this.hit) report("NSFileManager " + sel, this.p, this.context); },
      onLeave: function (r) { if (this.hit && BYPASS) r.replace(ptr(0)); }
    });
  });
  var UIA = ObjC.classes.UIApplication;
  if (UIA && UIA["- canOpenURL:"]) {
    Interceptor.attach(UIA["- canOpenURL:"].implementation, {
      onEnter: function (a) { this.u = new ObjC.Object(a[2]).absoluteString().toString(); this.hit = SCHEMES.test(this.u); if (this.hit) report("canOpenURL", this.u, this.context); },
      onLeave: function (r) { if (this.hit && BYPASS) r.replace(ptr(0)); }
    });
  }
  var NSS = ObjC.classes.NSString;
  if (NSS && NSS["- writeToFile:atomically:encoding:error:"]) {
    Interceptor.attach(NSS["- writeToFile:atomically:encoding:error:"].implementation, {
      onEnter: function (a) { var p = new ObjC.Object(a[2]).toString(); this.hit = /^\/private\/(?!var\/mobile\/Containers)/.test(p); if (this.hit) report("sandbox write", p, this.context); },
      onLeave: function (r) { if (this.hit && BYPASS) r.replace(ptr(0)); }
    });
  }
}
["stat", "lstat", "stat64", "lstat64", "access", "faccessat", "open", "fopen", "opendir", "realpath", "statfs", "getattrlist"].forEach(function (n) {
  var f = exp(n);
  if (!f) return;
  Interceptor.attach(f, {
    onEnter: function (a) {
      try { this.p = a[n === "faccessat" ? 1 : 0].readUtf8String(); } catch (e) { this.p = null; }
      this.hit = !!this.p && JB.test(this.p);
      if (this.hit) report(n, this.p, this.context);
    },
    onLeave: function (r) { if (this.hit && BYPASS) r.replace(ptr(n === "fopen" || n === "opendir" || n === "realpath" ? 0 : -1)); }
  });
});
var fk = exp("fork");
if (fk) Interceptor.attach(fk, { onEnter: function () { report("fork", "fork()", this.context); }, onLeave: function (r) { if (BYPASS) r.replace(ptr(-1)); } });
var clean = Memory.allocUtf8String("/usr/lib/libSystem.B.dylib");
var gin = exp("_dyld_get_image_name");
if (gin) Interceptor.attach(gin, {
  onLeave: function (r) {
    if (r.isNull()) return;
    var name = r.readUtf8String();
    if (INJECTED.test(name)) { report("_dyld_get_image_name", name, this.context); if (BYPASS) r.replace(clean); }
  }
});
var ge = exp("getenv");
if (ge) Interceptor.attach(ge, {
  onEnter: function (a) { try { this.hit = a[0].readUtf8String() === "DYLD_INSERT_LIBRARIES"; } catch (e) { this.hit = false; } if (this.hit) report("getenv", "DYLD_INSERT_LIBRARIES", this.context); },
  onLeave: function (r) { if (this.hit && BYPASS) r.replace(NULL); }
});
console.log("[jailbreak] " + (BYPASS ? "BYPASS mode: hiding jailbreak indicators" : "trace mode: logging checks only"));
