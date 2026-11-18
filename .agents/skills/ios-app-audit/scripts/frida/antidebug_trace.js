// Trace anti-debugging checks: ptrace(PT_DENY_ATTACH), sysctl KERN_PROC_PID (P_TRACED), getppid,
// isatty, ioctl(TIOCGWINSZ), task_get_exception_ports, syscall(SYS_ptrace) and dlsym("ptrace").
// BYPASS = true (approval required) neutralises PT_DENY_ATTACH and clears P_TRACED.
// Usage: frida -U -f <bundle> -l antidebug_trace.js
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
var counts = {};
function once(key, obj) { counts[key] = (counts[key] || 0) + 1; if (counts[key] <= 3) emit(obj); }

var pt = exp("ptrace");
if (pt) Interceptor.attach(pt, {
  onEnter: function (a) {
    var req = a[0].toInt32();
    once("ptrace" + req, { type: "anti-debug", api: "ptrace", request: req, deny_attach: req === 31, caller: bt(this.context) });
    if (BYPASS && req === 31) a[0] = ptr(-1);
  }
});
var sc = exp("syscall");
if (sc) Interceptor.attach(sc, {
  onEnter: function (a) {
    var n = a[0].toInt32();
    if (n === 26) { // SYS_ptrace
      once("syscall-ptrace", { type: "anti-debug", api: "syscall(SYS_ptrace)", request: a[1].toInt32(), caller: bt(this.context) });
      if (BYPASS && a[1].toInt32() === 31) a[1] = ptr(-1);
    }
  }
});
var sy = exp("sysctl");
if (sy) Interceptor.attach(sy, {
  onEnter: function (a) {
    this.check = false;
    try {
      var mib = a[0];
      if (a[1].toInt32() >= 4 && mib.readS32() === 1 && mib.add(4).readS32() === 14 && mib.add(8).readS32() === 1) {
        this.check = true; this.old = a[2];
        once("sysctl", { type: "anti-debug", api: "sysctl(KERN_PROC_PID)", note: "P_TRACED check", caller: bt(this.context) });
      }
    } catch (e) {}
  },
  onLeave: function (r) {
    if (BYPASS && this.check && !this.old.isNull()) {
      var flags = this.old.add(32).readU32(); // kinfo_proc.kp_proc.p_flag on 64-bit
      if (flags & 0x800) this.old.add(32).writeU32(flags & ~0x800);
    }
  }
});
["getppid", "isatty", "task_get_exception_ports"].forEach(function (n) {
  var f = exp(n);
  if (f) Interceptor.attach(f, { onEnter: function () { once(n, { type: "anti-debug", api: n, caller: bt(this.context) }); } });
});
var io = exp("ioctl");
if (io) Interceptor.attach(io, {
  onEnter: function (a) { if ((a[1].toUInt32() >>> 0) === 0x40087468) once("ioctl", { type: "anti-debug", api: "ioctl(TIOCGWINSZ)", caller: bt(this.context) }); }
});
var ds = exp("dlsym");
if (ds) Interceptor.attach(ds, {
  onEnter: function (a) {
    try { var s = a[1].readUtf8String(); if (/^(ptrace|sysctl|syscall)$/.test(s)) once("dlsym-" + s, { type: "anti-debug", api: "dlsym", symbol: s, caller: bt(this.context) }); } catch (e) {}
  }
});
console.log("[antidebug] " + (BYPASS ? "BYPASS mode" : "trace mode"));
