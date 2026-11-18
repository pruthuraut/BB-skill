// Searches the app's writable memory for known test markers (UTF-8 and UTF-16LE), for example the
// test password typed at login or a test card number. Run it after login, after logout, and after
// backgrounding; a hit after logout or backgrounding means the secret is retained. Reports counts and
// the mapped file or region only, never memory contents.
// Usage: frida -U -n <App> -l memory_marker_scan.js -P '{"markers":["Pw!mark-7731"]}'
//        then call scan() in the REPL after each step.
var MARKERS = [];
var MAX_RANGE = 256 * 1024 * 1024;
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function red(m) { return m.length <= 4 ? "****" : m.slice(0, 2) + "***" + m.slice(-1); }
function hexBytes(arr) { return arr.map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join(" "); }
function utf8(m) { var s = unescape(encodeURIComponent(m)), out = []; for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i)); return out; }
function utf16(m) { var out = []; for (var i = 0; i < m.length; i++) { var c = m.charCodeAt(i); out.push(c & 0xff, c >> 8); } return out; }
function scan(label) {
  if (!MARKERS.length) { console.log("[memory_marker_scan] no markers: pass -P '{\"markers\":[\"...\"]}' or set MARKERS"); return []; }
  var ranges = Process.enumerateRanges({ protection: "rw-", coalesce: true });
  var results = [];
  MARKERS.forEach(function (m) {
    [["utf8", utf8(m)], ["utf16le", utf16(m)]].forEach(function (p) {
      var pat = hexBytes(p[1]), total = 0, where = [];
      ranges.forEach(function (r) {
        if (r.size > MAX_RANGE) return;
        try {
          var hits = Memory.scanSync(r.base, r.size, pat);
          if (hits.length) { total += hits.length; where.push((r.file ? r.file.path.split("/").pop() : "anon") + "@" + r.base + " x" + hits.length); }
        } catch (e) {}
      });
      var o = { type: "memory-scan", step: label || "manual", marker: red(m), encoding: p[0], hits: total, regions: where.slice(0, 10) };
      emit(o);
      results.push(o);
    });
  });
  return results;
}
rpc.exports = {
  init: function (stage, params) { if (params && params.markers) MARKERS = params.markers; },
  scan: function (label) { return scan(label); }
};
setTimeout(function () { scan("initial"); }, 1000);
