// Traces SQLite and CoreData query construction: database paths opened, sqlite3_key (SQLCipher) use,
// SQL statements that embed literal values instead of ? bindings (string literals are masked), and
// NSPredicate format strings that compare against quoted literals (concatenated user input).
// Usage: frida -U -f <bundle> -l sqlite_trace.js   then use search, filters and login screens
function exp(n) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(n); } catch (e) {}
  try { return Module.findExportByName(null, n); } catch (e) { return null; }
}
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 3).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join(" < "); }
  catch (e) { return ""; }
}
var seen = {};
function short(p) { return String(p).replace(/^.*\/Containers\/(Data|Shared)\/[^/]+\/[^/]+\//, "<container>/"); }
["sqlite3_open", "sqlite3_open_v2"].forEach(function (n) {
  var f = exp(n);
  if (f) Interceptor.attach(f, { onEnter: function (a) {
    try { var p = a[0].readUtf8String(); if (!seen["o" + p]) { seen["o" + p] = 1; emit({ type: "sqlite-open", path: short(p) }); } } catch (e) {}
  } });
});
["sqlite3_key", "sqlite3_key_v2"].forEach(function (n) {
  var f = exp(n);
  if (f) Interceptor.attach(f, { onEnter: function (a) { emit({ type: "sqlite-key", api: n, keyLen: (n === "sqlite3_key" ? a[2] : a[3]).toInt32(), caller: bt(this.context) }); } });
});
function sql(text, via, ctx) {
  if (!text) return;
  var lits = text.match(/'(?:[^']|'')*'/g) || [];
  var norm = text.replace(/'(?:[^']|'')*'/g, "'?'").replace(/\b\d{4,}\b/g, "N").replace(/\s+/g, " ").slice(0, 300);
  if (/PRAGMA\s+key/i.test(text)) { emit({ type: "sqlite-key", api: "PRAGMA key", caller: bt(ctx) }); return; }
  if (seen["s" + norm]) return;
  seen["s" + norm] = 1;
  var dml = /^\s*(select|insert|update|delete|replace)\b/i.test(text);
  emit({ type: "sql", via: via, sql: norm, literalValues: lits.length, nonParameterized: dml && lits.length > 0, caller: bt(ctx) });
}
["sqlite3_prepare_v2", "sqlite3_prepare_v3", "sqlite3_prepare"].forEach(function (n) {
  var f = exp(n);
  if (f) Interceptor.attach(f, { onEnter: function (a) { try { sql(a[1].readUtf8String(), n, this.context); } catch (e) {} } });
});
var ex = exp("sqlite3_exec");
if (ex) Interceptor.attach(ex, { onEnter: function (a) { try { sql(a[1].readUtf8String(), "sqlite3_exec", this.context); } catch (e) {} } });
var P = ObjC.classes.NSPredicate;
["+ predicateWithFormat:", "+ predicateWithFormat:argumentArray:", "+ predicateWithFormat:arguments:"].forEach(function (sel) {
  if (!P[sel]) return;
  Interceptor.attach(P[sel].implementation, { onEnter: function (a) {
    var fmt = new ObjC.Object(a[2]).toString();
    if (seen["p" + fmt]) return;
    seen["p" + fmt] = 1;
    var literal = /(==|=|!=|CONTAINS|LIKE|BEGINSWITH|ENDSWITH|MATCHES)(\[[cd]+\])?\s*['"][^'"%]+['"]/i.test(fmt);
    emit({ type: "predicate", format: fmt.slice(0, 300), quotedLiteral: literal, usesArguments: fmt.indexOf("%@") >= 0 || fmt.indexOf("%K") >= 0,
           caller: bt(this.context) });
  } });
});
console.log("[sqlite_trace] running");
