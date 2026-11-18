// Traces NSURLSession requests and WebSocket tasks: method, scheme, host, path, names of sensitive
// query parameters and headers, Authorization presence, body size and sensitive body key names.
// Values are never printed. Cleartext http:// and ws:// are flagged. One line per method+host+path.
// Usage: frida -U -f <bundle> -l network_trace.js
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
var SENS = /pass|pwd|secret|token|session|auth|bearer|cookie|api.?key|key$|sig|otp|pin|card|cvv|ssn|email|phone|code/i;
var seen = {};
function describe(req, via) {
  try {
    var url = req.URL();
    if (url === null) return;
    var scheme = url.scheme().toString(), host = url.host() === null ? "" : url.host().toString();
    var path = url.path() === null ? "" : url.path().toString();
    var method = req.HTTPMethod ? (req.HTTPMethod() === null ? "GET" : req.HTTPMethod().toString()) : "GET";
    var key = method + " " + scheme + "://" + host + path;
    if (seen[key]) return;
    seen[key] = 1;
    var q = url.query() === null ? "" : url.query().toString();
    var qs = q.split("&").map(function (x) { return x.split("=")[0]; }).filter(function (k) { return k && SENS.test(k); });
    var headers = [], auth = false;
    var hf = req.allHTTPHeaderFields ? req.allHTTPHeaderFields() : null;
    if (hf !== null) {
      var ks = hf.allKeys();
      for (var i = 0; i < ks.count(); i++) { var h = ks.objectAtIndex_(i).toString(); headers.push(h); if (/authorization|cookie|token|api-?key/i.test(h)) auth = true; }
    }
    var body = req.HTTPBody ? req.HTTPBody() : null, bodyLen = 0, bodyKeys = [];
    if (body !== null) {
      bodyLen = body.length();
      try {
        var s = body.bytes().readUtf8String(Math.min(bodyLen, 16384));
        var m = s.match(/["']?([A-Za-z_][A-Za-z0-9_.-]{1,40})["']?\s*[:=]/g) || [];
        m.forEach(function (x) { var k = x.replace(/["'\s:=]/g, ""); if (SENS.test(k) && bodyKeys.indexOf(k) < 0) bodyKeys.push(k); });
      } catch (e) {}
    }
    emit({ type: "http", via: via, method: method, scheme: scheme, host: host, path: path, cleartext: scheme === "http" || scheme === "ws",
           sensitiveQueryParams: qs, headers: headers, authHeader: auth, bodyLen: bodyLen, sensitiveBodyKeys: bodyKeys });
  } catch (e) {}
}
var S = ObjC.classes.NSURLSession;
["- dataTaskWithRequest:", "- dataTaskWithRequest:completionHandler:", "- uploadTaskWithRequest:fromData:",
 "- uploadTaskWithRequest:fromData:completionHandler:", "- uploadTaskWithRequest:fromFile:", "- uploadTaskWithRequest:fromFile:completionHandler:",
 "- downloadTaskWithRequest:", "- downloadTaskWithRequest:completionHandler:", "- webSocketTaskWithRequest:", "- uploadTaskWithStreamedRequest:"].forEach(function (sel) {
  if (S[sel]) Interceptor.attach(S[sel].implementation, { onEnter: function (a) { describe(new ObjC.Object(a[2]), sel); } });
});
["- dataTaskWithURL:", "- dataTaskWithURL:completionHandler:", "- webSocketTaskWithURL:", "- webSocketTaskWithURL:protocols:"].forEach(function (sel) {
  if (S[sel]) Interceptor.attach(S[sel].implementation, { onEnter: function (a) {
    describe(ObjC.classes.NSURLRequest.requestWithURL_(new ObjC.Object(a[2])), sel);
  } });
});
var C = ObjC.classes.NSURLConnection;
if (C && C["+ sendSynchronousRequest:returningResponse:error:"]) {
  Interceptor.attach(C["+ sendSynchronousRequest:returningResponse:error:"].implementation, { onEnter: function (a) { describe(new ObjC.Object(a[2]), "NSURLConnection sync"); } });
}
console.log("[network_trace] running");
