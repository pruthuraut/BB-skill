// Inspects live WKWebView instances (JavaScript enabled, content JavaScript, file and universal
// access from file URLs, popups, inspectable, secure content, user scripts) and counts UIWebView
// instances. Hooks loadFileURL:allowingReadAccessToURL:, loadHTMLString:baseURL:, script message
// handler registration and evaluateJavaScript. Call inspect() again from the REPL on each screen.
// Usage: frida -U -n <App> -l webview_inspect.js
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function red(u) { return String(u).replace(/([?&#][^=&#]*(token|code|key|secret|pass|session|auth)[^=&#]*=)[^&#]+/gi, "$1<redacted>"); }
function tryv(f) { try { return f(); } catch (e) { return null; } }
function inspect() {
  ObjC.schedule(ObjC.mainQueue, function () {
    ObjC.choose(ObjC.classes.WKWebView, {
      onMatch: function (w) {
        var c = w.configuration(), p = c.preferences();
        emit({ type: "webview", class: w.$className, url: tryv(function () { return red(w.URL().absoluteString().toString()); }),
          javaScriptEnabled: tryv(function () { return p.javaScriptEnabled(); }),
          allowsContentJavaScript: tryv(function () { return c.defaultWebpagePreferences().allowsContentJavaScript(); }),
          javaScriptCanOpenWindowsAutomatically: tryv(function () { return p.javaScriptCanOpenWindowsAutomatically(); }),
          allowFileAccessFromFileURLs: tryv(function () { return p.valueForKey_("allowFileAccessFromFileURLs").boolValue(); }),
          allowUniversalAccessFromFileURLs: tryv(function () { return c.valueForKey_("allowUniversalAccessFromFileURLs").boolValue(); }),
          isInspectable: tryv(function () { return w.isInspectable(); }),
          hasOnlySecureContent: tryv(function () { return w.hasOnlySecureContent(); }),
          userScripts: tryv(function () { return c.userContentController().userScripts().count(); }) });
      },
      onComplete: function () {}
    });
    var n = 0;
    if (ObjC.classes.UIWebView) ObjC.choose(ObjC.classes.UIWebView, { onMatch: function () { n++; }, onComplete: function () {} });
    emit({ type: "webview-summary", uiWebViewInstances: n });
  });
}
var W = ObjC.classes.WKWebView;
if (W["- loadFileURL:allowingReadAccessToURL:"]) Interceptor.attach(W["- loadFileURL:allowingReadAccessToURL:"].implementation, { onEnter: function (a) {
  emit({ type: "webview-file", fileURL: new ObjC.Object(a[2]).absoluteString().toString(), readAccess: new ObjC.Object(a[3]).absoluteString().toString() });
} });
if (W["- loadHTMLString:baseURL:"]) Interceptor.attach(W["- loadHTMLString:baseURL:"].implementation, { onEnter: function (a) {
  emit({ type: "webview-html", baseURL: a[3].isNull() ? null : red(new ObjC.Object(a[3]).absoluteString().toString()) });
} });
var U = ObjC.classes.WKUserContentController;
["- addScriptMessageHandler:name:", "- addScriptMessageHandler:contentWorld:name:"].forEach(function (sel) {
  if (U[sel]) Interceptor.attach(U[sel].implementation, { onEnter: function (a) {
    emit({ type: "webview-bridge", handler: new ObjC.Object(a[2]).$className, name: new ObjC.Object(a[sel.indexOf("contentWorld") > 0 ? 4 : 3]).toString() });
  } });
});
var evals = 0;
if (W["- evaluateJavaScript:completionHandler:"]) Interceptor.attach(W["- evaluateJavaScript:completionHandler:"].implementation, { onEnter: function () { evals++; } });
setInterval(function () { if (evals) { emit({ type: "webview-eval", count: evals }); evals = 0; } }, 15000);
setTimeout(inspect, 2000);
rpc.exports = { inspect: inspect };
