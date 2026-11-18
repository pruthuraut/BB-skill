// Traces incoming URL scheme and universal link handling (app and scene delegates, cold-launch
// connection options), outbound openURL calls (callback leakage), and WKWebView loads, so each deep
// link test case can be tied to the code that handled it. Sensitive query values are redacted.
// Usage: frida -U -f <bundle> -l url_handler_trace.js   then open cases from ios_deeplink.py
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 3).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join(" < "); }
  catch (e) { return ""; }
}
function red(u) { return String(u).replace(/([?&#][^=&#]*(token|code|key|secret|pass|session|auth|sig)[^=&#]*=)[^&#]+/gi, "$1<redacted>"); }
function obj(p) { return p.isNull() ? null : new ObjC.Object(p); }
function hook(cls, sel, cb) {
  var c = ObjC.classes[cls];
  if (!c || !c[sel]) return false;
  Interceptor.attach(c[sel].implementation, cb);
  console.log("[url_handler_trace] hooked -[" + cls + " " + sel.slice(2) + "]");
  return true;
}
function urlOf(o) { try { return red(o.absoluteString().toString()); } catch (e) { return String(o); } }

ObjC.schedule(ObjC.mainQueue, function () {
  var app = ObjC.classes.UIApplication.sharedApplication();
  var del = app.delegate();
  if (del !== null) {
    var dc = del.$className;
    hook(dc, "- application:openURL:options:", { onEnter: function (a) {
      var opts = obj(a[4]); var src = null;
      try { var s = opts.objectForKey_("UIApplicationOpenURLOptionsSourceApplicationKey"); src = s === null ? null : s.toString(); } catch (e) {}
      emit({ type: "url-in", via: "application:openURL:options:", url: urlOf(obj(a[3])), sourceApplication: src, caller: bt(this.context) });
    } });
    hook(dc, "- application:handleOpenURL:", { onEnter: function (a) { emit({ type: "url-in", via: "handleOpenURL (deprecated)", url: urlOf(obj(a[3])) }); } });
    hook(dc, "- application:continueUserActivity:restorationHandler:", { onEnter: function (a) {
      var act = obj(a[3]);
      emit({ type: "activity-in", via: "continueUserActivity", activityType: act.activityType().toString(),
             webpageURL: act.webpageURL() === null ? null : urlOf(act.webpageURL()) });
    } });
  }
  try {
    var scenes = app.connectedScenes().allObjects();
    var done = {};
    for (var i = 0; i < scenes.count(); i++) {
      var sd = scenes.objectAtIndex_(i).delegate();
      if (sd === null || done[sd.$className]) continue;
      done[sd.$className] = 1;
      hook(sd.$className, "- scene:openURLContexts:", { onEnter: function (a) {
        var ctxs = obj(a[3]).allObjects();
        for (var j = 0; j < ctxs.count(); j++) {
          var c = ctxs.objectAtIndex_(j); var src = null;
          try { var s = c.options().sourceApplication(); src = s === null ? null : s.toString(); } catch (e) {}
          emit({ type: "url-in", via: "scene:openURLContexts:", url: urlOf(c.URL()), sourceApplication: src });
        }
      } });
      hook(sd.$className, "- scene:continueUserActivity:", { onEnter: function (a) {
        var act = obj(a[3]);
        emit({ type: "activity-in", via: "scene:continueUserActivity:", activityType: act.activityType().toString(),
               webpageURL: act.webpageURL() === null ? null : urlOf(act.webpageURL()) });
      } });
    }
  } catch (e) {}
  hook("UIApplication", "- openURL:options:completionHandler:", { onEnter: function (a) {
    emit({ type: "url-out", via: "openURL:options:completionHandler:", url: urlOf(obj(a[2])), caller: bt(this.context) });
  } });
  hook("WKWebView", "- loadRequest:", { onEnter: function (a) {
    try { emit({ type: "webview-load", url: urlOf(obj(a[2]).URL()), caller: bt(this.context) }); } catch (e) {}
  } });
  hook("SFSafariViewController", "- initWithURL:", { onEnter: function (a) { emit({ type: "safari-vc", url: urlOf(obj(a[2])) }); } });
});
