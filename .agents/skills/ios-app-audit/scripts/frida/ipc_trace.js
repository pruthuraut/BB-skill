// Traces inter-app and shared-container channels: app group containers and suite UserDefaults,
// Darwin notifications (names), NSUserActivity (type, Handoff/Search/Prediction eligibility, userInfo
// keys), Spotlight indexing, share sheet items, XPC connections, document pickers, security-scoped
// resources, iCloud key-value store and WatchConnectivity messages. Values are never printed.
// Usage: frida -U -f <bundle> -l ipc_trace.js   (also attach to extension processes by name)
function exp(n) {
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(n); } catch (e) {}
  try { return Module.findExportByName(null, n); } catch (e) { return null; }
}
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function s(p) { try { return p.isNull() ? null : new ObjC.Object(p).toString(); } catch (e) { return null; } }
function keys(d) { try { var k = d.allKeys(), out = []; for (var i = 0; i < k.count(); i++) out.push(k.objectAtIndex_(i).toString()); return out; } catch (e) { return []; } }
var seen = {};
function once(k, o) { if (seen[k]) return; seen[k] = 1; emit(o); }
function hook(cls, sel, cb) { var c = ObjC.classes[cls]; if (c && c[sel]) { Interceptor.attach(c[sel].implementation, cb); return true; } return false; }

hook("NSFileManager", "- containerURLForSecurityApplicationGroupIdentifier:", { onEnter: function (a) { once("grp" + s(a[2]), { type: "ipc", api: "appGroupContainer", group: s(a[2]) }); } });
hook("NSUserDefaults", "- initWithSuiteName:", { onEnter: function (a) { once("suite" + s(a[2]), { type: "ipc", api: "suiteDefaults", suite: s(a[2]) }); } });
var cfp = exp("CFNotificationCenterPostNotification");
if (cfp) Interceptor.attach(cfp, { onEnter: function (a) { var n = s(a[1]); once("cfn" + n, { type: "ipc", api: "CFNotificationCenterPost", name: n }); } });
var np = exp("notify_post");
if (np) Interceptor.attach(np, { onEnter: function (a) { var n = a[0].readUtf8String(); once("np" + n, { type: "ipc", api: "notify_post (Darwin)", name: n }); } });
var nr = exp("notify_register_dispatch");
if (nr) Interceptor.attach(nr, { onEnter: function (a) { var n = a[0].readUtf8String(); once("nr" + n, { type: "ipc", api: "notify_register (Darwin)", name: n }); } });
hook("NSUserActivity", "- becomeCurrent", { onEnter: function (a) {
  var u = new ObjC.Object(a[0]);
  emit({ type: "ipc", api: "NSUserActivity.becomeCurrent", activityType: u.activityType().toString(), handoff: u.isEligibleForHandoff(),
         search: u.isEligibleForSearch(), publicIndexing: u.isEligibleForPublicIndexing(),
         prediction: (function () { try { return u.isEligibleForPrediction(); } catch (e) { return null; } })(),
         userInfoKeys: u.userInfo() === null ? [] : keys(u.userInfo()), webpageURL: u.webpageURL() === null ? null : u.webpageURL().host().toString() });
} });
hook("CSSearchableIndex", "- indexSearchableItems:completionHandler:", { onEnter: function (a) {
  var items = new ObjC.Object(a[2]);
  emit({ type: "ipc", api: "CSSearchableIndex.index", items: items.count(), note: "Spotlight shows these on the lock screen search unless protected" });
} });
hook("UIActivityViewController", "- initWithActivityItems:applicationActivities:", { onEnter: function (a) {
  var items = new ObjC.Object(a[2]), cls = [];
  for (var i = 0; i < items.count(); i++) cls.push(items.objectAtIndex_(i).$className);
  emit({ type: "ipc", api: "UIActivityViewController", itemClasses: cls });
} });
hook("UIActivityViewController", "- setExcludedActivityTypes:", { onEnter: function (a) { emit({ type: "ipc", api: "share sheet excluded", types: s(a[2]) }); } });
hook("NSXPCConnection", "- initWithMachServiceName:options:", { onEnter: function (a) { once("xpc" + s(a[2]), { type: "ipc", api: "NSXPCConnection mach", name: s(a[2]) }); } });
hook("NSXPCConnection", "- initWithServiceName:", { onEnter: function (a) { once("xpcs" + s(a[2]), { type: "ipc", api: "NSXPCConnection service", name: s(a[2]) }); } });
hook("NSURL", "- startAccessingSecurityScopedResource", { onEnter: function (a) { emit({ type: "ipc", api: "securityScopedResource", url: new ObjC.Object(a[0]).lastPathComponent().toString() }); } });
hook("UIDocumentPickerViewController", "- initForOpeningContentTypes:asCopy:", { onEnter: function (a) { emit({ type: "ipc", api: "documentPicker", asCopy: a[3].toInt32() !== 0 }); } });
hook("NSUbiquitousKeyValueStore", "- setObject:forKey:", { onEnter: function (a) { once("kvs" + s(a[3]), { type: "ipc", api: "iCloud KV store set", key: s(a[3]) }); } });
hook("WCSession", "- sendMessage:replyHandler:errorHandler:", { onEnter: function (a) { emit({ type: "ipc", api: "WCSession.sendMessage", keys: keys(new ObjC.Object(a[2])) }); } });
hook("WCSession", "- transferUserInfo:", { onEnter: function (a) { emit({ type: "ipc", api: "WCSession.transferUserInfo", keys: keys(new ObjC.Object(a[2])) }); } });
hook("NSExtensionContext", "- inputItems", { onLeave: function (r) { try { once("ext-in", { type: "ipc", api: "NSExtensionContext.inputItems", count: new ObjC.Object(r).count() }); } catch (e) {} } });
console.log("[ipc_trace] running");
