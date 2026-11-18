// Traces notification handling: authorization options (critical, provisional, time-sensitive),
// categories and their action options (authenticationRequired, destructive, foreground), local
// notification content (lengths and tags only), foreground presentation, action responses and silent
// pushes (payload keys only).
// Usage: frida -U -f <bundle> -l notification_trace.js
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function tags(s) {
  var t = [];
  if (/\b\d{4,8}\b/.test(s)) t.push("code-like");
  if (/(?:\d[ -]?){13,19}/.test(s)) t.push("digits-13-19");
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(s)) t.push("email");
  if (/\$|€|£|balance|amount|password|otp|code/i.test(s)) t.push("financial-or-auth-words");
  return t;
}
function keys(d) { try { var k = d.allKeys(), out = []; for (var i = 0; i < k.count(); i++) out.push(k.objectAtIndex_(i).toString()); return out; } catch (e) { return []; } }
function hook(cls, sel, cb) { var c = ObjC.classes[cls]; if (c && c[sel]) { Interceptor.attach(c[sel].implementation, cb); return true; } return false; }
var AUTH = [[1, "badge"], [2, "sound"], [4, "alert"], [8, "carPlay"], [16, "criticalAlert"], [32, "providesAppSettings"], [64, "provisional"], [128, "announcement"], [256, "timeSensitive"]];
hook("UNUserNotificationCenter", "- requestAuthorizationWithOptions:completionHandler:", { onEnter: function (a) {
  var o = a[2].toInt32(), n = [];
  AUTH.forEach(function (x) { if (o & x[0]) n.push(x[1]); });
  emit({ type: "notification", api: "requestAuthorization", options: n });
} });
hook("UNUserNotificationCenter", "- setNotificationCategories:", { onEnter: function (a) {
  var cats = new ObjC.Object(a[2]).allObjects();
  for (var i = 0; i < cats.count(); i++) {
    var c = cats.objectAtIndex_(i), acts = c.actions(), list = [];
    for (var j = 0; j < acts.count(); j++) {
      var ac = acts.objectAtIndex_(j), op = ac.options();
      list.push({ id: ac.identifier().toString(), authenticationRequired: (op & 1) !== 0, destructive: (op & 2) !== 0, foreground: (op & 4) !== 0,
                  textInput: ac.$className.indexOf("TextInput") >= 0 });
    }
    var risky = list.filter(function (x) { return !x.authenticationRequired && !x.foreground; }).map(function (x) { return x.id; });
    emit({ type: "notification", api: "category", id: c.identifier().toString(), options: c.options(), actions: list,
           backgroundActionsWithoutAuth: risky, hiddenPreviewsPlaceholder: c.hiddenPreviewsBodyPlaceholder ? String(c.hiddenPreviewsBodyPlaceholder()) : null });
  }
} });
hook("UNUserNotificationCenter", "- addNotificationRequest:withCompletionHandler:", { onEnter: function (a) {
  var r = new ObjC.Object(a[2]), c = r.content();
  var body = c.body() === null ? "" : c.body().toString(), title = c.title() === null ? "" : c.title().toString();
  var lvl = null; try { lvl = c.interruptionLevel(); } catch (e) {}
  emit({ type: "notification", api: "localNotification", titleLen: title.length, bodyLen: body.length, tags: tags(title + " " + body),
         category: c.categoryIdentifier().toString(), thread: c.threadIdentifier().toString(), interruptionLevel: lvl,
         attachments: c.attachments().count(), userInfoKeys: keys(c.userInfo()) });
} });
ObjC.schedule(ObjC.mainQueue, function () {
  var center = ObjC.classes.UNUserNotificationCenter.currentNotificationCenter();
  var d = center.delegate();
  if (d !== null) {
    hook(d.$className, "- userNotificationCenter:willPresentNotification:withCompletionHandler:", { onEnter: function (a) {
      var n = new ObjC.Object(a[3]);
      emit({ type: "notification", api: "willPresent (foreground)", category: n.request().content().categoryIdentifier().toString() });
    } });
    hook(d.$className, "- userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:", { onEnter: function (a) {
      var r = new ObjC.Object(a[3]);
      emit({ type: "notification", api: "didReceiveResponse", action: r.actionIdentifier().toString(),
             userInfoKeys: keys(r.notification().request().content().userInfo()) });
    } });
  }
  var ad = ObjC.classes.UIApplication.sharedApplication().delegate();
  if (ad !== null) {
    hook(ad.$className, "- application:didReceiveRemoteNotification:fetchCompletionHandler:", { onEnter: function (a) {
      var ui = new ObjC.Object(a[3]);
      emit({ type: "notification", api: "remote/silent push", userInfoKeys: keys(ui), contentAvailable: ui.toString().indexOf("content-available") >= 0 });
    } });
    hook(ad.$className, "- application:didRegisterForRemoteNotificationsWithDeviceToken:", { onEnter: function () {
      emit({ type: "notification", api: "deviceToken registered", note: "check where the token is sent (network_trace.js)" });
    } });
  }
});
console.log("[notification_trace] running");
