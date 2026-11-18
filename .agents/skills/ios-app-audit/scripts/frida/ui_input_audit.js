// Defensive audit of the text inputs on the current screen: secureTextEntry, autocorrection and
// spell checking (keyboard cache), textContentType, keyboard type, accessibility identifier and
// whether accessibilityValue reveals the text of a secure field. Also reports screen capture state
// and whether the app rejects third-party keyboards. Text is never printed, only its length.
// Usage: frida -U -n <App> -l ui_input_audit.js   then call audit() on each sensitive screen
function emit(o) { console.log("IOSAUDIT " + JSON.stringify(o)); }
function tryv(f) { try { return f(); } catch (e) { return null; } }
var SENS = /pass|pin|otp|code|card|cvv|cvc|ssn|secret|token|account|iban|routing|security|answer/i;
var MUST_SECURE = /pass|pin|cvv|cvc|secret|security.?code|answer/i;
function audit() {
  ObjC.schedule(ObjC.mainQueue, function () {
    ["UITextField", "UITextView", "UISearchTextField"].forEach(function (cn) {
      var C = ObjC.classes[cn];
      if (!C) return;
      ObjC.choose(C, {
        onMatch: function (v) {
          if (tryv(function () { return v.window(); }) === null) return;
          var r = { type: "input", class: v.$className };
          r.placeholder = tryv(function () { return v.placeholder() === null ? null : v.placeholder().toString(); });
          r.secureTextEntry = tryv(function () { return v.isSecureTextEntry(); });
          r.autocorrectionType = tryv(function () { return v.autocorrectionType(); });
          r.spellCheckingType = tryv(function () { return v.spellCheckingType(); });
          r.textContentType = tryv(function () { var t = v.textContentType(); return t === null ? null : t.toString(); });
          r.keyboardType = tryv(function () { return v.keyboardType(); });
          r.accessibilityIdentifier = tryv(function () { var i = v.accessibilityIdentifier(); return i === null ? null : i.toString(); });
          var txt = tryv(function () { return v.text() === null ? "" : v.text().toString(); }) || "";
          var av = tryv(function () { return v.accessibilityValue() === null ? "" : v.accessibilityValue().toString(); }) || "";
          r.textLength = txt.length;
          r.accessibilityValueRevealsText = !!(txt && av && av.indexOf(txt) >= 0);
          var label = [r.placeholder, r.accessibilityIdentifier, r.textContentType].join(" ");
          r.sensitiveField = SENS.test(label);
          r.issues = [];
          if (MUST_SECURE.test(label) && !r.secureTextEntry) r.issues.push("not secureTextEntry");
          if (r.sensitiveField && !r.secureTextEntry && r.autocorrectionType !== 1) r.issues.push("autocorrection not disabled (keyboard cache)");
          if (r.sensitiveField && !r.secureTextEntry && r.spellCheckingType !== 1) r.issues.push("spell checking not disabled");
          if (r.secureTextEntry && r.accessibilityValueRevealsText) r.issues.push("accessibilityValue reveals secure text");
          emit(r);
        },
        onComplete: function () {}
      });
    });
    var app = ObjC.classes.UIApplication.sharedApplication();
    emit({ type: "ui-defences", screenCaptured: tryv(function () { return ObjC.classes.UIScreen.mainScreen().isCaptured(); }),
           rejectsThirdPartyKeyboards: tryv(function () { return app.delegate().respondsToSelector_(ObjC.selector("application:shouldAllowExtensionPointIdentifier:")); }) });
  });
}
setTimeout(audit, 1500);
rpc.exports = { audit: audit };
