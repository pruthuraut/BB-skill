// Authorized testing only: reports (and can neutralise) the app's debugger checks on your own build.
// Logs every call to Debug.isDebuggerConnected and returns false so debugger-gated paths run.
// Usage: frida -U -f <pkg> -l debug_check.js --no-pause
Java.perform(function () {
  var Debug = Java.use("android.os.Debug");
  Debug.isDebuggerConnected.implementation = function () {
    console.log("[+] Debug.isDebuggerConnected called; returning false");
    return false;
  };
});
