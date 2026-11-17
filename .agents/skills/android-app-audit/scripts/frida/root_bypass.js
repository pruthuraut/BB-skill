// Authorized testing only: hides common root indicators so root-gated behaviour can be tested
// on your own test device. Hooks File.exists and Runtime.exec for su, Magisk and Superuser paths.
// Usage: frida -U -f <pkg> -l root_bypass.js --no-pause
Java.perform(function () {
  var rootPath = /(\/su$|\/su\b|Superuser|magisk|\/xbin\/|\/sbin\/su)/i;

  var File = Java.use("java.io.File");
  File.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (rootPath.test(p)) { console.log("[+] hidden root path: " + p); return false; }
    return this.exists();
  };

  var Runtime = Java.use("java.lang.Runtime");
  Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
    if (/(^|\s)(su|which su|magisk)(\s|$)/.test(cmd)) {
      console.log("[+] blocked exec: " + cmd);
      throw Java.use("java.io.IOException").$new("Permission denied");
    }
    return this.exec(cmd);
  };
});
