// Authorized testing only: presents physical-device build properties to emulator checks.
// Changes android.os.Build fields in the process only; nothing on the device is modified.
// Usage: frida -U -f <pkg> -l emulator_bypass.js --no-pause
Java.perform(function () {
  var Build = Java.use("android.os.Build");
  var values = {
    FINGERPRINT: "google/redfin/redfin:13/TQ3A.230805.001/10316531:user/release-keys",
    MODEL: "Pixel 5",
    MANUFACTURER: "Google",
    HARDWARE: "redfin",
    PRODUCT: "redfin",
    BRAND: "google",
    DEVICE: "redfin"
  };
  Object.keys(values).forEach(function (k) {
    try {
      Build[k].value = values[k];
      console.log("[+] Build." + k + " set");
    } catch (e) {
      console.log("[-] could not set Build." + k + ": " + e);
    }
  });
});
