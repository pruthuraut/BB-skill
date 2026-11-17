// Authorized testing only: run against your own test build on your test device.
// Disables certificate pinning in common stacks so traffic can be inspected.
// Hooks: Conscrypt TrustManagerImpl (Android 7+), OkHttp3 CertificatePinner, Trustkit (if present).
// Usage: frida -U -f <pkg> -l ssl_pinning_bypass.js --no-pause
Java.perform(function () {
  function tryHook(name, fn) {
    try { fn(Java.use(name)); console.log("[+] hooked " + name); }
    catch (e) { /* class not in this app: skip quietly */ }
  }

  tryHook("com.android.org.conscrypt.TrustManagerImpl", function (TM) {
    TM.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host) {
      console.log("[+] TrustManagerImpl.verifyChain accepted for " + host);
      return untrustedChain;
    };
  });

  tryHook("okhttp3.CertificatePinner", function (CP) {
    CP.check.overload("java.lang.String", "java.util.List").implementation = function (host) {
      console.log("[+] okhttp3 CertificatePinner.check skipped for " + host);
    };
  });

  tryHook("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", function (HV) {
    HV.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (host) {
      console.log("[+] Trustkit hostname verify accepted for " + host);
      return true;
    };
  });
});
