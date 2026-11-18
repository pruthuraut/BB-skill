#!/usr/bin/env python3
"""Static audit of an authorized iOS app (IPA or extracted .app). No device, no network.

Pipeline:
  1. Safe IPA extraction (zip-slip and symlink guarded) into artifacts/<bundle>/ipa/ or --work.
  2. Info.plist: identity, ATS, URL schemes, queried schemes, background modes, usage descriptions,
     file sharing, document types, NSUserActivityTypes, Settings.bundle secure fields.
  3. Main binary and every app extension: own Mach-O reader (macho.py) for PIE, canary, ARC, PAC,
     encryption (cryptid), symbols, linked frameworks, code-signature entitlements, team ID.
  4. embedded.mobileprovision: profile type, devices, entitlements, expiry; compared with the binary.
  5. API rules over imported symbols, ObjC selectors and strings: keychain, crypto, random, WebView,
     pasteboard, file protection, logging, unsafe C, TLS and pinning, jailbreak and anti-debug,
     URL handlers, notifications, StoreKit and Apple Pay, IPC, privacy frameworks, screen capture.
  6. Secrets over binary strings and bundle files (redacted), endpoint and cleartext URL inventory,
     deep link route candidates, SDK inventory, CoreData models, GoogleService-Info.plist,
     bundled certificates and keys, hybrid frameworks (React Native, Flutter, Cordova, Unity).
  7. Optional Kali/open-source tools when installed: rabin2 (radare2), ipsw class-dump or class-dump.

Every finding carries checklist IDs (IOS-xxxx). Values are redacted.

Usage:
  ios_static.py --ipa App.ipa --out artifacts/<bundle>/ios-static.json
  ios_static.py --app Payload/App.app --out report.json [--no-tools]
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import tempfile
import zipfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ios_common import (ARTIFACTS, Finding, SENSITIVE_NAME_RE, find_secrets, ids, is_macho, load_plist,  # noqa: E402
                        load_plist_bytes, printable_strings, redact_value, run, safe_extract_zip, snippet,
                        sort_findings, which, write_json)
from macho import MachO  # noqa: E402

# --------------------------------------------------------------------------- reference data
USAGE_KEYS = {
    "NSCameraUsageDescription": ("camera", ["_OBJC_CLASS_$_AVCaptureDevice", "_OBJC_CLASS_$_UIImagePickerController"]),
    "NSMicrophoneUsageDescription": ("microphone", ["_OBJC_CLASS_$_AVAudioRecorder", "_OBJC_CLASS_$_AVAudioSession"]),
    "NSLocationWhenInUseUsageDescription": ("location", ["_OBJC_CLASS_$_CLLocationManager"]),
    "NSLocationAlwaysAndWhenInUseUsageDescription": ("location-always", ["_OBJC_CLASS_$_CLLocationManager"]),
    "NSLocationAlwaysUsageDescription": ("location-always-legacy", ["_OBJC_CLASS_$_CLLocationManager"]),
    "NSContactsUsageDescription": ("contacts", ["_OBJC_CLASS_$_CNContactStore"]),
    "NSPhotoLibraryUsageDescription": ("photos", ["_OBJC_CLASS_$_PHPhotoLibrary", "_OBJC_CLASS_$_UIImagePickerController"]),
    "NSPhotoLibraryAddUsageDescription": ("photos-add", ["_OBJC_CLASS_$_PHPhotoLibrary"]),
    "NSCalendarsUsageDescription": ("calendar", ["_OBJC_CLASS_$_EKEventStore"]),
    "NSCalendarsFullAccessUsageDescription": ("calendar-full", ["_OBJC_CLASS_$_EKEventStore"]),
    "NSRemindersUsageDescription": ("reminders", ["_OBJC_CLASS_$_EKEventStore"]),
    "NSRemindersFullAccessUsageDescription": ("reminders-full", ["_OBJC_CLASS_$_EKEventStore"]),
    "NSHealthShareUsageDescription": ("health-read", ["_OBJC_CLASS_$_HKHealthStore"]),
    "NSHealthUpdateUsageDescription": ("health-write", ["_OBJC_CLASS_$_HKHealthStore"]),
    "NSHomeKitUsageDescription": ("homekit", ["_OBJC_CLASS_$_HMHomeManager"]),
    "NSMotionUsageDescription": ("motion", ["_OBJC_CLASS_$_CMMotionActivityManager", "_OBJC_CLASS_$_CMPedometer"]),
    "NSBluetoothAlwaysUsageDescription": ("bluetooth", ["_OBJC_CLASS_$_CBCentralManager", "_OBJC_CLASS_$_CBPeripheralManager"]),
    "NSBluetoothPeripheralUsageDescription": ("bluetooth-legacy", ["_OBJC_CLASS_$_CBPeripheralManager"]),
    "NSLocalNetworkUsageDescription": ("local-network", ["_OBJC_CLASS_$_NSNetServiceBrowser", "_nw_browser_create"]),
    "NSUserTrackingUsageDescription": ("tracking", ["_OBJC_CLASS_$_ATTrackingManager"]),
    "NSFaceIDUsageDescription": ("face-id", ["_OBJC_CLASS_$_LAContext"]),
    "NSSiriUsageDescription": ("siri", ["_OBJC_CLASS_$_INPreferences"]),
    "NSSpeechRecognitionUsageDescription": ("speech", ["_OBJC_CLASS_$_SFSpeechRecognizer"]),
    "NSFocusStatusUsageDescription": ("focus-status", ["_OBJC_CLASS_$_INFocusStatusCenter"]),
    "NFCReaderUsageDescription": ("nfc", ["_OBJC_CLASS_$_NFCNDEFReaderSession", "_OBJC_CLASS_$_NFCTagReaderSession"]),
    "NSAppleMusicUsageDescription": ("media-library", ["_OBJC_CLASS_$_MPMediaLibrary"]),
}
PRIVACY_IDS = {
    "camera": r"camera access", "microphone": r"microphone access", "location": r"location access",
    "location-always": r"location access", "contacts": r"contacts access", "photos": r"photos access",
    "calendar": r"calendar access", "reminders": r"reminder access", "health-read": r"health kit",
    "health-write": r"health kit", "homekit": r"home kit", "motion": r"motion and fitness",
    "bluetooth": r"Bluetooth access", "local-network": r"local network access", "tracking": r"App Tracking",
    "siri": r"Siri data access", "focus-status": r"focus and Do Not Disturb", "face-id": r"Touch ID/Face ID",
}

EXTENSION_POINTS = {
    "com.apple.share-services": "share", "com.apple.widgetkit-extension": "widget", "com.apple.widget-extension": "today-widget",
    "com.apple.keyboard-service": "custom-keyboard", "com.apple.photo-editing": "photo-editing",
    "com.apple.fileprovider-nonui": "file-provider", "com.apple.fileprovider-actionsui": "file-provider-ui",
    "com.apple.fileprovider-ui": "document-provider-ui", "com.apple.ui-services": "action",
    "com.apple.services": "action", "com.apple.AudioUnit-UI": "audio-unit", "com.apple.AudioUnit": "audio-unit",
    "com.apple.broadcast-services-upload": "broadcast-upload", "com.apple.broadcast-services-setupui": "broadcast-setup",
    "com.apple.callkit.call-directory": "call-directory", "com.apple.intents-service": "intents",
    "com.apple.intents-ui-service": "intents-ui", "com.apple.identitylookup.message-filter": "message-filter",
    "com.apple.networkextension.packet-tunnel": "network-packet-tunnel", "com.apple.networkextension.app-proxy": "network-app-proxy",
    "com.apple.networkextension.filter-data": "network-content-filter", "com.apple.networkextension.dns-proxy": "network-dns-proxy",
    "com.apple.usernotifications.service": "notification-service", "com.apple.usernotifications.content-extension": "notification-content",
    "com.apple.message-payload-provider": "imessage", "com.apple.authentication-services-credential-provider-ui": "credential-provider",
    "com.apple.Safari.web-extension": "safari-web-extension", "com.apple.Safari.content-blocker": "content-blocker",
    "com.apple.spotlight.import": "spotlight-import", "com.apple.quicklook.preview": "quicklook-preview",
    "com.apple.quicklook.thumbnail": "quicklook-thumbnail", "com.apple.deviceactivity.monitor-extension": "device-activity",
    "com.apple.background-asset-downloader-extension": "background-assets",
}

SDK_SIGNATURES = {
    # name: (framework/dylib name fragments, ObjC class or string fragments)
    "Firebase": (["Firebase", "FirebaseCore", "FirebaseAnalytics"], ["FIRApp", "FIROptions"]),
    "Google Analytics": (["GoogleAnalytics", "GoogleAppMeasurement"], ["GAI", "APMAnalytics", "FIRAnalytics"]),
    "Crashlytics": (["Crashlytics", "FirebaseCrashlytics", "Fabric"], ["FIRCrashlytics", "Crashlytics", "Fabric"]),
    "Mixpanel": (["Mixpanel"], ["Mixpanel", "MPNetwork"]),
    "Amplitude": (["Amplitude"], ["Amplitude", "AMPConfig"]),
    "Segment": (["Segment", "Analytics"], ["SEGAnalytics", "SEGAnalyticsConfiguration"]),
    "Branch": (["Branch"], ["Branch", "BNCPreferenceHelper"]),
    "AppsFlyer": (["AppsFlyerLib"], ["AppsFlyerLib"]),
    "Adjust": (["Adjust", "AdjustSdk"], ["ADJAdjust", "Adjust", "ADJConfig"]),
    "Braze": (["Appboy", "BrazeKit"], ["Appboy", "BRZConfiguration", "ABKUser"]),
    "OneSignal": (["OneSignal"], ["OneSignal"]),
    "Pusher": (["PusherSwift", "Pusher"], ["PTPusher", "PusherChannel"]),
    "PubNub": (["PubNub"], ["PubNub", "PNConfiguration"]),
    "Twilio": (["TwilioVoice", "TwilioVideo", "TwilioChatClient", "TwilioConversationsClient"], ["TwilioVoiceSDK", "TVOCallOptions", "TVIRoom"]),
    "SendGrid": (["SendGrid"], ["SendGrid"]),
    "AWS SDK": (["AWSCore", "AWSS3", "AWSCognito", "Amplify"], ["AWSServiceManager", "AWSCognitoCredentialsProvider"]),
    "Azure / MSAL": (["MSAL", "AzureCommunication", "AzureStorageBlob"], ["MSALPublicClientApplication", "AZSCloudStorageAccount"]),
    "Google Cloud / Sign-In": (["GoogleSignIn", "GTMSessionFetcher", "GoogleCloud"], ["GIDSignIn", "GTMSessionFetcher"]),
    "Stripe": (["Stripe", "StripeCore", "StripePaymentSheet"], ["STPAPIClient", "STPPaymentHandler"]),
    "PayPal": (["PayPal", "PayPalCheckout", "PayPalDataCollector"], ["PayPalConfiguration", "PYPLCheckout", "PPDataCollector"]),
    "Braintree": (["Braintree", "BraintreeCore"], ["BTAPIClient", "BTDropInController"]),
    "AdMob": (["GoogleMobileAds"], ["GADMobileAds", "GADBannerView"]),
    "MoPub": (["MoPub", "MoPubSDK"], ["MoPub", "MPAdView"]),
    "IronSource": (["IronSource"], ["IronSource", "ISBannerView"]),
    "Unity Ads": (["UnityAds"], ["UnityAds", "UADSMetaData"]),
    "Vungle": (["VungleSDK", "VungleAdsSDK"], ["VungleSDK", "VungleAds"]),
    "AppLovin": (["AppLovinSDK"], ["ALSdk", "MAAdView"]),
    "InMobi": (["InMobiSDK"], ["IMSdk", "IMBanner"]),
    "Alamofire": (["Alamofire"], ["Alamofire", "ServerTrustManager"]),
    "AFNetworking": (["AFNetworking"], ["AFHTTPSessionManager", "AFSecurityPolicy"]),
    "TrustKit": (["TrustKit"], ["TrustKit", "TSKPinningValidator"]),
    "SDWebImage": (["SDWebImage"], ["SDWebImageManager", "SDImageCache"]),
    "Kingfisher": (["Kingfisher"], ["Kingfisher", "KingfisherManager"]),
    "Nuke": (["Nuke"], ["ImagePipeline"]),
    "SQLCipher": (["SQLCipher"], ["sqlite3_key", "PRAGMA key", "cipher_version"]),
    "Realm": (["Realm", "RealmSwift"], ["RLMRealm", "RLMRealmConfiguration"]),
    "FMDB": (["FMDB"], ["FMDatabase", "FMDatabaseQueue"]),
    "GRDB": (["GRDB"], ["DatabaseQueue", "GRDB"]),
    "KeychainAccess": (["KeychainAccess"], ["KeychainAccess"]),
    "Locksmith": (["Locksmith"], ["Locksmith"]),
    "SAMKeychain": (["SAMKeychain", "SSKeychain"], ["SAMKeychain", "SSKeychain"]),
    "RNCryptor": (["RNCryptor"], ["RNCryptor", "RNEncryptor"]),
    "CryptoSwift": (["CryptoSwift"], ["CryptoSwift"]),
    "SwiftyRSA": (["SwiftyRSA"], ["SwiftyRSA"]),
    "Sentry": (["Sentry"], ["SentrySDK", "SentryClient"]),
    "Bugsnag": (["Bugsnag"], ["Bugsnag"]),
    "Facebook SDK": (["FBSDKCoreKit", "FBSDKLoginKit"], ["FBSDKApplicationDelegate", "FBSDKSettings"]),
    "React Native": (["React", "hermes"], ["RCTBridge", "RCTRootView"]),
    "Flutter": (["Flutter", "App"], ["FlutterEngine", "FlutterViewController"]),
    "Cordova/Capacitor": (["Cordova", "Capacitor"], ["CDVViewController", "CAPBridgeViewController"]),
    "Unity": (["UnityFramework"], ["UnityFramework", "UnityAppController"]),
    "Xamarin/.NET": (["Xamarin", "Mono", "libmonosgen"], ["xamarin_", "mono_jit"]),
}

ROUTE_PARAMS = ["url", "redirect", "redirect_uri", "redirect_url", "redirectUrl", "return_url", "next_url", "returnUrl", "return_to", "returnTo", "next", "callback",
                "callback_url", "continue", "goto", "dest", "destination", "target", "link", "deeplink", "deep_link",
                "webview", "web_url", "path", "file", "page", "token", "access_token", "code", "state", "email", "user_id",
                "userId", "amount", "account", "id", "action", "screen", "route", "html", "js", "query"]

JB_STRINGS = ["/Applications/Cydia.app", "/Library/MobileSubstrate", "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
              "/private/var/lib/apt", "/var/jb", "/usr/lib/libsubstitute", "/usr/lib/substrate", "cydia://", "sileo://",
              "zbra://", "filza://", "undecimus://", "/private/jailbreak.txt", "frida-server", "FridaGadget", "frida-agent",
              "libhooker", "/.bootstrapped", "/usr/libexec/cydia", "checkra1n", "palera1n", "Dopamine"]
NOISE_HOSTS = re.compile(r"(^|\.)(apple\.com|w3\.org|xml\.org|purl\.org|schemas\.|ns\.adobe\.com|"
                         r"openxmlformats\.org|localhost|itunes\.apple\.com)$|^(www\.)?example\.(com|org|net)$", re.I)


def add(findings: list, rule: str, severity: str, title: str, where: str = "", evidence: str = "", *patterns: str):
    findings.append(Finding(rule, severity, title, where, snippet(evidence, 300), ids(*patterns) if patterns else []).as_dict())


# --------------------------------------------------------------------------- extraction
def locate_app(args, report) -> tuple[str, str]:
    if args.app:
        return os.path.abspath(args.app), os.path.abspath(args.work or os.path.dirname(args.app))
    if not zipfile.is_zipfile(args.ipa):
        raise SystemExit("not a zip/IPA: " + args.ipa)
    os.makedirs(ARTIFACTS, exist_ok=True)
    work = os.path.abspath(args.work or tempfile.mkdtemp(prefix="ipa-static-", dir=ARTIFACTS))
    os.makedirs(work, exist_ok=True)
    report["extraction"] = safe_extract_zip(args.ipa, os.path.join(work, "ipa"))
    apps = glob.glob(os.path.join(work, "ipa", "Payload", "*.app"))
    if not apps:
        raise SystemExit("no Payload/*.app in the IPA")
    return apps[0], work


# --------------------------------------------------------------------------- Info.plist
def audit_info_plist(app: str, info: dict, findings: list) -> dict:
    out = {
        "bundle_id": info.get("CFBundleIdentifier"), "name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
        "version": info.get("CFBundleShortVersionString"), "build": info.get("CFBundleVersion"),
        "executable": info.get("CFBundleExecutable"), "min_os": info.get("MinimumOSVersion"),
        "url_schemes": [], "queried_schemes": info.get("LSApplicationQueriesSchemes") or [],
        "background_modes": info.get("UIBackgroundModes") or [], "user_activity_types": info.get("NSUserActivityTypes") or [],
        "usage_descriptions": {}, "document_types": [], "exported_types": [],
    }
    for t in info.get("CFBundleURLTypes") or []:
        for s in t.get("CFBundleURLSchemes") or []:
            out["url_schemes"].append({"scheme": s, "name": t.get("CFBundleURLName"), "role": t.get("CFBundleTypeRole")})
    schemes = [s["scheme"].lower() for s in out["url_schemes"]]
    for s in out["url_schemes"]:
        sc = s["scheme"]
        generic = len(sc) <= 4 or sc.lower() in {"app", "myapp", "login", "auth", "pay", "wallet", "oauth", "callback", "fb", "http", "https"}
        if generic and not re.match(r"^(fb\d+|com\.googleusercontent\.apps\.)", sc):
            add(findings, "url-scheme-generic", "medium", f"short or generic URL scheme '{sc}' can be claimed by another app",
                "Info.plist CFBundleURLTypes", sc, r"scheme hijacking", r"schemes do not conflict", r"scheme confusion")
        elif not re.match(r"^(fb\d+|com\.googleusercontent\.apps\.|db-|msauth|twitterkit-)", sc):
            add(findings, "url-scheme", "info", f"custom URL scheme '{sc}' (any app or web page can open it)",
                "Info.plist CFBundleURLTypes", sc, r"URL schemes and deep links", r"custom URL schemes are properly validated")
        if re.match(r"^com\.googleusercontent\.apps\.|^msauth|^fb\d+", sc):
            add(findings, "oauth-redirect-scheme", "low", f"OAuth redirect scheme '{sc}': confirm PKCE and state are used",
                "Info.plist", sc, r"OAuth token handling", r"account takeover via token theft")
    if len(schemes) != len(set(schemes)):
        add(findings, "url-scheme-duplicate", "low", "duplicate URL scheme declarations", "Info.plist", ",".join(schemes))

    jb = [q for q in out["queried_schemes"] if q.lower() in {"cydia", "sileo", "zbra", "filza", "undecimus", "activator"}]
    if jb:
        add(findings, "jb-url-scheme-detection", "info", "URL scheme jailbreak detection (LSApplicationQueriesSchemes)",
            "Info.plist", ", ".join(jb), r"URL scheme-based jailbreak detection")
    if len(out["queried_schemes"]) > 30:
        add(findings, "queried-schemes-many", "low", f"{len(out['queried_schemes'])} queried URL schemes (app fingerprinting of installed apps)",
            "Info.plist LSApplicationQueriesSchemes", "")

    for mode in out["background_modes"]:
        sev = "medium" if mode in ("location", "voip") else "low" if mode in ("audio", "fetch", "remote-notification", "processing") else "info"
        add(findings, f"background-mode-{mode}", sev, f"background mode '{mode}'", "Info.plist UIBackgroundModes", mode,
            r"background modes security", r"background fetch")

    for key, (label, _cls) in USAGE_KEYS.items():
        if key in info:
            text = str(info.get(key) or "")
            out["usage_descriptions"][label] = text
            pat = PRIVACY_IDS.get(label.replace("-legacy", "").replace("-full", ""), label)
            if len(text.strip()) < 15 or re.search(r"(?i)^(\$\(|todo|test|required|we need|needed|n/?a)", text.strip()):
                add(findings, f"usage-description-weak-{label}", "low", f"vague or placeholder {key}", "Info.plist", text, pat)

    if info.get("UIFileSharingEnabled"):
        add(findings, "itunes-file-sharing", "medium", "UIFileSharingEnabled: Documents/ is visible in Finder/iTunes file sharing",
            "Info.plist", "UIFileSharingEnabled=true", r"iTunes file sharing", r"Documents/Library directories")
    if info.get("LSSupportsOpeningDocumentsInPlace"):
        add(findings, "open-in-place", "low", "LSSupportsOpeningDocumentsInPlace: Documents/ visible in the Files app",
            "Info.plist", "", r"document picker", r"Documents directory")
    for dt in info.get("CFBundleDocumentTypes") or []:
        out["document_types"].append({"name": dt.get("CFBundleTypeName"), "types": dt.get("LSItemContentTypes")})
    if out["document_types"]:
        add(findings, "document-types", "info", f"{len(out['document_types'])} document types the app opens (input from other apps)",
            "Info.plist CFBundleDocumentTypes", str(out["document_types"])[:200], r"validates file content before opening",
            r"validates file types")
    for ut in info.get("UTExportedTypeDeclarations") or []:
        out["exported_types"].append(ut.get("UTTypeIdentifier"))
    if out["user_activity_types"]:
        add(findings, "user-activity-types", "info", "NSUserActivityTypes declared (Handoff, Siri shortcuts, Spotlight)",
            "Info.plist", ", ".join(map(str, out["user_activity_types"]))[:200], r"continueUserActivity", r"Handoff")
    if info.get("UIApplicationExitsOnSuspend") is False or "UIApplicationSupportsIndirectInputEvents" in info:
        pass
    for k in ("UIRequiresPersistentWiFi", "UIApplicationSupportsMultipleScenes"):
        if k in info:
            out[k] = info[k]
    if info.get("ITSAppUsesNonExemptEncryption") is True:
        out["non_exempt_encryption"] = True
    for k, v in info.items():
        if isinstance(v, str) and SENSITIVE_NAME_RE.search(k) and len(v) >= 8 and not k.startswith("NS"):
            add(findings, "info-plist-secret-key", "medium", f"Info.plist key '{k}' looks like a secret", "Info.plist",
                f"{k}={redact_value(v)}", r"hardcoded secrets", r"Info.plist for sensitive configuration")
    sb = os.path.join(app, "Settings.bundle", "Root.plist")
    if os.path.isfile(sb):
        root = load_plist(sb) or {}
        for spec in root.get("PreferenceSpecifiers") or []:
            if spec.get("Type") == "PSTextFieldSpecifier" and SENSITIVE_NAME_RE.search(str(spec.get("Key", ""))):
                add(findings, "settings-bundle-secret", "medium", f"Settings.bundle text field '{spec.get('Key')}' stores a secret in UserDefaults",
                    "Settings.bundle/Root.plist", str(spec.get("Key")), r"UserDefaults for sensitive data")
    return out


def audit_ats(info: dict, findings: list) -> dict:
    ats = info.get("NSAppTransportSecurity") or {}
    out = {"present": bool(ats), "raw_keys": sorted(ats.keys()), "exceptions": {}}
    if ats.get("NSAllowsArbitraryLoads"):
        add(findings, "ats-arbitrary-loads", "high", "NSAllowsArbitraryLoads=YES disables ATS for all connections",
            "Info.plist NSAppTransportSecurity", "NSAllowsArbitraryLoads=true", r"NSAllowsArbitraryLoads", r"ATS .*exceptions",
            r"cleartext HTTP")
    for key, sev in (("NSAllowsArbitraryLoadsInWebContent", "medium"), ("NSAllowsArbitraryLoadsForMedia", "low"),
                     ("NSAllowsLocalNetworking", "low")):
        if ats.get(key):
            add(findings, f"ats-{key}", sev, f"{key}=YES", "Info.plist NSAppTransportSecurity", key,
                r"NSAllowsLocalNetworking" if "Local" in key else r"ATS", r"exception domains")
    for domain, cfg in (ats.get("NSExceptionDomains") or {}).items():
        cfg = cfg or {}
        out["exceptions"][domain] = cfg
        issues = []
        if cfg.get("NSExceptionAllowsInsecureHTTPLoads") or cfg.get("NSTemporaryExceptionAllowsInsecureHTTPLoads"):
            issues.append("insecure HTTP allowed")
        tls = cfg.get("NSExceptionMinimumTLSVersion") or cfg.get("NSTemporaryExceptionMinimumTLSVersion")
        if tls and tls in ("TLSv1.0", "TLSv1.1"):
            issues.append(f"minimum TLS {tls}")
        if cfg.get("NSExceptionRequiresForwardSecrecy") is False or cfg.get("NSTemporaryExceptionRequiresForwardSecrecy") is False:
            issues.append("forward secrecy not required")
        if cfg.get("NSIncludesSubdomains"):
            issues.append("includes subdomains")
        sev = "high" if "insecure HTTP allowed" in issues and not re.search(r"localhost|127\.0\.0\.1", domain) else \
            "medium" if issues else "info"
        add(findings, "ats-exception-domain", sev, f"ATS exception for {domain}: {', '.join(issues) or 'declared'}",
            "Info.plist NSExceptionDomains", str(cfg)[:200], r"ATS exception domains", r"exception domains security",
            r"cleartext HTTP traffic", r"TLS version")
    if not ats:
        out["note"] = "no NSAppTransportSecurity dictionary: ATS defaults apply (HTTPS, TLS 1.2+)"
    return out


# --------------------------------------------------------------------------- entitlements and profile
def parse_profile(app: str) -> dict:
    path = os.path.join(app, "embedded.mobileprovision")
    if not os.path.isfile(path):
        return {"present": False}
    with open(path, "rb") as fh:
        raw = fh.read()
    m = re.search(rb"<\?xml.*?</plist>", raw, re.S)
    pl = load_plist_bytes(m.group(0)) if m else None
    if not isinstance(pl, dict):
        return {"present": True, "parsed": False}
    devices = pl.get("ProvisionedDevices") or []
    kind = "enterprise" if pl.get("ProvisionsAllDevices") else ("development/ad-hoc" if devices else "app-store")
    ents = pl.get("Entitlements") or {}
    if kind == "development/ad-hoc" and ents.get("get-task-allow"):
        kind = "development"
    return {"present": True, "parsed": True, "name": pl.get("Name"), "type": kind, "team": pl.get("TeamIdentifier"),
            "team_name": pl.get("TeamName"), "devices": len(devices), "expires": str(pl.get("ExpirationDate")),
            "created": str(pl.get("CreationDate")), "entitlements": ents, "certificates": len(pl.get("DeveloperCertificates") or [])}


def audit_entitlements(ents: dict, where: str, findings: list, profile: dict | None = None) -> dict:
    ents = ents or {}
    out = {"keys": sorted(ents.keys())}
    if ents.get("get-task-allow"):
        add(findings, "get-task-allow", "high", "get-task-allow=true: debuggers can attach (development build)", where,
            "get-task-allow", r"anti-debugging", r"debug symbols", r"memory dumping via debuggers")
    aps = ents.get("aps-environment")
    if aps:
        out["aps_environment"] = aps
        add(findings, "aps-environment", "info" if aps == "production" else "low", f"push notifications enabled (aps-environment={aps})",
            where, aps, r"remote notification registration", r"device token")
    domains = ents.get("com.apple.developer.associated-domains") or []
    out["associated_domains"] = domains
    for d in domains:
        if "?mode=developer" in d or "?mode=managed" in d:
            add(findings, "associated-domain-mode", "low", f"associated domain with alternate mode: {d}", where, d,
                r"universal links verification")
    if domains:
        add(findings, "associated-domains", "info", f"{len(domains)} associated domains (universal links / webcredentials)",
            where, ", ".join(domains)[:300], r"universal links configuration", r"apple-app-site-association")
    kag = ents.get("keychain-access-groups") or []
    out["keychain_access_groups"] = kag
    team = None
    app_id = ents.get("application-identifier") or ""
    if "." in app_id:
        team = app_id.split(".", 1)[0]
    out["application_identifier"] = app_id
    out["team_id"] = team or ents.get("com.apple.developer.team-identifier")
    if any(g.endswith("*") or g == "*" for g in kag):
        add(findings, "keychain-group-wildcard", "medium", "wildcard keychain-access-groups entitlement", where, ", ".join(kag),
            r"Keychain access group", r"access groups properly isolate")
    if len(kag) > 1:
        add(findings, "keychain-group-sharing", "info", f"{len(kag)} keychain access groups (items can be shared across the team's apps)",
            where, ", ".join(kag)[:200], r"Keychain access group", r"sharing between apps", r"shared keychain items")
    groups = ents.get("com.apple.security.application-groups") or []
    out["app_groups"] = groups
    if groups:
        add(findings, "app-groups", "info", f"app groups {', '.join(groups)} shared with extensions or sibling apps", where,
            "", r"app group container", r"shared app group", r"app group containers securely")
    dp = ents.get("com.apple.developer.default-data-protection")
    out["default_data_protection"] = dp
    if dp != "NSFileProtectionComplete":
        add(findings, "default-data-protection", "low", f"default data protection is {dp or 'not set (CompleteUntilFirstUserAuthentication)'}",
            where, str(dp), r"Data Protection", r"NSFileProtectionComplete on sensitive files", r"encryption at rest")
    flags = {
        "com.apple.developer.usernotifications.critical-alerts": ("medium", "critical alerts entitlement (bypasses mute and Focus)",
                                                                  [r"critical alert", r"critical notification entitlement"]),
        "com.apple.developer.usernotifications.time-sensitive": ("low", "time-sensitive notifications (break through Focus)", [r"Focus"]),
        "com.apple.developer.usernotifications.communication": ("info", "communication notifications", [r"communication notification"]),
        "com.apple.developer.healthkit": ("medium", "HealthKit entitlement", [r"health kit"]),
        "com.apple.developer.homekit": ("medium", "HomeKit entitlement", [r"home kit", r"HomeKit"]),
        "com.apple.developer.siri": ("low", "SiriKit entitlement", [r"Siri"]),
        "com.apple.developer.nfc.readersession.formats": ("low", "NFC reader entitlement", [r"NFC"]),
        "com.apple.developer.networking.networkextension": ("medium", "Network Extension entitlement", [r"network extension"]),
        "com.apple.developer.networking.vpn.api": ("medium", "Personal VPN entitlement", [r"VPN"]),
        "com.apple.developer.networking.multicast": ("low", "multicast networking entitlement", [r"multicast"]),
        "com.apple.developer.icloud-container-identifiers": ("info", "iCloud containers", [r"iCloud", r"CloudKit"]),
        "com.apple.developer.ubiquity-kvstore-identifier": ("info", "iCloud key-value store", [r"NSUbiquitousKeyValueStore", r"iCloud"]),
        "com.apple.developer.in-app-payments": ("info", "Apple Pay merchant IDs", [r"Apple Pay"]),
        "com.apple.developer.pass-type-identifiers": ("info", "Wallet pass types", [r"Wallet"]),
        "com.apple.developer.contacts.notes": ("medium", "contact notes access", [r"contacts"]),
        "com.apple.developer.family-controls": ("medium", "Family Controls (Screen Time)", [r"parental controls"]),
        "com.apple.developer.devicecheck.appattest-environment": ("info", "App Attest enabled", [r"integrity", r"App Attest"]),
        "com.apple.developer.applesignin": ("info", "Sign in with Apple", [r"Sign in with Apple"]),
        "com.apple.developer.associated-appclip-app-identifiers": ("info", "App Clip", [r"App Clips"]),
        "com.apple.developer.kernel.increased-memory-limit": ("info", "increased memory limit", [r"memory exhaustion"]),
        "com.apple.developer.carplay-audio": ("info", "CarPlay", [r"CarPlay"]),
        "com.apple.developer.group-session": ("info", "SharePlay group activities", [r"group activity"]),
        "com.apple.developer.weatherkit": ("info", "WeatherKit", []),
    }
    for key, (sev, title, pats) in flags.items():
        if key in ents:
            add(findings, "ent-" + key.split(".")[-1], sev, title, where, f"{key}={str(ents[key])[:120]}", *pats)
    private = [k for k in ents if k.startswith("com.apple.private.") or k in ("platform-application", "task_for_pid-allow",
                                                                              "com.apple.system-task-ports")]
    if private:
        add(findings, "private-entitlements", "high", "private or platform entitlements (not allowed in App Store apps)", where,
            ", ".join(private), r"entitlements for dangerous permissions", r"sandbox")
    if profile and profile.get("parsed"):
        pent = profile.get("entitlements") or {}
        extra = sorted(set(ents) - set(pent) - {"com.apple.developer.team-identifier"})
        if extra and pent:
            add(findings, "entitlements-not-in-profile", "medium", "binary claims entitlements the provisioning profile does not grant",
                where, ", ".join(extra)[:200], r"code signing verification")
    return out


# --------------------------------------------------------------------------- binary rules
def has(imports: set, *names: str) -> list[str]:
    return [n for n in names if n in imports]


def cls(*names: str) -> list[str]:
    return [f"_OBJC_CLASS_$_{n}" for n in names]


def audit_binary(mo: MachO, label: str, findings: list, strings: list[str], selectors: set) -> dict:
    s = mo.summary()
    where = f"binary {label}"
    imp = mo.imports
    sset = set(strings)
    joined = "\n".join(strings)

    def sel(*names):
        return [n for n in names if n in selectors]

    def strs(*needles):
        return [n for n in needles if n in sset or n in joined]

    if s.get("encrypted"):
        add(findings, "fairplay-encrypted", "info", "binary is FairPlay encrypted (cryptid=1); strings and class names are unreadable",
            where, str(s.get("encryption")), r"class-dump", r"reverse engineering protection")
    if not s["pie"] and s.get("filetype") == "execute":
        add(findings, "no-pie", "high", "executable is not PIE (ASLR disabled)", where, "", r"Address Space Layout", r"position-independent")
    if "ALLOW_STACK_EXECUTION" in s["flags"]:
        add(findings, "stack-exec", "high", "MH_ALLOW_STACK_EXECUTION set", where, "", r"stack protection", r"return-oriented")
    if not s["stack_canary"] and s.get("imports_count", 0) > 20:
        add(findings, "no-stack-canary", "medium", "no ___stack_chk_guard import (compiled without -fstack-protector)", where, "",
            r"stack canary", r"stack protection flags", r"stack buffer overflow")
    if not s["arc"] and s.get("objc"):
        add(findings, "no-arc", "low", "Objective-C code without ARC imports (manual retain/release)", where, "",
            r"ARC", r"use-after-free", r"double-free")
    if s.get("debug_stab_symbols"):
        add(findings, "debug-symbols", "low", f"{s['debug_stab_symbols']} debug (stab) symbols present", where, "",
            r"debug symbols", r"reverse engineering")
    elif not s["stripped"]:
        add(findings, "not-stripped", "low", f"{s['local_symbols']} local symbols present (binary not fully stripped)", where, "",
            r"debug symbols", r"reverse engineering protection")
    if s.get("arm64e"):
        s["pac"] = True
    if s["codesign"].get("flags") and "GET_TASK_ALLOW" in s["codesign"]["flags"]:
        add(findings, "cs-get-task-allow", "high", "code signature allows task port access (get-task-allow)", where, "",
            r"anti-debugging", r"task_for_pid")
    if not s["codesign"].get("present"):
        add(findings, "unsigned", "medium", "no embedded code signature", where, "", r"code signing")

    # unsafe C and memory
    banned = has(imp, "_strcpy", "_strcat", "_sprintf", "_vsprintf", "_gets", "_scanf", "_sscanf", "_strncpy", "_alloca", "_memcpy", "_stpcpy")
    hard = [b for b in banned if b in ("_gets", "_strcpy", "_strcat", "_sprintf", "_vsprintf", "_stpcpy")]
    if hard:
        add(findings, "unsafe-c-functions", "medium" if "_gets" in hard else "low", "unsafe C string functions imported", where,
            ", ".join(banned), r"buffer overflow", r"buffer sizes before copy", r"integer overflow")
    fmt = has(imp, "_printf", "_NSLog", "_NSLogv", "_syslog", "_vprintf", "_os_log_impl", "_fprintf")
    if fmt:
        add(findings, "logging-apis", "low" if "_NSLog" in fmt else "info", "logging APIs imported (check release logging of sensitive data)",
            where, ", ".join(fmt), r"NSLog", r"format string", r"logged without sanitization", r"crash logs")
    if has(imp, "_memset_s") or has(imp, "_explicit_bzero"):
        s["secure_zeroing"] = True
    else:
        add(findings, "no-secure-zeroing", "info", "no memset_s import (sensitive buffers may not be zeroed reliably)", where, "",
            r"secure zeroing", r"clears sensitive data from memory", r"encryption key not zeroed")

    # random and crypto
    weak_rng = has(imp, "_rand", "_srand", "_random", "_srandom", "_drand48", "_lrand48")
    if weak_rng:
        add(findings, "insecure-random", "medium", "non-cryptographic RNG imported", where, ", ".join(weak_rng),
            r"random number generation")
    if has(imp, "_SecRandomCopyBytes"):
        s["secrandom"] = True
    if has(imp, "_CC_MD5", "_CC_MD5_Init", "_CC_SHA1", "_CC_SHA1_Init"):
        add(findings, "weak-hash", "medium", "MD5/SHA1 used (fine for checksums, not for passwords or signatures)", where,
            ", ".join(has(imp, "_CC_MD5", "_CC_MD5_Init", "_CC_SHA1", "_CC_SHA1_Init")), r"weak encryption algorithms", r"CommonCrypto")
    ccc = has(imp, "_CCCrypt", "_CCCryptorCreate", "_CCCryptorCreateWithMode")
    if ccc:
        add(findings, "commoncrypto", "info", "CommonCrypto symmetric crypto (trace mode, key and IV with crypto_trace.js)", where,
            ", ".join(ccc), r"CommonCrypto", r"IV/nonce reuse", r"ECB", r"hardcoded encryption keys")
    if has(imp, "_CCKeyDerivationPBKDF"):
        add(findings, "pbkdf2", "info", "PBKDF2 key derivation (check rounds with crypto_trace.js)", where, "", r"key derivation", r"PBKDF2")
    if any("CryptoKit" in d["name"] for d in mo.dylibs) or "CryptoKit" in joined:
        s["cryptokit"] = True
    if has(imp, "_kSecAttrTokenIDSecureEnclave"):
        s["secure_enclave"] = True
    if strs("kCCOptionECBMode", "AES/ECB", "ECBMode"):
        add(findings, "ecb-string", "medium", "ECB mode referenced in strings", where, "", r"ECB")
    if strs("DES-CBC", "kCCAlgorithmDES", "RC4", "kCCAlgorithmRC4", "3DES"):
        add(findings, "weak-cipher-string", "medium", "DES/3DES/RC4 referenced in strings", where, "", r"weak encryption algorithms")
    if has(imp, "_memcmp", "_strcmp") and (has(imp, "_CCHmac") or ccc):
        add(findings, "non-constant-compare", "info", "memcmp/strcmp alongside HMAC or crypto (check MAC comparison is constant-time)",
            where, "", r"timing attacks", r"secure memory comparison")

    # keychain
    always = has(imp, "_kSecAttrAccessibleAlways", "_kSecAttrAccessibleAlwaysThisDeviceOnly")
    if always:
        add(findings, "keychain-accessible-always", "high", "kSecAttrAccessibleAlways* used (readable while locked; deprecated)", where,
            ", ".join(always), r"kSecAttrAccessible", r"Keychain items with kSecAttrAccessibleAlways", r"protection level")
    afu = has(imp, "_kSecAttrAccessibleAfterFirstUnlock")
    if afu:
        add(findings, "keychain-after-first-unlock", "low", "kSecAttrAccessibleAfterFirstUnlock (migrates to new devices via backup)",
            where, "", r"AfterFirstUnlock", r"item migration", r"backup")
    if has(imp, "_SecItemAdd", "_SecItemUpdate"):
        s["keychain"] = True
        if not has(imp, "_SecAccessControlCreateWithFlags"):
            add(findings, "keychain-no-access-control", "low", "keychain items written without SecAccessControl (no user presence or biometry binding)",
                where, "", r"without kSecAttrAccessControl", r"access control with biometric", r"UserPresence")
        if not (has(imp, "_kSecAttrAccessibleWhenUnlockedThisDeviceOnly", "_kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
                    "_kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly")):
            add(findings, "keychain-not-device-only", "low", "no ThisDeviceOnly accessibility class imported (items may migrate in backups)",
                where, "", r"WhenUnlockedThisDeviceOnly", r"migration between devices", r"backup inclusion")
    if has(imp, "_kSecAttrSynchronizable"):
        add(findings, "keychain-synchronizable", "low", "kSecAttrSynchronizable used (items sync to iCloud Keychain)", where, "",
            r"kSecAttrSynchronizable", r"iCloud keychain")
    if has(imp, "_kSecAttrAccessGroup"):
        add(findings, "keychain-access-group-attr", "info", "kSecAttrAccessGroup set on keychain items", where, "",
            r"Keychain access group", r"sharing between apps")

    # biometrics
    if has(imp, *cls("LAContext")) or sel("evaluatePolicy:localizedReason:reply:"):
        if not has(imp, "_SecAccessControlCreateWithFlags"):
            add(findings, "biometric-boolean", "high", "LAContext evaluatePolicy without keychain access control: a boolean-only biometric gate can be bypassed by hooking",
                where, "", r"Touch ID/Face ID bypass", r"biometric access control", r"bypass biometric", r"LAContext")
        else:
            add(findings, "biometric-keychain", "info", "LAContext with SecAccessControl (check biometry flags with biometric_trace.js)",
                where, "", r"biometric", r"LAContext")

    # WebView
    if has(imp, *cls("UIWebView")):
        add(findings, "uiwebview", "medium", "UIWebView linked (deprecated; JavaScript cannot be disabled, file access defaults open)",
            where, "", r"UIWebView", r"WKWebView configuration", r"JavaScript execution in WebView")
    if has(imp, *cls("WKWebView")):
        s["wkwebview"] = True
        add(findings, "wkwebview", "info", "WKWebView used (inspect configuration with webview_inspect.js)", where, "",
            r"WKWebView configuration", r"JavaScript enabled in WKWebView")
    fa = strs("allowFileAccessFromFileURLs", "allowUniversalAccessFromFileURLs")
    if fa:
        add(findings, "webview-file-access", "high", "WKWebView private file-access preferences set via KVC", where, ", ".join(fa),
            r"allowFileAccessFromFileURLs", r"file access vulnerability", r"isolate web content")
    if sel("loadFileURL:allowingReadAccessToURL:"):
        add(findings, "webview-loadfileurl", "low", "loadFileURL:allowingReadAccessToURL: (check the read-access directory is narrow)",
            where, "", r"file access in WKWebView", r"file URL scheme")
    if sel("addScriptMessageHandler:name:", "addScriptMessageHandler:contentWorld:name:") or has(imp, *cls("JSContext")):
        add(findings, "js-bridge", "medium", "JavaScript-to-native bridge (WKScriptMessageHandler or JSContext): check origin checks on messages",
            where, "", r"inject JavaScript into WKWebView", r"isolate web content from native", r"JavaScript execution")
    if sel("setJavaScriptCanOpenWindowsAutomatically:"):
        add(findings, "webview-js-open-windows", "low", "javaScriptCanOpenWindowsAutomatically set", where, "", r"WKWebView configuration")
    if has(imp, *cls("SFSafariViewController")):
        s["sfsafari"] = True

    # pasteboard
    if has(imp, *cls("UIPasteboard")):
        local = has(imp, "_UIPasteboardOptionLocalOnly", "_UIPasteboardOptionExpirationDate")
        add(findings, "pasteboard", "low" if not local else "info",
            "UIPasteboard used" + ("" if local else " without localOnly/expiration options (Universal Clipboard sync)"),
            where, ", ".join(local), r"pasteboard", r"clipboard", r"Universal Clipboard")

    # files and data protection
    if has(imp, "_NSFileProtectionNone"):
        add(findings, "file-protection-none", "high", "NSFileProtectionNone used", where, "", r"NSFileProtectionNone",
            r"Data Protection", r"protection on")
    if has(imp, "_NSFileProtectionComplete", "_NSURLFileProtectionComplete"):
        s["file_protection_complete"] = True
    if has(imp, "_NSPersistentStoreFileProtectionKey"):
        s["coredata_file_protection"] = True
    if has(imp, "_NSURLIsExcludedFromBackupKey"):
        s["excludes_from_backup"] = True
    else:
        add(findings, "no-backup-exclusion", "info", "NSURLIsExcludedFromBackupKey not used (all Documents/Library files go to backup)",
            where, "", r"backup inclusion", r"excluded from iCloud backup", r"iCloud backup of sensitive")
    if has(imp, *cls("NSUserDefaults")):
        s["userdefaults"] = True
    if sel("unarchiveObjectWithData:", "unarchiveObjectWithFile:") or has(imp, "_NSKeyedUnarchiveFromDataTransformerName"):
        add(findings, "insecure-unarchive", "medium", "NSKeyedUnarchiver without secure coding (object injection from stored or received data)",
            where, "", r"transformable attributes use secure", r"value transformers")
    if sel("predicateWithFormat:", "predicateWithFormat:arguments:"):
        add(findings, "nspredicate-format", "info", "NSPredicate format strings (check user input is passed as an argument, not concatenated)",
            where, "", r"predicate format strings", r"parameterized predicates")
    if has(imp, "_sqlite3_exec", "_sqlite3_prepare_v2", "_sqlite3_open", "_sqlite3_open_v2"):
        s["sqlite"] = True
        if not has(imp, "_sqlite3_key", "_sqlite3_key_v2"):
            add(findings, "sqlite-no-sqlcipher", "low", "SQLite used without sqlite3_key (database not encrypted unless Data Protection covers it)",
                where, "", r"SQLite databases for sensitive data", r"SQLCipher")
    sqlfmt = [x for x in strings if re.search(r"(?i)\b(select|insert|update|delete)\b.{0,120}(%@|%s|\\\(|'\s*\+)", x)][:5]
    if sqlfmt:
        add(findings, "sql-format-string", "medium", "SQL built with format specifiers (SQL injection risk)", where, " | ".join(sqlfmt),
            r"SQL injection in parameters", r"query string manipulation")
    if has(imp, *cls("NSPersistentCloudKitContainer")):
        add(findings, "coredata-cloudkit", "info", "NSPersistentCloudKitContainer (CoreData mirrored to iCloud)", where, "",
            r"CloudKit integration", r"iCloud CoreData sync")
    if has(imp, *cls("CSSearchableIndex")) or sel("setEligibleForSearch:"):
        add(findings, "spotlight-indexing", "low", "Spotlight indexing (CSSearchableIndex or NSUserActivity eligibleForSearch)", where, "",
            r"Spotlight")

    # TLS and network
    if sel("URLSession:didReceiveChallenge:completionHandler:", "connection:willSendRequestForAuthenticationChallenge:",
           "URLSession:task:didReceiveChallenge:completionHandler:"):
        add(findings, "custom-trust-eval", "medium", "custom authentication challenge handler (check server trust is evaluated, not accepted blindly)",
            where, "", r"custom certificate validation", r"server trust evaluation", r"URL session delegate")
    if has(imp, "_SecTrustEvaluate"):
        add(findings, "sectrust-deprecated", "low", "deprecated SecTrustEvaluate used", where, "", r"server trust")
    if strs("setAllowInvalidCertificates:", "allowInvalidCertificates") and has(imp, *cls("AFSecurityPolicy")):
        add(findings, "afn-allow-invalid", "medium", "AFSecurityPolicy allowInvalidCertificates referenced (confirm it is NO in release)",
            where, "", r"AFNetworking", r"pinning")
    if strs("DisabledTrustEvaluator", "DisabledEvaluator"):
        add(findings, "alamofire-disabled-trust", "high", "Alamofire DisabledTrustEvaluator present (TLS validation off for some hosts)",
            where, "", r"Alamofire", r"certificate validation")
    if strs("kCFStreamSSLValidatesCertificateChain"):
        add(findings, "stream-ssl-no-validate", "high", "kCFStreamSSLValidatesCertificateChain referenced (often set to false)",
            where, "", r"certificate validation bypass")
    pinning = []
    if has(imp, "_SecTrustCopyKey", "_SecTrustCopyPublicKey", "_SecCertificateCopyData", "_SecTrustGetCertificateAtIndex",
           "_SecTrustCopyCertificateChain", "_SecTrustSetAnchorCertificates"):
        pinning.append("SecTrust key/cert APIs")
    pinning += [n for n in ("TrustKit", "AFSecurityPolicy", "PinnedCertificatesTrustEvaluator", "PublicKeysTrustEvaluator",
                            "TSKPinningValidator", "NSPinnedDomains") if n in joined]
    s["pinning_signals"] = pinning
    add(findings, "pinning" if pinning else "no-pinning", "info" if pinning else "low",
        "certificate pinning signals: " + ", ".join(pinning) if pinning else "no certificate pinning signals found",
        where, "", r"certificate pinning", r"pinning implementation")
    if has(imp, *cls("NSURLConnection")):
        add(findings, "nsurlconnection", "low", "deprecated NSURLConnection used", where, "", r"API communication security")
    if has(imp, "_CFNetworkCopySystemProxySettings"):
        add(findings, "proxy-detection", "info", "CFNetworkCopySystemProxySettings (proxy detection present)", where, "",
            r"proxy detection", r"proxy configuration")
    if sel("setConnectionProxyDictionary:"):
        add(findings, "proxy-dictionary", "info", "URLSessionConfiguration connectionProxyDictionary set (proxy bypass)", where, "",
            r"proxy configuration")
    if sel("backgroundSessionConfigurationWithIdentifier:"):
        add(findings, "background-urlsession", "info", "background URLSession (transfers continue after the app is suspended)", where, "",
            r"background URL session", r"background transfer")
    if has(imp, *cls("NSURLCredentialStorage")):
        add(findings, "url-credential-storage", "low", "NSURLCredentialStorage used (check persistence is not Permanent)", where, "",
            r"URLCredentialStorage", r"URLCredential storage")
    if has(imp, *cls("NSHTTPCookieStorage")):
        s["cookie_storage"] = True
    if has(imp, *cls("NSURLSessionWebSocketTask")) or "SRWebSocket" in joined or "Starscream" in joined:
        add(findings, "websocket", "info", "WebSocket client present (check wss:// and auth)", where, "", r"WebSocket")
    if has(imp, "_nw_privacy_context_require_encrypted_name_resolution") or sel("setRequireEncryptedNameResolution:fallbackResolver:"):
        add(findings, "encrypted-dns", "info", "encrypted DNS (DoH/DoT) configured", where, "", r"DNS over HTTPS")

    # jailbreak, anti-debug, integrity
    jb = [x for x in JB_STRINGS if x in joined]
    s["jailbreak_strings"] = jb
    add(findings, "jailbreak-detection" if jb else "no-jailbreak-detection", "info" if jb else "low",
        "jailbreak detection strings: " + ", ".join(jb[:8]) if jb else "no jailbreak detection strings found",
        where, "", r"jailbreak detection implementation", r"file-based jailbreak", r"jailbroken")
    anti = has(imp, "_ptrace", "_sysctl", "_getppid", "_isatty", "_ioctl", "_task_get_exception_ports", "_dlsym", "_syscall")
    if "ptrace" in sset or "PT_DENY_ATTACH" in joined:
        anti.append("ptrace string (dlsym)")
    s["anti_debug_signals"] = anti
    if anti:
        add(findings, "anti-debug", "info", "anti-debugging signals: " + ", ".join(anti), where, "", r"anti-debugging", r"P_TRACED")
    dyld = has(imp, "__dyld_image_count", "__dyld_get_image_name", "__dyld_register_func_for_add_image", "_dladdr")
    if dyld or "DYLD_INSERT_LIBRARIES" in joined:
        add(findings, "dylib-injection-detection", "info", "dyld image enumeration or DYLD_INSERT_LIBRARIES check", where,
            ", ".join(dyld), r"dylib injection detection", r"Frida")
    swz = has(imp, "_method_exchangeImplementations", "_class_replaceMethod", "_method_setImplementation", "_method_getImplementation")
    if swz:
        add(findings, "swizzling", "info", "ObjC runtime method replacement APIs (app swizzles, or checks for swizzling)", where,
            ", ".join(swz), r"method swizzling", r"runtime integrity")
    integ = [x for x in ("embedded.mobileprovision", "SignerIdentity", "_CodeSignature", "CodeResources") if x in joined]
    if has(imp, *cls("DCAppAttestService")):
        integ.append("App Attest")
    if has(imp, *cls("DCDevice")):
        integ.append("DeviceCheck")
    s["integrity_signals"] = integ
    add(findings, "integrity-checks" if integ else "no-integrity-checks", "info" if integ else "low",
        "integrity signals: " + ", ".join(integ) if integ else "no re-signing or App Attest integrity signals",
        where, "", r"code signing verification", r"app integrity verification", r"reverse engineering protection")

    # screen capture, keyboards, UI
    cap = has(imp, "_UIApplicationUserDidTakeScreenshotNotification", "_UIScreenCapturedDidChangeNotification") + sel("isCaptured")
    s["screen_capture_detection"] = cap
    if not cap:
        add(findings, "no-screen-capture-detection", "low", "no screenshot or screen recording detection", where, "",
            r"screenshot prevention", r"screen recording protection", r"screenshot protection", r"AssistiveTouch screen")
    if not sel("application:shouldAllowExtensionPointIdentifier:") and not has(imp, "_UIApplicationKeyboardExtensionPointIdentifier"):
        add(findings, "third-party-keyboards-allowed", "low", "app does not reject third-party keyboards", where, "",
            r"custom keyboard", r"Custom keyboard", r"malicious keyboards")
    if sel("setSecureTextEntry:", "isSecureTextEntry"):
        s["secure_text_entry"] = True
    if not sel("applicationDidEnterBackground:", "sceneDidEnterBackground:", "applicationWillResignActive:", "sceneWillResignActive:"):
        add(findings, "no-background-handler", "info", "no background/resign-active handler (snapshot may show sensitive data)", where, "",
            r"backgrounding behavior", r"background transitions")

    # URL handling
    handlers = sel("application:openURL:options:", "application:handleOpenURL:", "application:openURL:sourceApplication:annotation:",
                   "scene:openURLContexts:", "application:continueUserActivity:restorationHandler:", "scene:continueUserActivity:",
                   "scene:willConnectToSession:options:")
    s["url_handlers"] = handlers
    if "application:handleOpenURL:" in handlers or "application:openURL:sourceApplication:annotation:" in handlers:
        add(findings, "deprecated-url-handler", "low", "deprecated URL handler (no options dictionary)", where, ", ".join(handlers),
            r"validate URL scheme before processing")
    if handlers:
        src = has(imp, "_UIApplicationOpenURLOptionsSourceApplicationKey")
        add(findings, "url-handlers", "info", "URL and user-activity handlers: " + ", ".join(handlers), where,
            "sourceApplication read" if src else "sourceApplication not read",
            r"calling application bundle identifier", r"source of deep link", r"continueUserActivity")
    if sel("openURL:options:completionHandler:", "openURL:"):
        add(findings, "outbound-openurl", "info", "app opens URLs in other apps (check callbacks do not carry tokens)", where, "",
            r"callback data leakage", r"exfiltrate data via custom scheme callbacks")

    # notifications
    if has(imp, *cls("UNUserNotificationCenter")):
        s["notifications"] = True
        add(findings, "notifications", "info", "UserNotifications used (check category action options with notification_trace.js)",
            where, "", r"notification actions", r"notification categories")
    if sel("registerForRemoteNotifications") or sel("application:didRegisterForRemoteNotificationsWithDeviceToken:"):
        add(findings, "remote-notifications", "info", "remote notifications registered", where, "", r"device token handling")

    # StoreKit / Apple Pay
    if has(imp, *cls("SKPaymentQueue")) or "StoreKit" in "".join(d["name"] for d in mo.dylibs):
        s["storekit"] = True
        if strs("buy.itunes.apple.com/verifyReceipt", "sandbox.itunes.apple.com/verifyReceipt"):
            add(findings, "receipt-validation-on-device", "high", "app calls Apple verifyReceipt directly (receipt validation on the device can be bypassed)",
                where, "", r"receipt validation bypass", r"receipt validation server communication", r"in-app purchase verification")
        if sel("appStoreReceiptURL"):
            add(findings, "local-receipt", "info", "appStoreReceiptURL read (check the receipt is sent to the server)", where, "",
                r"StoreKit receipt")
    if has(imp, *cls("PKPaymentAuthorizationViewController", "PKPaymentAuthorizationController", "PKPaymentRequest")):
        add(findings, "apple-pay", "info", "Apple Pay used (verify the payment token on the server)", where, "",
            r"Apple Pay payment token", r"Apple Pay session")

    # IPC and sharing
    ipc = has(imp, *cls("NSXPCConnection", "NSUserActivity", "UIActivityViewController", "NSFileCoordinator", "NSUbiquitousKeyValueStore",
                        "CKContainer", "WCSession", "MCSession", "UIDocumentPickerViewController", "INInteraction", "NIDNearbyInteraction")) + \
        has(imp, "_CFNotificationCenterGetDarwinNotifyCenter", "_notify_post", "_notify_register_dispatch")
    ipc += sel("containerURLForSecurityApplicationGroupIdentifier:", "initWithSuiteName:", "startAccessingSecurityScopedResource",
               "bookmarkDataWithOptions:includingResourceValuesForKeys:relativeToURL:error:")
    s["ipc_apis"] = sorted(set(x.replace("_OBJC_CLASS_$_", "") for x in ipc))
    if s["ipc_apis"]:
        add(findings, "ipc-apis", "info", "inter-app and shared-container APIs: " + ", ".join(s["ipc_apis"])[:250], where, "",
            r"IPC between app and extensions", r"Darwin notification", r"app group", r"Handoff", r"UIActivityViewController")

    # privacy frameworks vs usage descriptions (filled later)
    s["privacy_classes"] = sorted({c for _k, (_l, cs) in USAGE_KEYS.items() for c in cs if c in imp})
    if has(imp, *cls("ASIdentifierManager")) or sel("advertisingIdentifier"):
        s["idfa"] = True
    return s


# --------------------------------------------------------------------------- bundle content
def scan_bundle_files(app: str, findings: list, report: dict) -> None:
    secrets, certs, configs, hybrid = [], [], [], []
    for dp, dn, fn in os.walk(app):
        dn[:] = [d for d in dn if not d.endswith((".framework",)) or d in ("App.framework",)]
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, app)
            low = f.lower()
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if low.endswith((".p12", ".pfx", ".pem", ".key")):
                sev = "high" if low.endswith((".p12", ".pfx", ".key")) else "medium"
                with open(p, "rb") as fh:
                    head = fh.read(4096)
                if b"PRIVATE KEY" in head or low.endswith((".p12", ".pfx", ".key")):
                    add(findings, "bundled-private-key", sev, f"private key or PKCS#12 bundled: {rel}", rel, "",
                        r"hardcoded encryption keys", r"hardcoded secrets", r"configuration files in application bundle")
                certs.append(rel)
            elif low.endswith((".cer", ".der", ".crt")):
                certs.append(rel)
            if low in ("googleservice-info.plist",):
                continue
            if low.endswith((".plist", ".json", ".js", ".jsbundle", ".html", ".htm", ".xml", ".txt", ".strings", ".xcconfig",
                             ".env", ".yaml", ".yml", ".properties", ".cfg", ".conf", ".config")) and size < 30 * 1024 * 1024:
                if low.endswith(".plist"):
                    pl = load_plist(p)
                    text = repr(pl) if pl is not None else ""
                else:
                    with open(p, "rb") as fh:
                        text = fh.read().decode("utf-8", "replace")
                hits = find_secrets(text, rel)
                secrets += hits
                if low in ("config.xml",) and 'access origin="*"' in text:
                    add(findings, "cordova-open-access", "medium", "Cordova config.xml allows access origin=*", rel, "",
                        r"WKWebView content security policy", r"ATS")
                if low.endswith((".json", ".plist", ".xcconfig", ".env", ".config", ".cfg")) and re.search(
                        r"(?i)(staging|dev|internal|debug)[\w.-]*\.(com|net|io|org)", text):
                    configs.append(rel)
            if low == "main.jsbundle" or low.endswith(".jsbundle"):
                hybrid.append("React Native bundle " + rel)
            if "flutter_assets" in rel and "flutter_assets" not in "".join(hybrid):
                hybrid.append("Flutter assets")
            if rel.startswith("www" + os.sep) and "Cordova www/" not in hybrid:
                hybrid.append("Cordova www/")
            if low.endswith((".sqlite", ".db", ".sqlite3", ".realm")):
                add(findings, "bundled-database", "low", f"database shipped in the bundle: {rel}", rel, "",
                    r"configuration files in application bundle", r"SQLite databases")
    for h in secrets:
        add(findings, f"secret-{h['type']}", h["severity"], f"{h['type']} in bundle file", h["where"], h["value"],
            r"hardcoded secrets", r"hardcoded encryption keys", r"credential exposure", r"configuration files in application bundle")
    report["bundled_certificates"] = certs
    if certs:
        add(findings, "bundled-certificates", "info", f"{len(certs)} certificates bundled (pinning material or client certs)", "",
            ", ".join(certs[:10]), r"certificate pinning")
    report["environment_config_files"] = configs
    if configs:
        add(findings, "non-prod-hosts", "low", "config files mention staging/dev/internal hosts", "", ", ".join(configs[:10]),
            r"Info.plist for sensitive configuration", r"configuration files in application bundle")
    report["hybrid"] = hybrid


def audit_firebase(app: str, findings: list, work: str) -> dict:
    hits = glob.glob(os.path.join(app, "**", "GoogleService-Info*.plist"), recursive=True)
    if not hits:
        return {"present": False}
    pl = load_plist(hits[0]) or {}
    out = {"present": True, "file": os.path.relpath(hits[0], app), "project_id": pl.get("PROJECT_ID"),
           "database_url": pl.get("DATABASE_URL"), "storage_bucket": pl.get("STORAGE_BUCKET"),
           "api_key": redact_value(pl.get("API_KEY", "")) if pl.get("API_KEY") else None,
           "client_id": pl.get("CLIENT_ID"), "gcm_sender_id": pl.get("GCM_SENDER_ID"),
           "is_analytics_enabled": pl.get("IS_ANALYTICS_ENABLED")}
    add(findings, "firebase-config", "info", f"GoogleService-Info.plist for project {pl.get('PROJECT_ID')} (test rules with firebase_probe.py)",
        out["file"], str({k: out[k] for k in ("project_id", "database_url", "storage_bucket")}),
        r"Firebase/GoogleService-Info.plist", r"Firebase iOS SDK")
    # android firebase_probe.py reads google-services.json; write a compatible file so it can be reused
    compat = {"project_info": {"project_id": pl.get("PROJECT_ID"), "firebase_url": pl.get("DATABASE_URL"),
                               "storage_bucket": pl.get("STORAGE_BUCKET"), "project_number": pl.get("GCM_SENDER_ID")},
              "client": [{"client_info": {"mobilesdk_app_id": pl.get("GOOGLE_APP_ID")},
                          "api_key": [{"current_key": pl.get("API_KEY")}]}]}
    path = os.path.join(work, "google-services.compat.json")
    write_json(path, compat)
    out["firebase_probe_input"] = path
    return out


def audit_coredata(app: str, findings: list) -> list[dict]:
    models = []
    for path in glob.glob(os.path.join(app, "**", "*.mom"), recursive=True):
        pl = load_plist(path)
        strings = []
        if isinstance(pl, dict):
            for o in pl.get("$objects", []):
                if isinstance(o, str) and 1 < len(o) < 80:
                    strings.append(o)
        sensitive = sorted({x for x in strings if SENSITIVE_NAME_RE.search(x) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", x)})
        transformers = sorted({x for x in strings if x.endswith("Transformer") or x.startswith("NS") and "Unarchive" in x})
        rel = os.path.relpath(path, app)
        models.append({"model": rel, "sensitive_attribute_candidates": sensitive[:50], "transformers": transformers})
        if sensitive:
            add(findings, "coredata-sensitive-attributes", "medium", f"CoreData model has sensitive attribute names: {', '.join(sensitive[:8])}",
                rel, "", r"CoreData model for sensitive", r"CoreData database for sensitive", r"CoreData store files are encrypted")
        if any("NSKeyedUnarchiveFromData" in t for t in transformers):
            add(findings, "coredata-insecure-transformer", "medium", "transformable attribute uses NSKeyedUnarchiveFromData (not secure coding)",
                rel, "", r"transformable attributes", r"value transformers")
        if strings and "allowsCloudEncryption" in "".join(strings):
            add(findings, "coredata-cloud-encryption", "info", "CoreData attributes with allowsCloudEncryption", rel, "", r"CloudKit")
    return models


def sdk_inventory(app: str, binaries: dict, classnames: set, joined_strings: str, findings: list) -> list[dict]:
    fws = []
    for fw in sorted(glob.glob(os.path.join(app, "Frameworks", "*.framework")) + glob.glob(os.path.join(app, "Frameworks", "*.dylib"))):
        name = os.path.basename(fw).rsplit(".", 1)[0]
        info = load_plist(os.path.join(fw, "Info.plist")) if fw.endswith(".framework") else None
        fws.append({"name": name, "bundle_id": (info or {}).get("CFBundleIdentifier"),
                    "version": (info or {}).get("CFBundleShortVersionString")})
    dylib_names = " ".join(d["name"] for b in binaries.values() for d in b.get("dylibs", []))
    found = []
    for sdk, (fw_frag, cls_frag) in SDK_SIGNATURES.items():
        ev = []
        for f in fws:
            if any(f["name"] == x or f["name"].startswith(x) for x in fw_frag):
                ev.append(f"framework {f['name']} {f['version'] or ''}".strip())
        if not ev and any(f"/{x}.framework/" in dylib_names for x in fw_frag):
            ev.append("linked framework")
        cls_hits = [c for c in cls_frag if c in classnames or (len(c) > 7 and c in joined_strings)]
        if cls_hits:
            ev.append("classes/strings " + ", ".join(cls_hits[:3]))
        if ev:
            ver = next((f["version"] for f in fws if any(f["name"].startswith(x) for x in fw_frag) and f["version"]), None)
            found.append({"sdk": sdk, "version": ver, "evidence": ev})
    if found:
        add(findings, "sdk-inventory", "info", f"{len(found)} third-party SDKs: " + ", ".join(x["sdk"] for x in found)[:250], "Frameworks/",
            "", r"third-party frameworks", r"iOS SDK")
    for x in found:
        if x["sdk"] in ("MoPub", "Fabric"):
            add(findings, f"sdk-eol-{x['sdk'].lower()}", "medium", f"{x['sdk']} SDK is end-of-life", "", "", x["sdk"], r"third-party frameworks")
        if x["sdk"] == "AFNetworking" and x["version"] and x["version"].startswith(("2.", "1.")):
            add(findings, "afnetworking-old", "high", f"AFNetworking {x['version']} (pre-2.5.3 releases skipped TLS validation)", "", "",
                r"AFNetworking")
    return [{"frameworks": fws}] + found


def endpoints(strings: list[str], findings: list) -> dict:
    urls = set()
    for x in strings:
        for m in re.finditer(r"\b(https?|wss?)://[A-Za-z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]{4,300}", x):
            urls.add(m.group(0).rstrip(".,;'\")"))
    hosts = Counter()
    http, ws = [], []
    for u in urls:
        m = re.match(r"^(\w+)://([^/:?#]+)", u)
        if not m:
            continue
        scheme, host = m.group(1).lower(), m.group(2).lower()
        if NOISE_HOSTS.search(host):
            continue
        hosts[host] += 1
        if scheme == "http" and not re.match(r"^(127\.|10\.|192\.168\.|localhost)", host):
            http.append(u)
        if scheme == "ws":
            ws.append(u)
    if http:
        add(findings, "cleartext-urls", "medium", f"{len(http)} cleartext http:// URLs in the binary", "", " | ".join(sorted(http)[:8]),
            r"cleartext HTTP", r"API communication security", r"bypass app Transport Security")
    if ws:
        add(findings, "cleartext-websocket", "medium", f"{len(ws)} ws:// URLs (unencrypted WebSocket)", "", " | ".join(sorted(ws)[:5]),
            r"WebSocket")
    tok = [u for u in urls if re.search(r"(?i)[?&](token|access_token|api_key|apikey|key|password|secret|session)=", u)]
    if tok:
        add(findings, "secrets-in-url", "medium", "URLs carry tokens or keys in query parameters", "", " | ".join(tok[:5]),
            r"sensitive data in network request parameters")
    return {"hosts": dict(hosts.most_common(200)), "http_urls": sorted(http)[:200], "ws_urls": sorted(ws)[:50], "url_count": len(urls)}


def deeplink_candidates(schemes: list[str], strings: list[str], domains: list[str]) -> dict:
    routes = set()
    low = [s.lower() for s in schemes]
    for x in strings:
        for sc in low:
            for m in re.finditer(r"(?<![A-Za-z0-9+.\-])" + re.escape(sc) + r"://[^\s\"'<>]{0,200}", x, re.I):
                routes.add(m.group(0))
        if re.match(r"^/[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-:{}]+){0,5}/?$", x) and len(x) < 60 and not x.startswith(("/System", "/usr", "/var", "/private", "/Library", "/bin", "/etc", "/dev", "/Applications", "/tmp")):
            routes.add(x)
    params = sorted({p for p in ROUTE_PARAMS if p in set(strings)})
    applinks = [d.split(":", 1)[1].split("?")[0] for d in domains if d.startswith("applinks:")]
    return {"routes": sorted(routes)[:300], "params_seen": params, "applinks_domains": applinks}


# --------------------------------------------------------------------------- extensions
def audit_extensions(app: str, host_ents: dict, findings: list, binaries: dict, all_strings: list, profile: dict) -> list[dict]:
    out = []
    appexes = glob.glob(os.path.join(app, "PlugIns", "*.appex")) + glob.glob(os.path.join(app, "Extensions", "*.appex"))
    for ax in sorted(appexes):
        info = load_plist(os.path.join(ax, "Info.plist")) or {}
        ext = info.get("NSExtension") or info.get("EXAppExtensionAttributes") or {}
        point = ext.get("NSExtensionPointIdentifier") or ext.get("EXExtensionPointIdentifier") or "?"
        kind = EXTENSION_POINTS.get(point, point)
        attrs = ext.get("NSExtensionAttributes") or {}
        name = os.path.basename(ax)
        rec = {"name": name, "bundle_id": info.get("CFBundleIdentifier"), "point": point, "kind": kind}
        exe = os.path.join(ax, info.get("CFBundleExecutable") or name[:-6])
        ents = {}
        if os.path.isfile(exe) and is_macho(exe):
            mo = MachO(exe)
            ents = mo.entitlements or {}
            ss = mo.section_strings()
            sels = set(ss.get("objc_methname", []))
            strs = [x for v in ss.values() for x in v]
            all_strings.extend(strs)
            binaries[f"PlugIns/{name}"] = audit_binary(mo, f"PlugIns/{name}", findings, strs, sels)
        rec["entitlements"] = sorted(ents.keys())
        rec["app_groups"] = ents.get("com.apple.security.application-groups") or []
        rec["keychain_access_groups"] = ents.get("keychain-access-groups") or []
        where = f"PlugIns/{name}"
        if kind == "custom-keyboard":
            ro = attrs.get("RequestsOpenAccess")
            rec["requests_open_access"] = ro
            add(findings, "keyboard-extension", "medium" if ro else "low",
                f"custom keyboard extension (RequestsOpenAccess={bool(ro)})", where, "",
                r"custom keyboard extension", r"Custom keyboard", r"keyboard data access")
        if kind in ("share", "action"):
            rule = attrs.get("NSExtensionActivationRule")
            rec["activation_rule"] = rule
            if rule == "TRUEPREDICATE" or (isinstance(rule, str) and "TRUEPREDICATE" in rule):
                add(findings, "share-truepredicate", "low", f"{kind} extension activates for any input (TRUEPREDICATE)", where, "",
                    r"Share extension data handling", r"Action extension")
            else:
                add(findings, f"{kind}-extension", "info", f"{kind} extension accepts data from other apps", where, str(rule)[:200],
                    r"Share extension", r"Action extension", r"share extension data access")
        elif kind in ("notification-service", "notification-content"):
            add(findings, kind, "info", f"{kind} extension", where, "", r"notification service extension", r"notification content extension")
        elif kind.startswith("network"):
            add(findings, "network-extension", "medium", f"network extension ({kind})", where, "", r"network extension", r"Network extension security")
        elif kind in ("file-provider", "file-provider-ui", "document-provider-ui"):
            add(findings, "file-provider-extension", "info", f"{kind} extension", where, "", r"File provider extension", r"Document provider")
        elif kind in ("widget", "today-widget"):
            add(findings, "widget-extension", "info", "widget extension (reads shared data, shows content on the lock screen)", where, "",
                r"widget extension data", r"Today widget")
        elif kind in ("intents", "intents-ui"):
            add(findings, "intents-extension", "info", "Siri intents extension (check authentication for sensitive intents)", where, "",
                r"Intents extension", r"SiriKit intent handling")
        else:
            add(findings, "app-extension", "info", f"{kind} extension", where, "", r"app extensions security")
        host_groups = set(host_ents.get("com.apple.security.application-groups") or [])
        if set(rec["app_groups"]) - host_groups:
            add(findings, "extension-group-mismatch", "low", "extension uses app groups the host app does not", where,
                ", ".join(set(rec["app_groups"]) - host_groups), r"app group container security", r"entitlements match between app and extensions")
        host_kag = set(host_ents.get("keychain-access-groups") or [])
        if rec["keychain_access_groups"] and set(rec["keychain_access_groups"]) & host_kag:
            add(findings, "extension-shares-keychain", "info", "extension shares a keychain access group with the host app", where,
                ", ".join(set(rec["keychain_access_groups"]) & host_kag), r"isolate keychain items between app and share extension",
                r"keychain item modification by extensions")
        out.append(rec)
    for sub in ("Watch", "AppClips"):
        for a in glob.glob(os.path.join(app, sub, "*.app")):
            out.append({"name": os.path.basename(a), "kind": "watch-app" if sub == "Watch" else "app-clip"})
            add(findings, f"embedded-{sub.lower()}", "info", f"embedded {sub} app {os.path.basename(a)}", sub, "",
                r"App Clips" if sub == "AppClips" else r"watch connectivity")
    return out


# --------------------------------------------------------------------------- external tools
def external_tools(binary: str, work: str, report: dict, enabled: bool) -> None:
    tools = report.setdefault("tools", {})
    if not enabled:
        tools["external"] = {"status": "skipped", "reason": "--no-tools"}
        return
    r2 = which("rabin2")
    if r2:
        rc, out, err = run([r2, "-I", binary], timeout=120)
        rc2, out2, _ = run([r2, "-c", binary], timeout=300)
        path = os.path.join(work, "rabin2-classes.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(out2)
        tools["rabin2"] = {"status": "ok" if rc == 0 else "error", "info": out[:3000], "classes_file": path}
    else:
        tools["rabin2"] = {"status": "skipped", "reason": "radare2 not installed (apt install radare2)"}
    dump_dir = os.path.join(work, "class-dump")
    ipsw, cd = which("ipsw"), which("class-dump", "dsdump")
    if ipsw:
        rc, out, err = run([ipsw, "class-dump", binary, "--headers", "--output", dump_dir], timeout=600)
        tools["ipsw-class-dump"] = {"status": "ok" if rc == 0 else "error", "output": dump_dir, "stderr": err[-500:]}
    elif cd:
        os.makedirs(dump_dir, exist_ok=True)
        rc, out, err = run([cd, "-H", "-o", dump_dir, binary], timeout=600)
        tools["class-dump"] = {"status": "ok" if rc == 0 else "error", "output": dump_dir, "stderr": err[-500:]}
    else:
        tools["class-dump"] = {"status": "skipped", "reason": "install ipsw (go install github.com/blacktop/ipsw/cmd/ipsw@latest) or class-dump"}
    tools["ghidra"] = {"status": "manual", "note": "open the binary in Ghidra (apt install ghidra) for control-flow review"}


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ipa", help="IPA file (decrypted for full string coverage)")
    src.add_argument("--app", help="already extracted .app directory")
    ap.add_argument("--out", help="JSON report path (default artifacts/<bundle>/ios-static.json)")
    ap.add_argument("--work", help="work directory for extraction and tool output")
    ap.add_argument("--no-tools", action="store_true", help="skip rabin2 and class-dump")
    args = ap.parse_args()

    report: dict = {"tools": {}, "findings": []}
    app, work = locate_app(args, report)
    report["work_dir"] = work
    findings: list[dict] = []
    info = load_plist(os.path.join(app, "Info.plist")) or {}
    if not info:
        raise SystemExit("Info.plist missing or unreadable in " + app)
    report["app"] = audit_info_plist(app, info, findings)
    report["ats"] = audit_ats(info, findings)

    exe = os.path.join(app, info.get("CFBundleExecutable") or "")
    if not os.path.isfile(exe) or not is_macho(exe):
        raise SystemExit("main executable not found or not Mach-O: " + exe)
    mo = MachO(exe)
    ss = mo.section_strings()
    strings = [x for v in ss.values() for x in v]
    if mo.summary().get("encrypted") or not strings:
        strings += mo.all_printable()
    selectors = set(ss.get("objc_methname", []))
    classnames = set(ss.get("objc_classname", [])) | {i.replace("_OBJC_CLASS_$_", "") for i in mo.imports if i.startswith("_OBJC_CLASS_$_")}
    binaries = {"main": audit_binary(mo, os.path.basename(exe), findings, strings, selectors)}
    report["profile"] = parse_profile(app)
    ents = mo.entitlements or {}
    report["entitlements_source"] = "code signature" if mo.entitlements is not None else "provisioning profile"
    if mo.entitlements is None and report["profile"].get("parsed"):
        ents = report["profile"].get("entitlements") or {}
    report["entitlements"] = audit_entitlements(ents, "entitlements", findings, report["profile"])
    report["entitlements_raw"] = {k: (v if not isinstance(v, (bytes, bytearray)) else "<data>") for k, v in ents.items()}
    if report["profile"].get("type") in ("development", "development/ad-hoc", "enterprise"):
        add(findings, "profile-type", "low" if report["profile"]["type"] != "enterprise" else "medium",
            f"provisioning profile type: {report['profile']['type']}", "embedded.mobileprovision",
            f"devices={report['profile'].get('devices')} expires={report['profile'].get('expires')}", r"code signing", r"managed distribution")

    all_strings = list(strings)
    report["extensions"] = audit_extensions(app, ents, findings, binaries, all_strings, report["profile"])
    report["binaries"] = binaries

    # privacy: imported framework classes vs declared usage descriptions
    declared = set(report["app"]["usage_descriptions"])
    imported = set(c for b in binaries.values() for c in b.get("privacy_classes", []))
    for key, (label, classes) in USAGE_KEYS.items():
        used = any(c in imported for c in classes)
        pat = PRIVACY_IDS.get(label.replace("-legacy", "").replace("-full", ""), label)
        if used and label not in declared and not label.endswith(("-legacy", "-full", "-add", "-always")) and label not in ("face-id",):
            add(findings, f"privacy-missing-{label}", "low", f"{label} API imported without {key}", "Info.plist", "", pat)
        if label in declared and not used and classes:
            add(findings, f"privacy-unused-{label}", "info", f"{key} declared but no matching API import found (check need)", "Info.plist", "", pat)
    if binaries["main"].get("idfa") and "tracking" not in declared:
        add(findings, "idfa-without-att", "medium", "advertisingIdentifier read without NSUserTrackingUsageDescription", "Info.plist", "",
            r"App Tracking Transparency", r"AdSupport identifier")

    # secrets in binary strings
    blob = "\n".join(all_strings)
    for h in find_secrets(blob, "binary strings", limit=80):
        add(findings, f"secret-{h['type']}", h["severity"], f"{h['type']} in binary strings", h["where"], h["value"],
            r"hardcoded secrets in binary", r"hardcoded encryption keys", r"credential exposure")
    keyish = [x for x in set(all_strings) if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{64}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{22}==", x)]
    if keyish:
        add(findings, "possible-key-material", "low", f"{len(keyish)} hex/base64 strings with key-like length (check against CCCrypt keys)",
            "binary strings", ", ".join(redact_value(k) for k in keyish[:5]), r"hardcoded encryption keys", r"key management")

    scan_bundle_files(app, findings, report)
    report["firebase"] = audit_firebase(app, findings, work)
    report["coredata_models"] = audit_coredata(app, findings)
    report["sdks"] = sdk_inventory(app, binaries, classnames, blob, findings)
    report["endpoints"] = endpoints(all_strings, findings)
    report["deeplinks"] = deeplink_candidates([s["scheme"] for s in report["app"]["url_schemes"]], all_strings,
                                              report["entitlements"].get("associated_domains", []))
    external_tools(exe, work, report, not args.no_tools)

    # de-duplicate (same rule+where+title) and sort
    seen, uniq = set(), []
    for f in findings:
        k = (f["rule"], f["where"], f["title"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    report["findings"] = sort_findings(uniq)
    bundle = report["app"]["bundle_id"] or "app"
    out = args.out or os.path.join(ARTIFACTS, bundle, "ios-static.json")
    write_json(out, report)
    counts = Counter(f["severity"] for f in report["findings"])
    print(f"bundle: {bundle} {report['app']['version']} ({report['app']['build']})  min iOS {report['app']['min_os']}")
    print(f"binary: encrypted={binaries['main']['encrypted']} pie={binaries['main']['pie']} canary={binaries['main']['stack_canary']} "
          f"arc={binaries['main']['arc']} stripped={binaries['main']['stripped']} swift={binaries['main']['swift']}")
    print(f"schemes: {[s['scheme'] for s in report['app']['url_schemes']]}  applinks: {report['deeplinks']['applinks_domains']}")
    print(f"extensions: {len(report['extensions'])}  sdks: {len(report['sdks']) - 1}  hosts: {len(report['endpoints']['hosts'])}")
    print(f"findings: {len(report['findings'])} {dict(counts)}  report: {out}")
    for name, t in report["tools"].items():
        print(f"  tool {name}: {t['status']}" + (f" ({t['reason']})" if "reason" in t else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
