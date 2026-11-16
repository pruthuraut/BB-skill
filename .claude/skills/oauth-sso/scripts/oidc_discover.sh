#!/usr/bin/env bash
# Discover OAuth 2.0 / OpenID Connect / SAML metadata on authorized hosts and
# summarise security-relevant capabilities. Read-only GETs, scope-gated, rate-limited.
#
# Usage:
#   oidc_discover.sh --target DOMAIN --host auth.example.com [--host app.example.com]
#                    [--out artifacts/oauth/discovery] [--delay 0.5] [--path /custom/.well-known/...]
set -euo pipefail

TARGET="" OUT="artifacts/oauth/discovery" DELAY=0.5
HOSTS=() EXTRA_PATHS=()
usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --host)   HOSTS+=("$2"); shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    --delay)  DELAY="$2"; shift 2 ;;
    --path)   EXTRA_PATHS+=("$2"); shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$TARGET" ] && [ "${#HOSTS[@]}" -gt 0 ] || usage

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/../../../../scripts/scope_check.sh"
target_lc="$(printf '%s' "$TARGET" | tr '[:upper:]' '[:lower:]')"

PATHS=(
  "/.well-known/openid-configuration"
  "/.well-known/oauth-authorization-server"
  "/.well-known/jwks.json"
  "/jwks.json"
  "/oauth/jwks"
  "/oauth2/jwks"
  "/.well-known/oauth-protected-resource"
  "/realms/master/.well-known/openid-configuration"
  "/auth/realms/master/.well-known/openid-configuration"
  "/oauth2/default/.well-known/openid-configuration"
  "/adfs/.well-known/openid-configuration"
  "/FederationMetadata/2007-06/FederationMetadata.xml"
  "/saml/metadata"
  "/saml2/metadata"
  "/sso/saml/metadata"
  "/Shibboleth.sso/Metadata"
  "/simplesaml/saml2/idp/metadata.php"
  "/idp/shibboleth"
)
PATHS+=("${EXTRA_PATHS[@]+"${EXTRA_PATHS[@]}"}")

mkdir -p "$OUT"
for host in "${HOSTS[@]}"; do
  host="$(printf '%s' "$host" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##' | tr '[:upper:]' '[:lower:]')"
  if [ "$host" != "$target_lc" ] && [[ "$host" != *".$target_lc" ]]; then
    echo "[!] $host is outside target $TARGET; skipping (third-party IdPs are not tested)" >&2; continue
  fi
  "$GATE" "$host" || { echo "[!] scope gate failed for $host; skipping" >&2; continue; }
  hdir="$OUT/$host"; mkdir -p "$hdir"
  echo "[*] $host"
  for p in "${PATHS[@]}"; do
    fname="$(printf '%s' "$p" | sed 's#^/##; s#[/?=&]#_#g')"
    code="$(curl -sk --max-time 15 -o "$hdir/$fname" -w '%{http_code}' "https://$host$p" || echo 000)"
    if [ "$code" = "200" ] && [ -s "$hdir/$fname" ]; then
      echo "    200 $p"
    else
      rm -f "$hdir/$fname"
    fi
    sleep "$DELAY"
  done

  # Summarise any OIDC/OAuth metadata documents found.
  for f in "$hdir"/*openid-configuration "$hdir"/*oauth-authorization-server; do
    [ -f "$f" ] || continue
    echo "    --- summary of $(basename "$f")"
    python3 -I - "$f" <<'PY' | tee "$f.summary.txt" | sed 's/^/    /'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print(f"not JSON: {e}"); sys.exit(0)
g = lambda k: d.get(k) or []
keys = ["issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
        "registration_endpoint", "revocation_endpoint", "introspection_endpoint", "end_session_endpoint",
        "device_authorization_endpoint", "backchannel_authentication_endpoint",
        "pushed_authorization_request_endpoint"]
for k in keys:
    if d.get(k):
        print(f"{k}: {d[k]}")
flags = []
rt = " ".join(g("response_types_supported"))
if "token" in rt.split() or "id_token token" in rt or "code token" in rt:
    flags.append("OA-06/36 implicit or hybrid response types supported: " + rt)
pk = g("code_challenge_methods_supported")
if not pk:
    flags.append("OA-09/29 code_challenge_methods_supported not advertised (PKCE may be optional)")
elif "plain" in pk:
    flags.append("OA-09 PKCE 'plain' method supported")
gt = g("grant_types_supported")
for t, cid in (("password", "OA-50 ROPC grant"), ("urn:ietf:params:oauth:grant-type:token-exchange", "OA-11 token exchange"),
               ("urn:ietf:params:oauth:grant-type:device_code", "OA-40 device grant"),
               ("urn:openid:params:grant-type:ciba", "OA-40 CIBA"), ("client_credentials", "OA-26 client credentials")):
    if t in gt:
        flags.append(f"{cid} supported")
if d.get("registration_endpoint"):
    flags.append("OA-33 Dynamic Client Registration endpoint present - test unauthenticated registration")
if d.get("request_uri_parameter_supported", True) and "request_uri_parameter_supported" in d:
    flags.append("OA-48/49 request_uri supported - test server-side fetch and unsigned request objects")
if d.get("request_parameter_supported"):
    flags.append("OA-49 request objects supported")
algs = g("id_token_signing_alg_values_supported")
if "none" in algs:
    flags.append("OA-16 'none' listed in id_token_signing_alg_values_supported")
if any(a.startswith("HS") for a in algs):
    flags.append("OA-16 HMAC id_token algs supported (client_secret-keyed) - check secret strength / confusion")
if "none" in g("token_endpoint_auth_methods_supported"):
    flags.append("OA-10 public clients (token_endpoint_auth_method=none) supported - PKCE must be enforced")
if not d.get("authorization_response_iss_parameter_supported"):
    flags.append("OA-18 RFC 9207 iss response parameter not advertised (mix-up defence relies on client)")
if d.get("dpop_signing_alg_values_supported"):
    flags.append("OA-28 DPoP supported - test bearer fallback")
if d.get("tls_client_certificate_bound_access_tokens"):
    flags.append("OA-28 mTLS-bound tokens supported - test acceptance without client cert")
if g("acr_values_supported"):
    flags.append(f"OA-39 acr_values_supported: {g('acr_values_supported')}")
print("flags:")
for f in flags or ["none"]:
    print(f"  - {f}")
PY
  done
done
echo "[+] Results in $OUT"
