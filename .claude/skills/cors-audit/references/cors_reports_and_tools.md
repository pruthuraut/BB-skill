# CORS Reports, Research, Tools, and Labs

Study these for patterns and report wording. Read each source for its specific details.

## Hunting methods (from the source notes)

**Method 1, single target**
1. Proxy the target and spider or crawl the whole site in Burp.
2. Search Burp history for `Access-Control`.
3. Add an Origin header: `Origin: attacker.com`, `Origin: null`, `Origin: attacker.target.com`, `Origin: target.attacker.com`.
4. If the origin is reflected in the response (with credentials), the endpoint is a candidate.

**Method 2, many hosts**
1. `subfinder -d target.com -o domains.txt`
2. `cat domains.txt | httpx | tee -a alive.txt`
3. `cat alive.txt | parallel -j 10 curl --proxy "http://127.0.0.1:8080" -sk 2>/dev/null` (send each live host through Burp)
4. Repeat method 1. Or run `scripts/cors_probe.py --urls alive.txt`.

Tip: on any page that discloses usernames, passwords, keys, or other sensitive data, try CORS.

## Tools

| Tool | Use | Command |
|---|---|---|
| Corsy | Origin-bypass scanner | `python3 corsy.py -u https://HOST` |
| CORScanner | Scanner with many bypass patterns | `python cors_scan.py -u HOST` |
| CorsMe | Fast multi-host checker | `echo "https://HOST" \| ./CorsMe` ; `cat http_https.txt \| ./CorsMe -t 70` |
| outpost24-cors-check | CORS checker | https://github.com/Outpost24/outpost24-cors-check |
| honoki CORS PoC | Browser PoC page generator | https://tools.honoki.net/cors.html |
| This skill | Origin matrix, preflight, PoC writer | `scripts/cors_probe.py` |

Links: https://github.com/s0md3v/Corsy, https://github.com/chenjj/CORScanner, https://github.com/Shivangx01b/CorsMe. Run scanners only against in-scope hosts and keep thread counts within program rate limits.

## Writeups and reports

- CORS bug on Google's 404 page (rewarded) — https://medium.com/@jayateerthag/cors-bug-on-googles-404-page-rewarded-2163d58d3c8b
- CORS misconfiguration leading to private information disclosure — https://medium.com/@sasaxxx777/cors-misconfiguration-leading-to-private-information-disclosure-3034cfcb4b93
- CORS misconfiguration ATO: out of scope to grab items in scope — https://medium.com/@mashoud1122/cors-misconfiguration-account-takeover-out-of-scope-to-grab-items-in-scope-66d9d18c7a46
- Chrome CORS — https://blog.bi.tk/chrome-cors/
- Bypassing CORS — https://medium.com/@saadahmedx/bypassing-cors-13e46987a45b
- CORS to CSRF attack — https://medium.com/@osamaavvan/cors-to-csrf-attack-c33a595d441
- An unexploited CORS misconfiguration reflecting further issues — https://smaranchand.com.np/2019/05/an-unexploited-cors-misconfiguration-reflecting-further-issues/
- Think outside the scope: advanced CORS exploitation techniques — https://medium.com/@sandh0t/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397
- A simple CORS misconfig leaked private posts of Twitter, Facebook, Instagram — https://medium.com/@nahoragg/a-simple-cors-misconfig-leaked-private-post-of-twitter-facebook-instagram-5f1a634feb9d
- Exploiting CORS misconfiguration — https://bugbaba.blogspot.com/2018/02/exploiting-cors-miss-configuration.html
- Full account takeover through CORS with connection sockets — https://medium.com/@saamux/full-account-takeover-through-cors-with-connection-sockets-179133384815
- Exploiting insecure CORS API api.artsy.net — https://blog.securitybreached.org/2017/10/10/exploiting-insecure-cross-origin-resource-sharing-cors-api-artsy-net
- Pre-domain wildcard CORS exploitation — https://medium.com/bugbountywriteup/pre-domain-wildcard-cors-exploitation-2d6ac1d4bd30
- Exploiting misconfigured CORS on a popular BTC site — https://medium.com/@arbazhussain/exploiting-misconfigured-cors-on-popular-btc-site-2aedfff906f6
- Abusing CORS for an XSS on Flickr — https://whitton.io/articles/abusing-cors-for-an-xss-on-flickr/
- Tricky CORS bypass in Yahoo! View — https://www.corben.io/tricky-CORS/
- HackerOne: SOP bypass using browser cache — https://hackerone.com/reports/761726
- Stealing user details by exploiting CORS — https://medium.com/@armaanpathan/stealing-user-details-by-exploiting-cors-c5ee86ebe7fb
- Exploiting CORS to perform an IDOR leading to PII disclosure — https://notmarshmllow.medium.com/exploiting-cors-to-perform-an-idor-attack-leading-to-pii-information-disclosure-95ef21ecf8ee

## Research and articles

- PortSwigger Research: Exploiting CORS misconfigurations for Bitcoins and bounties — https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- Advanced CORS exploitation techniques (Corben Leo) — https://www.corben.io/advanced-cors-techniques/
- Abusing CORS origin — https://root4loot.com/post/abusing_cors_origin/
- Misconfigured CORS — https://ejj.io/misconfigured-cors/index.html
- CORS security guide (BeDefended) — https://www.bedefended.com/papers/cors-security-guide
- CORS, a guided tour — https://medium.com/statuscode/cors-a-guided-tour-4e72230a8739
- CORS exploitation when allowed origin is null — https://www.yassineaboukir.com/blog/cors-exploitation-data-exfiltration-when-allowed-origin-is-set-to-null/
- Broken parser (SSRF cheat sheet section) — https://0xn3va.gitbook.io/cheat-sheets/web-application/server-side-request-forgery#broken-parser
- @HolyBugx origin bypass tweet — https://mobile.twitter.com/HolyBugx/status/1464904818242338820
- W3C forgetting Vary: Origin — https://lists.w3.org/Archives/Public/public-webappsec/2016Jun/0057.html
- MDN Same-origin policy — https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
- MDN CORS — https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- PortSwigger SOP — https://portswigger.net/web-security/cors/same-origin-policy

## Labs

- PortSwigger Web Security Academy CORS labs — https://portswigger.net/web-security/cors (basic origin reflection, trusted null origin, trusted insecure protocols, internal network pivot)
- All labs — https://portswigger.net/web-security/all-labs
