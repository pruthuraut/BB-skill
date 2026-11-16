# CSRF Reports, Writeups, Tips, Tools, and Labs

Study these for patterns and report wording. Read each source for its specific details; titles and bounty figures are as listed in the source notes.

## HackerOne reports

- https://hackerone.com/reports/834366
- https://hackerone.com/reports/339352
- https://hackerone.com/reports/1122408
- https://hackerone.com/reports/177508
- https://hackerone.com/reports/1890310
- https://hackerone.com/reports/2712857
- https://hackerone.com/reports/1668489
- https://hackerone.com/reports/1118521

### Top disclosed CSRF reports

| # | Report | Program | Bounty |
|---|---|---|---|
| 1 | [CSRF on connecting PayPal as Payment Provider](https://hackerone.com/reports/807924) | Shopify | $500 |
| 2 | [Account Takeover using Linked Accounts due to lack of CSRF protection](https://hackerone.com/reports/463330) | Rockstar Games | $1000 |
| 3 | [Periscope android app deeplink leads to CSRF in follow action](https://hackerone.com/reports/583987) | Twitter | $1540 |
| 4 | [Leakage of CSRF token which leads to Stored XSS and Account Takeover](https://hackerone.com/reports/604120) | InnoGames | $1100 |
| 5 | [Site wide CSRF affecting job seeker and employer accounts on glassdoor.com](https://hackerone.com/reports/790061) | Glassdoor | $3000 |
| 6 | [CSRF leads to a stored self XSS](https://hackerone.com/reports/323005) | Imgur | $500 |
| 7 | [CSRF protection bypass in GitHub Enterprise management console](https://hackerone.com/reports/1497169) | GitHub | $10000 |
| 8 | [Slack integration setup lacks CSRF protection](https://hackerone.com/reports/170552) | HackerOne | $2500 |
| 9 | [Lack of CSRF header validation at g-mail.grammarly.com/profile](https://hackerone.com/reports/629892) | Grammarly | $750 |
| 10 | [CSRF token validation system is disabled on Stripe Dashboard](https://hackerone.com/reports/1483327) | Stripe | $2500 |
| 11 | [CSRF on API endpoint allows account takeovers](https://hackerone.com/reports/419891) | Khan Academy | $0 |
| 12 | [CSRF on signin.rockstargames.com/tpa/facebook/link/](https://hackerone.com/reports/474833) | Rockstar Games | $1000 |
| 13 | [CSRF to HTML Injection in Comments](https://hackerone.com/reports/428019) | WordPress | $950 |
| 14 | [One-click ATO using OAuth CSRF bypass with null byte %00 in state](https://hackerone.com/reports/1046630) | Logitech | $200 |
| 15 | [CSRF in Account Deletion feature (flickr.com/account/delete)](https://hackerone.com/reports/615448) | Flickr | $750 |
| 16 | [ATO at try.discourse.org: no CSRF protection connecting Yahoo account](https://hackerone.com/reports/423022) | Discourse | $512 |
| 17 | [CSRF token validation system is disabled on Stripe Dashboard](https://hackerone.com/reports/1493437) | Stripe | $2500 |
| 18 | [Full account takeover using CSRF](https://hackerone.com/reports/235642) | Twitter | $5040 |
| 19 | [CSRF Account Takeover](https://hackerone.com/reports/1253462) | TikTok | $2373 |

Patterns: account linking and OAuth connect (2, 12, 14, 16), payment and integration setup (1, 8), token leakage chained with XSS (4, 6, 13), framework-level token check disabled (7, 10, 17), and email/password ATO (11, 18, 19).

## Writeups

- How a simple CSRF attack turned into a P1 — https://ladysecspeare.wordpress.com/2020/04/05/how-a-simple-csrf-attack-turned-into-a-p1-level-bug/
- JSON CSRF with method override — https://medium.com/@secureITmania/how-i-exploit-the-json-csrf-with-method-override-technique-71c0a9a7f3b0
- How I found CSRF (first bounty) — https://medium.com/@rajeshranjan457/how-i-csrfd-my-first-bounty-a62b593d3f4d
- WebSocket application-wide XSS and CSRF — https://medium.com/@osamaavvan/exploiting-websocket-application-wide-xss-csrf-66e9e2ac8dfa
- Site-wide CSRF on a popular program — https://fellchase.blogspot.com/2020/02/site-wide-csrf-on-popular-program.html
- CSRF to weird account takeover — https://flex0geek.blogspot.com/2020/02/using-csrf-i-got-weird-account-takeover.html
- CSRF CSRF CSRF — https://medium.com/@navne3t/csrf-csrf-csrf-f203e6452a9c
- Google bug bounty CSRF in learndigital.withgoogle.com — https://santuysec.com/2020/01/21/google-bug-bounty-csrf-in-learndigital-withgoogle-com/
- CSRF token bypass (a $2k bug) — https://medium.com/@sainttobs/csrf-token-bypasss-a-tale-of-my-2k-bug-ff7f51166ea1
- 2FA bypass via CSRF — https://medium.com/@vbharad/2-fa-bypass-via-csrf-attack-8f2f6a6e3871
- Stored iframe injection CSRF account takeover — https://medium.com/@irounakdhadiwal999/stored-iframe-injection-csrf-account-takeover-42c93ad13f5d
- Instagram delete media CSRF — https://blog.darabi.me/2019/12/instagram-delete-media-csrf.html
- An inconsistent CSRF — https://smaranchand.com.np/2019/10/an-inconsistent-csrf/
- Bypass CSRF with clickjacking — https://medium.com/@saadahmedx/bypass-csrf-with-clickjacking-worth-1250-6c70cc263f40
- Site-wide CSRF in GraphQL — https://rafiem.github.io/bugbounty/tokopedia/site-wide-csrf-graphql/
- Account takeover using JSON-based CSRF — https://medium.com/@shub66452/account-takeover-using-csrf-json-based-a0e6efd1bffc
- CORS to CSRF — https://medium.com/@osamaavvan/cors-to-csrf-attack-c33a595d441
- First CSRF to account takeover — https://medium.com/@nishantrustlingup/my-first-csrf-to-account-takeover-worth-750-1332641d4304
- 4 chained CSRFs for company account takeover — https://medium.com/a-bugz-life/4x-csrfs-chained-for-company-account-takeover-f9fada416986
- JSON-based CSRF in profile management — https://sallam.gitbook.io/sec-88/write-ups/exploiting-json-based-csrf-the-hidden-threat-in-profile-management
- CSRF bypass using domain confusion leads to ATO — https://medium.com/@osamaaly/csrf-bypass-using-domain-confusion-leads-to-ato-ac682dd17722
- Subdomain takeover (for CORS/Origin trust chains) — https://monish-basaniwal.medium.com/how-i-found-my-first-subdomain-takeover-vulnerability-b7d5c17b61fd

## Articles and cheat sheets

- JSON CSRF with parameter padding — http://blog.opensecurityresearch.com/2012/02/json-csrf-with-parameter-padding.html
- Login/logout CSRF: time to reconsider (Detectify) — https://labs.detectify.com/2017/03/15/loginlogout-csrf-time-to-reconsider/
- Site-wide CSRF chained with clickjacking (zseano) — https://medium.com/@zseano/site-wide-csrf-issue-chained-with-clickjacking-multiple-sites-vulnerable-6201abab0d3e
- Seven sins of anti-CSRF tokens — https://blog.securityinnovation.com/seven-sins-of-anti-csrf-tokens
- Bypass CSRF protection and password confirmation to take over accounts — https://medium.com/bugbountywriteup/lets-bypass-csrf-protection-password-confirmation-to-takeover-victim-accounts-d-4a21297847ff
- CSRF cheat sheet (TrustFoundry) — https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/
- OWASP CSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Videos

- https://www.youtube.com/watch?v=eWEgUcHPle0
- https://www.youtube.com/watch?v=ULvf6N8AL2A

## Field tips (from the source notes)

- Origin-check fix bypassed: Firefox did not send Origin when the form was in a `data:text/html;base64,` iframe, so the server skipped the check (zseano). Test `Origin: null` and missing Origin separately.
- Simplest bypass seen in the wild: change POST to GET and drop the token; the request worked.
- If an action happens via a URL with no token, check whether you can set a remote image or avatar URL to that action URL. Anyone who views the image triggers it. (Own-account test only.)
- SameSite=Lax only blocks cross-site POST, so try the state change as GET.
- PUT and DELETE are CSRF-able when the framework honors `_method` on POST.
- `_csrf_token=undefined` bypassed validation on one target.
- PHP: `csrftoken[]=&message=x` (empty array) bypassed several CSRF libraries.
- `Content-Type: text/plain; application/json` is sent cross-site without CORS, and some backends parse it as JSON.
- ATO via password change: capture the request, remove both `current_password` and the CSRF token, generate the PoC.
- Anti-CSRF tokens with a static part and a dynamic part: send only the static part.
- Some apps skip the token check for mobile or tablet User-Agents.
- CSRF token may be a hash; try to crack or reproduce it.
- Steal the token with XSS or HTML injection (dangling markup) when it is present and validated.

## Tools

- XSRFProbe — https://github.com/0xInfection/XSRFProbe (`xsrfprobe -u https://TARGET --crawl`; run only in scope, it submits forms)
- Burp Suite Professional — Generate CSRF PoC; CSRF Scanner extension
- `scripts/csrf_probe.py` and `scripts/csrf_token_analyze.py` in this skill

## Labs

- PortSwigger Web Security Academy CSRF labs — https://portswigger.net/web-security/csrf (token validation, method, token-not-tied-to-session, double submit, SameSite Lax/Strict bypass, Referer validation)
- PortSwigger all labs — https://portswigger.net/web-security/all-labs
