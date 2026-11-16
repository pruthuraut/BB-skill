---
name: email-security-audit
description: Audit authorized domains for email security posture (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, MX hygiene, DNSSEC) and for email header injection and reset-email misdirection in application forms. Triggers on "SPF", "DKIM", "DMARC", "email spoofing", "mail security", "MX records", "email header injection", "reset email", "spoofable domain", or when a target's DNS and forms need an email review.
---

# Email Security Audit

Check DNS records that determine whether mail from the domain can be spoofed, and check application forms that send email for header injection or address misdirection. DNS lookups are passive. Form tests use only your own addresses.

Checklist: `references/spf_dkim_dmarc.md` (14 rows).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. DNS (passive): query TXT for SPF, `_dmarc`, common DKIM selectors, `_mta-sts`, `_smtp._tls`. Query MX and DNSSEC (MAIL-001 to MAIL-008).
3. Evaluate: SPF `+all` or `?all`, DMARC `p=none` on a live domain, weak DKIM keys, missing MTA-STS.
4. Forms (bounded): submit a contact or signup form with your own address and a benign CRLF marker (MAIL-010). Check the delivered headers on your own mailbox.
5. Reset flow (bounded): trigger a reset on your own account with an altered email parameter pointing to your second address (MAIL-011). Check where the link lands.
6. Mail servers (passive only): banner and STARTTLS status. Never test open relay against third-party recipients (MAIL-012).
7. Save results to `artifacts/<target>/email_security.json`.

## Classes

- `passive`: DNS and banner.
- `bounded`: own-address form submissions.
- `authorized-only`: any sending to third parties.

## Rules

- Never send test mail to addresses you do not own.
- Spoofability is a DNS finding; report it with the policy evidence, not with a spoofed message.
