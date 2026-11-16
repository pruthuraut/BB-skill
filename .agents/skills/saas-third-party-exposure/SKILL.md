---
name: saas-third-party-exposure
description: Find third-party SaaS tags, widgets, and client-side keys on an authorized target (analytics, session replay, chat, email marketing, payments, maps, CDN and image services, CAPTCHA, error monitoring) and classify each as a public identifier (normal) or a leaked secret (finding). Triggers on "third-party scripts", "API keys in JS", "exposed keys", "tracking tags", "Stripe key", "Mailgun key", "Algolia", "Firebase key", "embedded widget", or when route_target.py finds vendor markers in a page.
---

# SaaS Third-Party Exposure

Vendor tags and keys in page source and JavaScript. Most identifiers are public by design. The finding is a secret that should never reach a browser (secret keys, admin tokens, sending keys, webhook secrets) or a public identifier that exposes data the program does not expect to be public.

Checklist: `references/saas_tags_and_keys.md` (about 90 rows, grouped by vendor family).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Collect page source and JS bundles for in-scope pages (crawl or jsrecon output). Save to a new directory under `artifacts/<target>/js/`.
3. Grep for vendor markers and key prefixes. Examples: `sk_live_`, `sk_test_`, `rk_live_`, `shpat_`, `shpca_`, `AKIA`, `AIza`, `xox`, `ghp_`, `glpat-`, `EAA`, `SG.`, `re_`, `figd_`, `sl.`, `pat` tokens, `api_secret`, `client_secret`, `private_key`, `service_role`, `master key`.
4. Classify each hit: public (publishable, anon, client, search-only, widget ID), secret (must not be client-side), or ambiguous (needs vendor docs). Record evidence with values redacted.
5. For `bounded` rows only, make at most one or two read-only requests with a key you are authorized to use, and only to confirm scope and type. Never use a secret for writes, sends, charges, or data reads of real users.
6. Save findings to `artifacts/<target>/saas_exposure.json` with key type, location (URL and line), class, and redacted value.

## Classes

- `passive`: grep and page reading only.
- `bounded`: one or two read-only calls with an authorized key.
- `authorized-only`: any write, send, charge, or access to real data.

## Rules

- Redact keys in every artifact and report (keep the first 4 and last 2 characters at most).
- Report a leaked secret immediately to the program. Do not paste it into chat or public issues.
- Do not claim exposure for publishable keys. Explain why they are expected and only report misconfiguration (for example, a publishable key whose domain restriction is missing and is abused).
- Session replay tools (Hotjar, FullStory, LogRocket, and similar) are a privacy finding when inputs are not masked. Check the masking config on pages you own in the test account.
