# Subdomain Takeover: 50-Check Verification Ledger

**Progress:** `[ 0 / 50 assessed ]`

Use this ledger for authorized, non-destructive validation. Provider behavior and custom-domain controls change over time, so treat every fingerprint as a routing hint and confirm against current provider documentation or maintained detection templates.

## Status values

- `PASS` — the relevant record/provider condition exists and was tested with negative evidence.
- `CANDIDATE` — stale dependency or provider fingerprint exists, but claimability is unproven.
- `LIKELY` — DNS control, unbound resource, and current provider binding behavior align; no resource was claimed.
- `NOT_APPLICABLE` — the relevant record/provider is absent from the collected inventory.
- `BLOCKED` — evidence could not be collected; record the reason.

`CONFIRMED` is intentionally excluded from normal execution because claiming or binding a resource is outside this skill.

For every `CANDIDATE` or `LIKELY` row, record the provider evidence URL or maintained-template version, retrieval date, relevant binding rule, and whether exact-host claimability is documented. Never test claimability through provider signup, UI, or API flows. If several checks map to one dependency, reuse a single finding ID and cross-reference it from each applicable row.

## Checklist

| # | Verification check | Minimum non-destructive evidence | Important caveat |
|---:|---|---|---|
| 01 | Generic dangling CNAME | Full chain, terminal failure/unbound endpoint, repeated HTTP/TLS evidence | NXDOMAIN or 404 alone is only a candidate |
| 02 | Deleted AWS S3 bucket | CNAME/alias to S3, exact bucket/region evidence, `NoSuchBucket`-class provider response | Never create the bucket; access-denied is not dangling |
| 03 | Unclaimed GitHub Pages custom domain | CNAME/A pattern, Pages-specific unbound response, current custom-domain binding rules | Do not add the hostname to a repository |
| 04 | Deleted Heroku app | CNAME to Heroku routing domain and repeated unbound-app response | Platform domain ownership controls may prevent claims |
| 05 | Unverified Shopify custom domain | Custom hostname points to Shopify and provider reports it is not attached | Distinguish custom domains from store-name allocation |
| 06 | Dangling A/AAAA to released cloud address | Stale address, provider/ASN attribution, resource deallocation evidence | Reallocation of the exact IP must not be assumed |
| 07 | Unclaimed Azure Web App custom domain | Azure endpoint chain plus unbound custom-host response | Azure domain-verification IDs may prevent binding |
| 08 | Deleted Ghost-hosted blog | Ghost provider target and tenant-not-found behavior | Self-hosted Ghost is not a provider takeover condition |
| 09 | Unregistered WordPress.com custom domain | WordPress.com target plus unbound mapping response | A deleted site may retain protected ownership |
| 10 | Removed Fastly service | Fastly target and unknown-domain response on original Host/SNI | Fastly activation controls change; validate current rules |
| 11 | Unclaimed Pantheon custom domain | Pantheon target and unknown-site response | Do not add the hostname to another site |
| 12 | Deleted Tumblr blog | Tumblr DNS target and missing-blog/custom-domain evidence | Blog-name availability is not equivalent to custom-domain claimability |
| 13 | Abandoned Mailgun domain | Mailgun DNS dependencies or verification records reference removed tenant | Do not send mail or add verification records |
| 14 | Deleted CloudFront distribution | CloudFront alias/target and distribution-not-found behavior | Generic CloudFront 403 is not evidence of takeover |
| 15 | Unclaimed Firebase Hosting domain | Firebase target and unbound hosting response | Current domain ownership verification may block reassignment |
| 16 | Retired Desk.com mapping | Historical Desk.com target and unresolved/decommissioned dependency | Usually historical hygiene; mark N/A if service no longer permits binding |
| 17 | Abandoned SendGrid authentication domain | CNAME/TXT authentication records reference an absent tenant/configuration | Do not attempt sender verification or mail delivery |
| 18 | Deleted Freshdesk helpdesk | Freshdesk target and tenant-not-found response | Confirm exact custom-domain binding behavior |
| 19 | Abandoned Pagoda Box app | Historical provider target and terminal failure | Retired provider normally means stale DNS, not claimability |
| 20 | Removed GitLab Pages project | GitLab Pages target and unbound domain response | Account/project namespaces and domain verification affect risk |
| 21 | Dangling child-zone NS delegation | Parent NS delegation, every child NS terminal state, authoritative-query failure | Never register the zone or nameserver; impact may cover the whole child zone |
| 22 | Dangling MX/mail provider dependency | MX target failure or decommissioned tenant plus current provider binding evidence | Never send, receive, or intercept email |
| 23 | Terminated Elastic Beanstalk environment | CNAME to Beanstalk endpoint and environment-not-found evidence | Region and generated environment names matter |
| 24 | Deleted Bitbucket Pages/repository | Bitbucket provider target and missing workspace/repository response | Verify whether custom domains can still be bound |
| 25 | Unclaimed Webflow custom domain | Webflow target and unbound-site response | Do not attach the hostname in Webflow |
| 26 | Deleted Unbounce campaign/domain | Unbounce target and domain-not-configured response | Confirm current domain verification safeguards |
| 27 | Abandoned Cargo Collective domain | Cargo target and absent-site response | Account retention may reserve old bindings |
| 28 | Deleted Statuspage page | Statuspage target and missing-page response | Custom-domain verification may prevent another tenant binding |
| 29 | Dangling TXT verification record | Orphaned provider verification token tied to a removed integration | Informational unless the provider demonstrably treats it as sufficient ownership proof |
| 30 | Removed ReadMe project | ReadMe target and project/domain-not-found response | Confirm current custom-domain controls |
| 31 | Unclaimed Surge custom domain | Surge target and project-not-found response | Do not publish or reserve the domain |
| 32 | Deleted Fly.io app | Fly.io target and absent-app response | Certificate/domain ownership enforcement may block binding |
| 33 | Abandoned Netlify custom domain | Netlify target and unbound-site response | A generic Netlify 404 is insufficient |
| 34 | Removed Vercel project | Vercel target and domain/project-not-found evidence | Vercel ownership verification frequently prevents reassignment |
| 35 | Deleted Render service | Render target and unknown-service response | Confirm custom-domain verification state |
| 36 | Deleted Strikingly site | Strikingly target and missing-site response | Account/domain retention may prevent claims |
| 37 | Wildcard DNS to dangling dependency | Random-label controls resolve through the same dangling terminal target | Wildcard scope increases blast radius but does not prove claimability |
| 38 | Removed DigitalOcean App Platform app | App Platform target and missing-app response | Verify current domain ownership protections |
| 39 | Deleted AWS API Gateway stage/domain | API Gateway custom-domain or execute-api dependency and absent mapping | Missing stage alone may leave the custom domain allocated |
| 40 | Deleted Intercom workspace/help center | Intercom target and tenant-not-found response | Confirm whether another workspace can bind the exact hostname |
| 41 | Abandoned Help Scout custom domain | Help Scout target and missing-docs/site response | Do not add the domain to another workspace |
| 42 | Unclaimed Shopify `myshopify.com` target | Custom CNAME points to an absent Shopify store identifier | Store-name reuse and custom-domain takeover are separate questions |
| 43 | Removed Cloudflare Workers route/custom hostname | Worker/custom-host dependency and provider-level missing route/origin evidence | A removed route commonly falls back safely; validate binding path |
| 44 | Deleted Zeit/Now deployment | Legacy Zeit/Now or current Vercel target and missing-deployment response | Treat as Vercel lineage; avoid duplicate findings with Check 34 |
| 45 | Orphaned Bing verification record | Stale Bing verification TXT/XML/CNAME record | Informational unless it grants a security-relevant binding |
| 46 | Orphaned Google site-verification record | Stale Google verification token without active property ownership evidence | Usually hygiene only; do not attempt property enrollment |
| 47 | Dangling SRV target | SRV target chain fails or reaches an unbound provider resource | Validate service, priority, weight, and port; no service interaction required |
| 48 | Multi-hop CNAME terminal takeover | Every hop captured and terminal provider resource shown unbound | Intermediate live hops do not eliminate terminal risk |
| 49 | Dangling apex ALIAS/ANAME flattening | Authoritative provider configuration or repeated flattened answers identify stale target | Public DNS may hide the alias; require authoritative evidence |
| 50 | CAA-assisted takeover triage | CAA issuer clues correlate with an abandoned hosting/CDN integration | CAA cannot itself be taken over; classify as informational context |

## Completion requirement

Create `artifacts/takeover_checklist_50.tsv` with columns:

```text
check_id	status	finding_id	host	record_type	dependency	provider	provider_evidence	retrieved_at	evidence_paths	notes
```

All 50 rows must be present. `NOT_APPLICABLE` and `BLOCKED` count as assessed only when the reason and supporting inventory evidence are recorded.
