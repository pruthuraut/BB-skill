# Third-Party SaaS Tags, Widgets, and Client-Side Keys

Most rows here are passive: find the vendor tag or key in page source or JavaScript, then decide whether the exposed value is a public identifier (normal) or a secret (finding). Publishable and public keys are expected in client code. Secret keys, server tokens, webhook secrets, and admin keys are findings. Never use a found secret for anything beyond confirming it is live if the program allows it. Redact values in reports.

Class key: `passive` = read page source/JS only. `bounded` = one or two read-only API calls with a key you are authorized to use. `authorized-only` = anything that writes, sends, or touches customer data.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SAAS-001 | Algolia | Admin/write API key in client JS (search-only key is normal) | passive | Grep JS for 32-char keys near `algolia`; classify key type from docs |
| SAAS-002 | Algolia | Admin key abuse (index delete) | authorized-only | Never test writes; report classification |
| SAAS-003 | Atatus | API key exposed in JS | passive | Grep for atatus |
| SAAS-004 | Braintree | Server keys or client tokens hardcoded | passive | Grep for braintree, merchant_id, private_key patterns |
| SAAS-005 | BrowserStack | Access key in .env or JS | passive | Grep for browserstack key patterns |
| SAAS-006 | Bunny CDN | Storage zone API key | passive | Grep for AccessKey or storage zone names |
| SAAS-007 | Bunny CDN | Public storage zone listing | bounded | GET storage listing with no key (names only) |
| SAAS-008 | Checkout.com | Secret keys (sk_live_) in client code | passive | Grep for sk_ prefixes (redact) |
| SAAS-009 | Clearbit | API key in client JS | passive | Grep for clearbit key |
| SAAS-010 | Clerk | Secret key (sk_) in client code | passive | Grep for sk_test_/sk_live_ |
| SAAS-011 | CleverTap | Account ID and passcode in SDK config | passive | Grep for clevertap account IDs |
| SAAS-012 | ClientJS | Fingerprinting script present (privacy review) | passive | Grep for ClientJS |
| SAAS-013 | Cloudinary | Unsigned upload preset allowing anyone to upload | bounded | Read preset list; attempt upload of harmless test file on own account only |
| SAAS-014 | Cloudinary | API secret in client JS | passive | Grep for api_secret |
| SAAS-015 | Cloudbeds | API token exposure | passive | Grep for cloudbeds tokens |
| SAAS-016 | Coinhive / in-browser miner | Crypto miner script present (compromise indicator) | passive | Grep for coinhive, cryptonight, miner |
| SAAS-017 | CometChat | App ID and API key exposure | passive | Grep for cometchat key |
| SAAS-018 | Comm100 / LiveChat / LivePerson / Tawk.to / Tidio / Drift / Intercom / Crisp / Olark / Zendesk widget | Widget IDs (public) vs access tokens (secret) | passive | Grep widget IDs; flag any token with write scope |
| SAAS-019 | CommentSold | Order and customer API exposure | bounded | Own-account API request only |
| SAAS-020 | Commento | Admin interface and API key | passive | GET /commento/ status |
| SAAS-021 | Conekta / Cybersource / Dwolla / Midtrans / Mollie / Razorpay / Xsolla / Juspay / Klarna / Authorize.Net / Square / PayPal / Recurly / Zuora / ThriveCart / Lemon Squeezy / Checkout.com | Payment secret keys in client code | passive | Grep for vendor key prefixes; secret vs publishable classification |
| SAAS-022 | Constant Contact / ConvertKit / Drip / Klaviyo / MailChimp / Mailgun / Mailjet / MailerLite / GetResponse / Listrak / Cordial / Flodesk / Iterable / Resend / Mailchimp | Email marketing or sending API key | passive | Grep client JS; treat sending keys as secret |
| SAAS-023 | Contentful / Contentstack / Prismic / Storyblok / DatoCMS / Plasmic | Delivery token (read-only) vs management token (secret) | passive | Grep for accessToken; management tokens are findings |
| SAAS-024 | Contentsquare / Crazy Egg / Hotjar / Inspectlet / Lucky Orange / LogRocket / FullStory / Microsoft Clarity / Heap / Kameleoon / Optimizely / Dynamic Yield / Pendo / PostHog / Mixpanel / Amplitude / Statcounter / GoSquared / Histats / Yandex Metrica / Matomo / Plausible / Fathom / GoStats / Taboola / Pinterest / TikTok Pixel / Criteo / Roistat / Releva / Refersion / Rokt / Marketo / Privy | Analytics, session replay, and tracking IDs | passive | Grep site ID; session replay tools can record inputs, check masking config |
| SAAS-025 | Cookiebot / CookieYes / OneTrust / Usercentrics | Consent platform IDs and script integrity | passive | Grep ID; check SRI and CSP for script host |
| SAAS-026 | Coveo / Algolia / Typesense / Meilisearch / Sphinx | Search key exposure | passive | Grep; search-only keys are normal |
| SAAS-027 | Datadog / Dynatrace / New Relic / Rollbar / Sentry | Client token with write or ingest scope | passive | Grep; ingest keys are public by design but note scope |
| SAAS-028 | DataDome / Kasada / FunCaptcha / GeeTest / Akamai Bot Manager | Bot protection presence and token reuse | bounded | Check whether tokens are validated server-side (own request replay) |
| SAAS-029 | DigiCert | API key in JS | passive | Grep |
| SAAS-030 | DigitalOcean Spaces | Access key in JS; bucket listing | passive | Grep for DO_SPACES; bounded listing check on known bucket |
| SAAS-031 | Disqus | Shortname exposure (public) | passive | Grep shortname |
| SAAS-032 | Docusign | Integration key and secret in JS | passive | Grep for integration_key and secret |
| SAAS-033 | Dropbox | Access token (sl./db_) in JS | passive | Grep patterns; treat as secret |
| SAAS-034 | Duda / Hashnode / Ghost hosted domains | Dangling hosted domain | passive | See subdomain-takeover provider_fingerprints.md |
| SAAS-035 | Evernote | Consumer key/secret in JS | passive | Grep |
| SAAS-036 | Figma | Personal access token in client or repo | passive | Grep for figd_ tokens |
| SAAS-037 | Figma public files | Sensitive content shared with link | bounded | Review own share links only |
| SAAS-038 | FingerprintJS | API key (secret) in JS | passive | Grep for fpjs keys; public agent key is normal |
| SAAS-039 | Font Awesome Pro | Pro license key in build or JS | passive | Grep for FA key in npm config and HTML |
| SAAS-040 | Formstack / Form.io / Jotform / Typeform / Wufoo | Submission data visible by ID | bounded | Own form submission URL access check |
| SAAS-041 | Freshdesk / Freshworks CRM | API key in client code | passive | Grep for API key patterns |
| SAAS-042 | Froala / JW Player / Kaltura / Uploadcare / ImageKit / Imgix | License or private key in client JS | passive | Grep; private keys are findings |
| SAAS-043 | Genially / Infogram / Looker embed / Power BI embed | Embed token exposure | passive | Grep embed URLs with tokens |
| SAAS-044 | Giscus | Repo and category IDs (public) | passive | Note public discussions repo |
| SAAS-045 | GTranslate / Weglot | API key exposure | passive | Grep |
| SAAS-046 | Google Cloud Firebase | API key public by design; rules are the control | bounded | See cloud-supplychain firebase checks |
| SAAS-047 | HubSpot | Private app token or OAuth token in JS | passive | Grep for pat- tokens |
| SAAS-048 | HubSpot / Hotjar / Gravity-style forms | Portal or site IDs (public) | passive | Grep |
| SAAS-049 | ICONSCOUT / Imgix | API keys | passive | Grep |
| SAAS-050 | Impact / Indeed / Ko-fi / Ecwid / Instatus / UptimeRobot / Patreon | Account or API keys in JS | passive | Grep; classify public vs private |
| SAAS-051 | Keybase | Public proof exposure (OSINT) | passive | Note proofs only |
| SAAS-052 | KeyCDN | Origin exposure via headers | passive | See techfingerprint waf_cdn_origin.md |
| SAAS-053 | LaunchDarkly | Client-side ID (public) vs server SDK key (secret) | passive | Grep for sdk-/mob- keys; sdk- keys are secret |
| SAAS-054 | Leaflet / Mapbox / OpenLayers | Map tile API token in JS | passive | Grep for pk. tokens (public) vs sk. tokens (secret) |
| SAAS-055 | Loom / Vimeo / YouTube / Twitch / SoundCloud / Spline / Rumble / Unity WebGL / Tableau / TradingView | Embed IDs and unlisted URLs | passive | Note; unlisted media relying on URL secrecy is an information item |
| SAAS-056 | Lever / Greenhouse / Workday job boards | Candidate data on public boards | bounded | Public board view only |
| SAAS-057 | LottieFiles / Medium / Substack / Tumblr / Twitter / Reddit / Pinterest embeds | Embed metadata only | passive | Low value; note only |
| SAAS-058 | Meilisearch master key | Master key in JS | passive | Grep for master key; search keys are normal |
| SAAS-059 | Mux | Token ID and secret in client code | passive | Grep for mux tokens |
| SAAS-060 | Netlify | Deploy key or env in CI logs or JS | passive | Grep for nf_ tokens |
| SAAS-061 | OneSignal / Pusher / PubNub / Ably | App key or publish key exposure | passive | Grep; subscribe-only keys are normal, publish/secret keys are findings |
| SAAS-062 | Parse / Supabase | App ID or anon key; service-role key | passive | Grep; service_role key is a finding |
| SAAS-063 | Plaid | Client secret in JS (public key and environment are normal) | passive | Grep for client_id and secret |
| SAAS-064 | Plivo / Twilio | Auth token or account SID in JS | passive | Grep for AC[0-9a-f]{32} and auth tokens |
| SAAS-065 | Pipedrive / Zoho / Zoom SDK / Pocket | API token or SDK secret | passive | Grep |
| SAAS-066 | Postman documentation | Collections with tokens published | bounded | Review public documentation pages for tokens |
| SAAS-067 | Privy / Podia / Route / Riskified / Rise.ai / Romancart / Refersion / Roistat | Site or merchant IDs | passive | Note IDs only |
| SAAS-068 | Recharge / Recurly / Zuora | Subscription API key in client | passive | Grep; secret keys are findings |
| SAAS-069 | Resend / Postmark / SendGrid | Sending API key in JS | passive | Grep for re_ and SG. keys; treat as secret |
| SAAS-070 | Retool / Hasura / Appwrite | Instance exposure and client keys | bounded | Anonymous status of instance URL |
| SAAS-071 | Rollbar | Access token with write scope in JS | passive | Grep; post_client_item token is public by design, note scope |
| SAAS-072 | RudderStack | Write key exposure | passive | Grep write key; note as low-impact ingest key |
| SAAS-073 | Shopify | Storefront token (public) vs Admin API token (secret) | passive | Grep for shpat_ and shpca_ |
| SAAS-074 | Stripe | Secret key (sk_live_) in client code; publishable key (pk_) is normal | passive | Grep for sk_ and rk_ prefixes (redact) |
| SAAS-075 | Storyblok / Sanity / Strapi tokens | Management token vs delivery token | passive | Grep for token types |
| SAAS-076 | Twilio | See SAAS-064 | passive | See above |
| SAAS-077 | Uploadcare | Secret key in JS | passive | Grep for uploadcare secret |
| SAAS-078 | Vanta / Gokwik / Cookie banner platforms | Tracking identifiers | passive | Note only |
| SAAS-079 | Zapier / Make / n8n webhooks | Webhook URL with embedded secret | passive | Grep for hooks.zapier.com and similar; URLs with secrets are findings |
| SAAS-080 | Google Maps / Google APIs | Unrestricted browser key | bounded | Check referrer restriction by calling a quota-free endpoint from a foreign origin you control |
| SAAS-081 | Google Analytics / Tag Manager | Container ID exposure (public) | passive | Grep for G- and GTM- IDs |
| SAAS-082 | Facebook / Meta pixel and Graph tokens | Access token in JS | passive | Grep for EAA tokens; treat as secret |
| SAAS-083 | Cloudflare Turnstile / hCaptcha / reCAPTCHA | Site key (public) and server-side verification | bounded | Replay a token from your own session; check server rejects reuse |
| SAAS-084 | Cloudflare / Vercel / Netlify analytics | Token in JS | passive | Grep for token patterns |
| SAAS-085 | Heroku / Railway / Render env files | Env values in client build | passive | Grep for bundled secrets |
| SAAS-086 | Ada / Gorgias / Help Scout Beacon | Beacon ID; API keys | passive | Grep; Beacon keys allow sending as user only if signed |
| SAAS-087 | Coremedia / Adobe Target / Adobe Launch | Property IDs | passive | Note only |
| SAAS-088 | Brevo / Sendinblue / Mailjet | Key exposure | passive | Grep |
| SAAS-089 | Bitbucket / GitHub / GitLab tokens in JS or config | Personal access tokens leaked | passive | Grep for ghp_, glpat-, bb tokens; treat as secret |
| SAAS-090 | Docker Hub / npm / PyPI tokens in published artifacts | Publish tokens leaked | passive | Grep .npmrc, .pypirc, docker config in artifacts you are given |
