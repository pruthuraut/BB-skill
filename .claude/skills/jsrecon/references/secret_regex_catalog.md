# Master JavaScript Secret Regex Catalog & Verification Matrix

This reference catalog details 60+ verified regular expressions for extracting credentials, API keys, and sensitive tokens from frontend JavaScript bundles and unpacked source maps.

---

## 1. Cloud & Infrastructure Providers

| Provider / Token | Regex Pattern | Verification Command |
| :--- | :--- | :--- |
| **AWS Access Key ID** | `\b(AKIA\|ASIA\|ABIA\|ACCA)[0-9A-Z]{16}\b` | `aws sts get-caller-identity` |
| **AWS Secret Access Key** | `aws.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]` | Correlate with Key ID |
| **AWS S3 Bucket URL** | `[a-z0-9.-]+\.s3([.-][a-z0-9-]+)?\.amazonaws\.com` | `aws s3 ls s3://<bucket> --no-sign-request` |
| **AWS Cognito Pool ID** | `[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com` | Check unauthenticated signup |
| **Google API Key** | `AIza[0-9A-Za-z_-]{35}` | Query Google Maps/Identity APIs |
| **Google OAuth Client ID** | `[0-9]{10,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com` | Check allowed redirect URIs |
| **Firebase Realtime DB** | `https?://[a-z0-9-]+\.firebaseio\.com` | `curl https://<db>.firebaseio.com/.json` |
| **Azure Blob Storage** | `https?://[a-z0-9]+\.blob\.core\.windows\.net` | Check public container listings |
| **DigitalOcean PAT** | `dop_v1_[a-f0-9]{64}` | `curl -H "Authorization: Bearer <token>" https://api.digitalocean.com/v2/account` |
| **Heroku API Key** | `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | Test Heroku Platform API |

---

## 2. Communication & Developer Services

| Service / Token | Regex Pattern | Verification |
| :--- | :--- | :--- |
| **Slack Bot / User Token** | `xox[baprs]-[0-9A-Za-z-]{10,}` | `curl -H "Authorization: Bearer <token>" https://slack.com/api/auth.test` |
| **Slack Webhook URL** | `https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}` | Inspect channel destination |
| **Discord Webhook** | `https://(ptb\.)?discord\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}` | Inspect channel name |
| **Twilio Account SID** | `AC[a-f0-9]{32}` | Twilio REST API check |
| **Twilio API Secret** | `SK[a-f0-9]{32}` | Twilio REST API check |
| **SendGrid API Key** | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | Test SendGrid Mail API |
| **Mailgun API Key** | `key-[a-z0-9]{32}` | Test Mailgun v3 API |

---

## 3. Payment & Authentication Credentials

| Type | Regex Pattern | High Impact Risk |
| :--- | :--- | :--- |
| **Stripe Live Secret Key** | `sk_live_[A-Za-z0-9]{24,}` | Direct financial drain / charge refunds |
| **Stripe Publishable Key** | `pk_live_[A-Za-z0-9]{24,}` | Client-side identifier (low severity unless misconfigured) |
| **JWT (JSON Web Token)** | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}` | Inspect header/payload on jwt.io |
| **Private Key Header** | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH\|PGP )?PRIVATE KEY` | Host / Server RCE or decrypt traffic |
| **Basic Auth URL** | `[a-zA-Z][a-zA-Z0-9+.-]{2,10}://[^/:\s@'\"]+:[^/:\s@'\"]+@[^/:\s'\"]+` | Internal service credentials |
| **Authorization Header** | `['\"]?[Aa]uthorization['\"]?\s*[:=]\s*['\"][^'\"]{15,}['\"]` | Hardcoded Bearer/Basic headers |

---

## 4. Artificial Intelligence & Modern APIs

| Service | Regex Pattern |
| :--- | :--- |
| **OpenAI API Key** | `sk-(proj-)?[A-Za-z0-9_-]{20,}` |
| **Anthropic API Key** | `sk-ant-[A-Za-z0-9_-]{20,}` |
| **HuggingFace User Token** | `hf_[A-Za-z0-9]{34}` |
| **Postman API Key** | `PMAK-[a-f0-9]{24}-[a-f0-9]{34}` |
| **GitHub Token** | `(ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9]{36}` |
| **GitHub Fine-Grained PAT** | `github_pat_[A-Za-z0-9_]{82}` |
| **GitLab PAT** | `glpat-[A-Za-z0-9_-]{20}` |
| **Telegram Bot Token** | `[0-9]{8,10}:AA[0-9A-Za-z_-]{33}` |
