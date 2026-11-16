# Takeover Provider Fingerprints (extension)

Class key: `passive` = DNS and HTTP response reading. `bounded` = one unauthenticated GET per host. Claiming a resource or registering a provider name is never part of this skill (see the skill's rules).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TKO-S3-001 | Amazon S3 | CNAME to bucket that does not exist (NoSuchBucket) | passive | `dig CNAME`; GET host, look for NoSuchBucket |
| TKO-S3-002 | Amazon S3 | Bucket name enumeration and public list permission | bounded | Anonymous `aws s3 ls s3://<bucket> --no-sign-request` (listing only, no writes) |
| TKO-S3-003 | Amazon S3 | Public write permission | authorized-only | Never write; report from bucket policy/ACL read only |
| TKO-S3-004 | Amazon S3 | Object ACL misconfiguration | authorized-only | Read ACL only where approved |
| TKO-GHP-001 | GitHub Pages | CNAME to *.github.io with "There isn't a GitHub Pages site here" | passive | GET host, look for the message |
| TKO-HEROKU-001 | Heroku | CNAME to herokuapp with "No such app" | passive | GET host, look for message |
| TKO-FASTLY-001 | Fastly | "Fastly error: unknown domain" on CNAME target | passive | GET host, look for message |
| TKO-HASHNODE-001 | Hashnode | Custom domain pointing to Hashnode without active blog | passive | GET host, look for Hashnode 404 text |
| TKO-DUDA-001 | Duda | CNAME to Duda with deleted site | passive | GET host, look for Duda not-found page |
| TKO-AZURE-001 | Azure (App Service, Blob, Traffic Manager) | CNAME to azurewebsites.net or blob with no resource | passive | `dig CNAME`; GET host; check NXDOMAIN on target |
| TKO-NETLIFY-001 | Netlify | "Not found - Request ID" on custom domain | passive | GET host, look for message |
| TKO-VERCEL-001 | Vercel | "The deployment could not be found" on alias | passive | GET host, look for message |
| TKO-SHOPIFY-001 | Shopify | "Sorry, this shop is currently unavailable" | passive | GET host, look for message |
| TKO-TUMBLR-001 | Tumblr | "Whatever you were looking for doesn't currently exist" | passive | GET host |
| TKO-WIX-001 | Wix | Unclaimed Wix site on CNAME | passive | GET host, look for Wix not-found page |
| TKO-SQUARESPACE-001 | Squarespace | Dangling domain page | passive | GET host |
| TKO-PANTHEON-001 | Pantheon | "404 unknown site" | passive | GET host |
| TKO-CLOUDFRONT-001 | CloudFront | "Bad request: could not resolve" with dangling distribution | passive | GET host, dig CNAME |
| TKO-ZENDESK-001 | Zendesk | "Help Center Closed" | passive | GET host |
| TKO-UNBOUNCE-001 | Unbounce | "The requested URL was not found" page | passive | GET host |
| TKO-READTHEDOCS-001 | Read the Docs | Unclaimed project page | passive | GET host |
| TKO-ACQUIA-001 | Acquia / Pantheon / Platform.sh | Environment removed but CNAME remains | passive | GET host, dig CNAME |
| TKO-NS-001 | Any | Delegated NS to nameserver domain that is expired | passive | `dig NS` for each delegated zone; check registrar availability via WHOIS only (do not register) |
| TKO-MX-001 | Any | MX to expired domain | passive | `dig MX`; check domain availability via WHOIS only |
| TKO-TXT-001 | Any | Verification TXT (SaaS) for a service the org no longer uses | passive | Review TXT records for SaaS verification tokens (report, do not claim) |
| TKO-DANGLE-001 | Any | A record to released cloud IP | passive | `dig A`; check ownership via ASN lookup, no claim |
