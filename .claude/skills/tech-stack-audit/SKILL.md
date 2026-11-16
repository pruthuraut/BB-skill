---
name: tech-stack-audit
description: Audit authorized targets for product-specific exposure and known-CVE version risk across about 470 checks, grouped into CMS and ecommerce, web frameworks and languages, DevOps and CI/CD, monitoring and databases, identity and network appliances, IoT and ICS, and enterprise/ERP/collaboration. Triggers when a fingerprint shows Jenkins, GitLab, Grafana, Kibana, Elasticsearch, WordPress, Drupal, Joomla, Magento, Tomcat, WebLogic, Confluence, Jira, FortiGate, Palo Alto, Ivanti, Citrix, Zabbix, Keycloak, Kubernetes, Docker, Vault, Redis, MongoDB, or similar. Checks are version, exposure, and default-surface verifications, never exploits.
---

# Tech Stack Audit

Product-specific checks for what the target runs. Each row says what to verify, how safe it is, and how to verify it without exploiting. Rows are grouped in `references/`:

| File | Covers |
|---|---|
| `cms-ecommerce.md` | WordPress, Drupal, Joomla, Magento, OpenCart, Shopify, hosting panels, and about 120 more CMS and ecommerce products |
| `frameworks-languages.md` | Django, Rails, Laravel, Spring Boot, Express, Next.js, Nuxt, Struts, and more |
| `devops-containers.md` | Jenkins, GitLab, Gitea, Nexus, Harbor, Docker, Kubernetes, etcd, Consul, Vault, Traefik, Kong, APISIX |
| `monitoring-databases-queues.md` | Grafana, Kibana, Prometheus, Zabbix, Splunk, Elasticsearch, Redis, MongoDB, Solr, RabbitMQ, ActiveMQ, Firebase |
| `identity-network-iot.md` | Keycloak, Okta, Apereo CAS, FortiGate, Palo Alto, Ivanti, Citrix, F5, Cisco, Ubiquiti, routers, cameras, iLO |
| `enterprise-collab-erp.md` | Confluence, Jira, SharePoint, Exchange, SAP, ManageEngine, Odoo, Frappe, BI tools, AEM, ColdFusion, WebLogic |

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Build the product list from the fingerprint: `python3 scripts/route_target.py --fingerprint <file>` prints matched rows with IDs and classes.
3. Run `passive` rows first, then `bounded` rows (limits from each row). Run `authorized-only` rows only after approval for that check.
4. For each version-gated CVE row, record the detected version, the fixed release from the advisory, and the verdict (affected, not affected, unknown). Do not run exploit code to confirm.
5. Track the checklist: 0 to N rows complete per target. Save results to `artifacts/<target>/tech_stack.json`.

## Classes

- `passive`: headers, body, or a known path with GET. No login, no writes.
- `bounded`: a few safe requests on your own accounts or without credentials, with stated limits.
- `authorized-only`: default credentials, spraying, deserialization, or any state change. Requires explicit approval recorded in the scope file or the engagement notes.

## Rules

- Version checks never run an exploit. If a CVE is affected, report the version evidence and the advisory link. Confirmation beyond that needs a separate, approved lab test.
- Default credential checks are authorized-only and must be approved per product.
- Redact any secret found in responses (keys, tokens, passwords) in artifacts.
- Vendor advisories are the source of truth for fixed versions. Verify the version before reporting.
