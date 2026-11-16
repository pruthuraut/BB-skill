# Microservices and API Gateway Checklist

Class key: `passive` = configuration and documentation review. `bounded` = a few GET requests or single marker headers. `authorized-only` = registry changes, interception, floods, or any change to service state.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GW-001 | Eureka | Service registry readable without auth (`/eureka/apps`) | bounded | GET `/eureka/apps`; record service names and count only |
| GW-002 | Consul | Catalog and agent service lists readable without ACL token | bounded | GET `/v1/catalog/services`, `/v1/agent/services` |
| GW-003 | Nacos | Service list readable without auth | bounded | GET `/nacos/v1/ns/service/list` |
| GW-004 | Gateway auth | Protected route answers without credentials | bounded | Anonymous GET of one documented protected route |
| GW-005 | Gateway auth | Backend reachable directly, bypassing the gateway auth layer | bounded | `--backend` in-scope URL; compare auth parity |
| GW-006 | Routing headers | X-Forwarded-For, X-Original-URL, X-Forwarded-Host change the access decision | bounded | Routing-header comparison in `gateway_probe.py` |
| GW-007 | Service mesh | Istio or Linkerd admin or control endpoints exposed | passive | Review ingress rules; check admin ports 15000, 15014 on in-scope hosts with nmap |
| GW-008 | Service mesh | Trace or dtab headers accepted from clients (routing override) | authorized-only | Review config; do not send routing overrides |
| GW-009 | mTLS | Inter-service traffic not encrypted or not mutually authenticated | passive | Review mesh policy; `openssl s_client` to in-scope internal TLS ports |
| GW-010 | Rate limits | Limits enforced per route, not per client, so a route bypass skips them | bounded | Compare a few requests across routes (no flood) |
| GW-011 | Transformation | Request or response transformation exposes internal fields | bounded | Compare gateway response with backend response for one route |
| GW-012 | Errors | Gateway error pages reveal backend names, stack traces, or versions | bounded | Malformed route marker; `gateway_probe.py` errors section |
| GW-013 | Ports | Internal service ports reachable from the internet through misconfigured gateway | bounded | `nmap -Pn -sV -p <ports> <in-scope host>` |
| GW-014 | Registry | Service registration or deregistration possible without auth | authorized-only | Review ACLs; never register or deregister |
| GW-015 | Circuit breaker | Breaker state or fallback reveals internal endpoints | passive | Review fallback responses; no fault injection |
| GW-016 | Health | Health endpoints disclose dependency names, versions, or credentials | bounded | GET `/health`, `/actuator/health`; check detail level |
| GW-017 | Actuator | Actuator env or beans exposed through the gateway | bounded | GET `/actuator` index; never call write endpoints |
| GW-018 | Tracing | X-B3-TraceId, traceparent reflected or logged unsafely | bounded | Single marker header; `gateway_probe.py` headers section |
| GW-019 | Tracing | Trace headers used in downstream queries or logs (injection) | authorized-only | Review logs and code; no injection payloads |
| GW-020 | CORS | Gateway reflects arbitrary origins with credentials | bounded | One Origin probe; `gateway_probe.py` cors section |
| GW-021 | Documentation | Swagger or OpenAPI for internal services exposed through the gateway | bounded | GET `/v3/api-docs`, `/swagger-ui.html` |
| GW-022 | Reporting | Evidence and fixes: restrict discovery endpoints, enforce auth at backends, strip routing headers, mTLS, limit error detail | passive | Recommendation list |
