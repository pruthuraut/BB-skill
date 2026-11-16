---
name: microservices-gateway-audit
description: Audit authorized microservice and API gateway deployments across 15 checks: exposed service discovery (Eureka, Consul, Nacos), gateway authentication bypass and direct backend access, service mesh exposure (Istio, Linkerd), inter-service encryption and mTLS, gateway rate-limit and transformation issues, backend information disclosure through gateway errors, internal port exposure, service registry spoofing, circuit breaker and health endpoint disclosure, distributed tracing header injection, and gateway CORS. Uses Kali nmap for in-scope port checks and a bounded, scope-gated probe. Triggers on "API gateway", "microservices", "Eureka", "Consul", "Nacos", "service mesh", "Istio", "Linkerd", "mTLS", "service discovery", "X-B3-TraceId", "actuator", "health endpoint", "gateway bypass".
---

# Microservices and API Gateway Audit

Check how a gateway fronts internal services: what discovery and health endpoints are exposed, whether backends answer without the gateway, whether routing headers change access decisions, and what internal details leak through errors. The probe sends bounded GET requests and single benign marker headers. It writes nothing and never changes a registry.

Checklist: `references/gateway_checklist.md` (15 core checks plus supporting rows). Probe: `scripts/gateway_probe.py` (with Kali `nmap` for in-scope ports).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. The gateway, each backend, and each host you scan must be listed in scope.
2. Run the probe. Add in-scope backends you can reach directly and an in-scope host with ports to scan:

   ```
   python3 .agents/skills/microservices-gateway-audit/scripts/gateway_probe.py --target example.com \
     --workspace ~/Documents/bugbounty --base https://api.example.com \
     --backend https://10.0.0.5:8443 --host 10.0.0.5 --ports 8080,8500,8761,15000 \
     --out artifacts/example.com/gateway.json
   ```

3. Compare backend and gateway responses for the same operation: same status, same auth requirement, same data. A backend that answers without the gateway is a finding only if it returns data the gateway would protect.
4. Review discovery results (Eureka `/eureka/apps`, Consul `/v1/catalog/services`, Nacos service list). Report what is exposed. Do not register or deregister services.
5. Use `scripts/gateway_probe.py` output for the tracing and CORS items, then follow the checklist for mesh and mTLS items (configuration review).
6. Save evidence to `artifacts/<target>/gateway.json`.

## Classes

- `passive`: configuration review, headers, mesh documentation.
- `bounded`: GET requests to discovery and health paths, one routing-header comparison, one tracing marker, one CORS probe, and nmap service detection on in-scope ports.
- `authorized-only`: registry changes, traffic interception, stream or request floods, and any action that changes service state.

## Rules

- Do not modify service registries, configuration, or routes.
- Do not flood the gateway. The probe is capped at 40 requests.
- Redact tokens and internal addresses from saved artifacts where the program requires it.
