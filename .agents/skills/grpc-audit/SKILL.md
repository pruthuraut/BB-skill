---
name: grpc-audit
description: Audit authorized gRPC services across 10 checks — server reflection exposure, unauthenticated access to services and methods, protobuf message serialization attacks (type confusion, unknown fields, oversized/negative lengths, deep nesting), connection hijacking via plaintext or unauthenticated channels (no TLS, no mTLS, h2c), metadata security (sensitive request/response headers and trailers, debug metadata, tokens in metadata), stream abuse for DoS (approval only), TLS configuration and encryption enforcement (ALPN h2, plaintext fallback, gRPC-Web over HTTP/1.1), service enumeration through reflection (admin, debug, channelz, health, internal services), deadline and timeout exploitation, and channel credential and token handling (per-RPC credentials, token scope, reuse across services). Includes a dependency-free transport probe (TLS + ALPN, plaintext HTTP/2 preface, gRPC-Web detection) and a grpcurl driver for reflection, describe, health, metadata capture, and own-call authorization comparison. Triggers on "gRPC", "grpc", "protobuf", "proto", "grpcurl", "reflection", "grpc-web", "HTTP/2 API", "h2c", "channelz", ":50051", or when network-portscan finds HTTP/2-only services.
---

# gRPC Security Audit (10 checks)

gRPC runs over HTTP/2 with protobuf messages. Clients normally need `.proto` definitions, so server reflection is the main enumeration path. Authentication usually rides in metadata (`authorization` headers) or on the channel (mTLS), and must be enforced per method by interceptors. Plaintext HTTP/2 (h2c) and gRPC-Web gateways often widen exposure.

- Checklist: `references/grpc_checklist.md` (GRPC-001 to GRPC-010, sensitive service names, metadata review list, deadline notes).
- Templates: `references/grpc_commands.md` (grpcurl commands for reflection, describe, calls with/without metadata, proto-file mode, gRPC-Web with curl, fuzzing notes).
- Tracker: `references/grpc_tracker.md`.
- `scripts/grpc_probe.py`: transport checks without dependencies (TCP, TLS + ALPN `h2`, certificate summary, plaintext HTTP/2 preface/SETTINGS, gRPC-Web on HTTP/1.1), then, if `grpcurl` is installed, reflection `list`/`describe`, health check, sensitive-service flags, verbose metadata capture, and own read-only `--call` operations with and without `--auth` metadata.
- Related: `tls-audit` (TLS details), `api-security` (AA rows), `access-control`, `idor`, `resource-exhaustion`, `network-portscan` (find gRPC ports such as 50051, 9090, 8443), `request-smuggling-audit` (h2c upgrade smuggling).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. gRPC is often on non-web ports; include `host:port` hosts in scope.
2. Find services: network-portscan (HTTP/2 services, 50051, 9090, 443), JS/mobile apps (`.proto` files, `grpc-web` clients, `/package.Service/Method` paths), Envoy/gateway configs.
3. Transport and exposure:

   ```bash
   python3 .agents/skills/grpc-audit/scripts/grpc_probe.py --target example.com --addr grpc.example.com:443 \
     --auth 'authorization: Bearer OWN_TOKEN' --out artifacts/example.com/grpc.json
   ```

   Install grpcurl for reflection and calls (`go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`) or pass `--grpcurl PATH`.
4. With reflection off, use `.proto` files from apps (`--proto`/`--import-path` in grpcurl) or guess common service names (health, reflection, channelz).
5. Authorization (GRPC-002, GRPC-010): list read-only methods on your own data in a calls file and run them with your token, another account's token (`--auth-b`), and no metadata.
6. Serialization (GRPC-003): mutate own requests (wrong field types via JSON→protobuf, unknown field numbers, very large strings at a bounded size, deep nesting) with grpcurl or a protobuf fuzzer, one request per variant; follow the error-handling rules.
7. Streams and deadlines (GRPC-006, GRPC-009): record whether the server enforces message size limits, max concurrent streams, and its own deadlines (from configuration or a single long-deadline request); floods are authorized-only.
8. Save findings to `artifacts/<target>/grpc.json` and the tracker to `artifacts/<target>/grpc_tracker.md`.

## Classes

- `passive`: proto files, client code, configuration.
- `bounded`: transport checks, reflection list/describe, health check, own read-only calls with/without metadata, single mutated messages.
- `authorized-only`: stream floods, connection exhaustion, oversized messages beyond small proofs, calling write/admin methods, and channelz/admin operations that change state.

## Rules

- Call only methods you have identified as read-only and only on your own data; never call methods whose names suggest writes/admin without approval.
- Do not hold long-lived streams open or open many concurrent streams.
- Redact tokens in captured metadata.

## Mitigation guidance for reports

- Disable server reflection in production (or require auth); do not expose channelz/admin services publicly.
- Authentication interceptors on every service and method (default deny); per-method authorization; validate token audience and scope.
- TLS (preferably mTLS for service-to-service); never serve plaintext h2c on public interfaces; gRPC-Web gateways must enforce the same auth.
- Message size limits (`MaxRecvMsgSize`), max concurrent streams, keepalive enforcement, server-side deadlines and cancellation.
- Strip sensitive metadata and internal error details from responses (`grpc-message` without stack traces).
- Validate decoded messages (ranges, lengths, enums); keep protobuf libraries patched.

## Sources

gRPC documentation (authentication, ALTS/TLS, reflection, deadlines, keepalive), OWASP gRPC Security Cheat Sheet, grpcurl documentation, CNCF/Envoy gRPC-Web docs, CWE-306, CWE-319, CWE-400, CWE-502.
