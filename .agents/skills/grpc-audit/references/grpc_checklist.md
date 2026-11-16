# gRPC Security Checklist

Class key: `passive` = protos, client code, config. `bounded` = transport checks, reflection, health, own read-only calls, single mutated messages. `authorized-only` = stream floods, connection exhaustion, oversized messages, write/admin calls.

## Core checks (10)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| GRPC-001 | Reflection | Server reflection service exposed (`grpc.reflection.v1alpha.ServerReflection` / `v1`) without authentication | bounded | grpc_probe.py `grpcurl list` with and without `--auth` |
| GRPC-002 | Auth | Unauthenticated access to services/methods (interceptor missing on some services, health/admin open) | bounded | grpc_probe.py `--calls` own read-only methods without metadata |
| GRPC-003 | Serialization | Protobuf serialization attacks: type confusion, unknown field numbers, negative/oversized lengths, deep recursion, enum out of range, decoding errors leaking internals | bounded | Single mutated own requests; record status codes (`INVALID_ARGUMENT` expected) and `grpc-message` leaks |
| GRPC-004 | Hijacking | Connection hijacking between client and server: plaintext h2c, TLS without certificate validation in clients, no mTLS for service-to-service, tokens over plaintext | bounded | grpc_probe.py plaintext preface check; client config review |
| GRPC-005 | Metadata | Metadata security: sensitive response headers/trailers (server versions, internal hosts, stack traces in `grpc-status-details-bin`, debug info), tokens or PII in metadata, trust in client metadata (`x-user-id`, `x-role`) | bounded | grpc_probe.py verbose capture; own call with identity metadata variants |
| GRPC-006 | Streams | Stream abuse for DoS (unbounded server/client streams, no max concurrent streams, no message size limits, keepalive abuse) | authorized-only | Configuration review and approved tests only |
| GRPC-007 | TLS | TLS configuration and encryption enforcement (ALPN `h2`, protocol versions, certificate validity, plaintext fallback, gRPC-Web over HTTP/1.1 without TLS) | bounded | grpc_probe.py TLS/ALPN and gRPC-Web checks; tls-audit for depth |
| GRPC-008 | Enumeration | Service enumeration via reflection: admin/debug/internal/channelz/CSDS/health services, hidden methods, full message schemas | bounded | grpc_probe.py `list` + `describe`; flag sensitive names |
| GRPC-009 | Deadlines | Deadline and timeout exploitation (server ignores cancellation, no server-side deadline, very long client deadlines accepted for heavy methods) | bounded | One own call with a long `grpc-timeout`; config review; resource-exhaustion rules |
| GRPC-010 | Credentials | Channel credential and token handling (per-RPC tokens not validated per method, tokens for one service accepted by another, long-lived static tokens, tokens over insecure channels, missing audience checks) | bounded | `--calls` with `--auth-b` and tokens from other services/environments you own |

## Sensitive service and method names

`grpc.channelz.v1.Channelz`, `envoy.service.status.v3.ClientStatusDiscoveryService` (CSDS), `grpc.admin`, `*Admin*`, `*Debug*`, `*Internal*`, `*Management*`, `*Config*`, `*Migration*`, `*Backup*`, `*Exec*`, `*Shell*`, `*Impersonat*`, `grpc.health.v1.Health` (expected, but check what it reveals), `*.v1alpha*`/`*.test*` services.

## Metadata review list

| Location | Look for |
|---|---|
| Response headers | `server`, `x-envoy-*`, `x-powered-by`, internal hostnames, versions |
| Trailers | `grpc-message` with stack traces/SQL, `grpc-status-details-bin` (decode `google.rpc.Status` details) |
| Request metadata trusted | `x-user-id`, `x-tenant-id`, `x-role`, `x-forwarded-*`, `x-internal` |
| Tokens | `authorization`, `x-api-key`, cookies over plaintext channels |

## gRPC status codes

| Situation | Expected |
|---|---|
| No credentials | `UNAUTHENTICATED (16)` |
| Not allowed | `PERMISSION_DENIED (7)` |
| Bad message | `INVALID_ARGUMENT (3)` |
| Not found / other's object | `NOT_FOUND (5)` |
| Too large | `RESOURCE_EXHAUSTED (8)` |
| Deadline | `DEADLINE_EXCEEDED (4)` |

## Cross-references

| GRPC row | Related |
|---|---|
| GRPC-002, GRPC-010 | api-security AA-001, AA-023; access-control; idor |
| GRPC-003 | error-handling-audit |
| GRPC-004, GRPC-007 | tls-audit, request-smuggling-audit RS-V-005 (h2c) |
| GRPC-006, GRPC-009 | resource-exhaustion |
