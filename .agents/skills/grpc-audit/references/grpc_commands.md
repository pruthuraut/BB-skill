# gRPC Command Templates (grpcurl)

Install: `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`. Use `-plaintext` for h2c, `-insecure` only for testing certificate issues, and `-H` for metadata.

## Reflection and enumeration (GRPC-001, GRPC-008)

```bash
grpcurl HOST:PORT list
grpcurl -plaintext HOST:PORT list
grpcurl HOST:PORT list package.Service
grpcurl HOST:PORT describe package.Service
grpcurl HOST:PORT describe package.Request
grpcurl -H 'authorization: Bearer OWN' HOST:PORT list          # reflection behind auth?
```

## Health and admin (GRPC-008)

```bash
grpcurl HOST:PORT grpc.health.v1.Health/Check
grpcurl HOST:PORT grpc.channelz.v1.Channelz/GetTopChannels      # read-only, reveals peers/addresses
```

## Calls with and without credentials (GRPC-002, GRPC-010)

```bash
grpcurl -d '{"id":"OWN_ID"}' HOST:PORT package.UserService/GetUser
grpcurl -H 'authorization: Bearer OWN_A' -d '{"id":"OWN_ID"}' HOST:PORT package.UserService/GetUser
grpcurl -H 'authorization: Bearer OWN_B' -d '{"id":"A_OBJECT_ID"}' HOST:PORT package.UserService/GetUser
grpcurl -H 'x-user-id: OTHER_OWN_ID' -H 'authorization: Bearer OWN_A' -d '{}' HOST:PORT package.UserService/GetMe
```

## Without reflection (proto files from the app)

```bash
grpcurl -import-path ./protos -proto user.proto HOST:PORT list
grpcurl -import-path ./protos -proto user.proto -d '{"id":"OWN_ID"}' HOST:PORT package.UserService/GetUser
```

## Verbose metadata (GRPC-005)

```bash
grpcurl -v -H 'authorization: Bearer OWN' -d '{"id":"OWN_ID"}' HOST:PORT package.UserService/GetUser
```

## Serialization variants (GRPC-003, one request each)

```bash
grpcurl -d '{"id": 123}' ...                 # number where string expected
grpcurl -d '{"id": "OWN_ID", "limit": -1}' ...
grpcurl -d '{"id": "OWN_ID", "unknownField": 1}' ...    # grpcurl rejects unknown JSON fields; use raw protobuf tools for unknown field numbers
grpcurl -max-msg-sz 4194304 -d '{"name":"<4000 chars>"}' ...
```

Raw protobuf mutation: `protoc --encode` to build a message, edit bytes (field numbers, wire types, lengths), send with a small gRPC client or Burp + gRPC extension (e.g. "blackboxprotobuf").

## Deadlines (GRPC-009)

```bash
grpcurl -max-time 600 -d '{...}' HOST:PORT package.ReportService/Generate     # own report; observe whether the server applies its own limit
```

## gRPC-Web (GRPC-007)

```bash
printf '\x00\x00\x00\x00\x00' | curl -s -i -X POST https://HOST/grpc.health.v1.Health/Check \
  -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' --data-binary @-
```

A response with `grpc-status` headers means a gRPC-Web gateway is exposed over HTTP/1.1 (browser-reachable; check CORS and auth parity).

## Other tools

grpcui (web UI over reflection), Burp extensions for gRPC/protobuf, Postman gRPC, ghz (load testing: authorized-only), protoc.
