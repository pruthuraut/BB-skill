---
name: server-side-injection
description: "Audit authorized applications for server-side injection classes that are not SQL or XSS: server-side template injection (SSTI), OS command injection, XML external entities (XXE), NoSQL operator injection, LDAP filter injection, unsafe deserialization, and input validation failures. Triggers on \"SSTI\", \"template injection\", \"command injection\", \"XXE\", \"XML upload\", \"NoSQL injection\", \"$ne\", \"LDAP injection\", \"deserialization\", \"ysoserial\", \"unserialize\", \"input validation\", or when route_target.py routes template, cmd, xml, ldap, or filter parameters."
---

# Server-Side Injection

Find where user input reaches a template engine, a shell, an XML parser, a NoSQL query, an LDAP filter, or a deserializer. Detection uses harmless arithmetic, markers, and OOB callbacks. Code execution, file reads, and gadget chains are authorized-only and need a lab or explicit approval.

Checklist: `references/ssti_cmdi_xxe_nosql_ldap_deser.md` (33 rows). For full template-injection work (engine matrix, injection points, blind SSTI, detection probe tool), use `ssti-audit` and start there when a template parameter is present. For shell command injection, use `command-injection-audit`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Identify sinks from parameters (template, cmd, xml, ldap, filter) and content types (XML, serialized blobs in cookies or params).
3. SSTI: send the arithmetic probe set (SSI-001) and check for evaluated output. Identify the engine from error text (SSI-002). Stop at detection.
4. OS command: use timing or harmless marker probes only (SSI-008, SSI-009), with approved delay.
5. XXE: point the entity to your OOB host (SSI-012, SSI-016). Local file reads are authorized-only.
6. NoSQL: compare the normal response with operator variants on your own account (SSI-017, SSI-019).
7. LDAP: wildcard and filter probes on your own username (SSI-021, SSI-022).
8. Deserialization: identify serialized formats (SSI-023 to SSI-027) and report. Do not send gadget payloads without approval.
9. Save evidence to `artifacts/<target>/server_side_injection.json`.

## Classes

- `passive`: review, headers, error text.
- `bounded`: arithmetic, marker, timing, and OOB probes.
- `authorized-only`: execution, file reads, writes, gadgets.

## Rules

- A confirmed SSTI or command injection is critical. Stop at proof (arithmetic result or sleep difference) and report. Do not chain to a shell without approval.
- Never send XXE entities that read real secrets. Use OOB confirmation only.

## Additional checklist and tools (added)

- Covers: Deserialization (21 checks) and SSI injection (10 checks).
- Checklist: `references/deserialization_ssi_checks.md`.
- Tools: scripts/deser_detect.py (passive format detector) and scripts/ssi_probe.py (echo directives only).
- Class policy: `passive` and `bounded` run in scope with the stated limits. `authorized-only` needs explicit approval for that check. These probes never send gadget, execution, or flood payloads.
