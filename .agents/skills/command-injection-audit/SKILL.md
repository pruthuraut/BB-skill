---
name: command-injection-audit
description: "Audit authorized applications for OS command injection (shell injection) across unix and Windows: command separators (; | && || & newline), backticks and $() substitution, quote-context breaks, IFS and brace-expansion encodings, WAF and encoding bypass variants, blind detection by timing and out-of-band DNS or HTTP callbacks, and feature contexts (ping, traceroute, DNS lookup, filename, image and PDF conversion, archive extraction, backup and cron parameters, email headers, log processing). Includes a scope-gated probe that uses only echo and arithmetic probes, a timing mode, and a passive source sink scanner for code review. Triggers on \"command injection\", \"shell injection\", \"OS command\", \"ping=\", \"host=\", \"cmd=\", \"exec=\", \"system(\", \"shell=True\", \"child_process\", \"Runtime.exec\", or when route_target.py routes cmd, exec, ping, or similar parameters."
---

# Command Injection Audit

Find where user input reaches a shell or process-spawn call. Detection uses an echo of a split marker, shell arithmetic, and optionally a timed sleep, all on your own input. Confirmed execution is reported with that evidence. File writes, network callbacks beyond your own DNS or HTTP host, reverse shells, and persistence are authorized-only and are not part of this skill.

Checklist: `references/cmdi_checklist.md`. Tools: `scripts/cmdi_probe.py` (black-box, scope-gated), `scripts/sink_scan.py` (passive source review).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Find candidate parameters: `route_target.py --params` returns the command-style names (cmd, exec, command, ping, host, query, process, and others from the checklist). Also check every feature that calls an external tool (ping, traceroute, nslookup, convert, pdf, zip, backup, cron).
3. Black-box detection:

   ```
   python3 .agents/skills/command-injection-audit/scripts/cmdi_probe.py --target example.com \
     --workspace ~/Documents/bugbounty --url 'https://example.com/ping' --param host \
     --out artifacts/example.com/cmdi.json
   ```

   The probe sends at most 40 requests. Every echo probe uses a split marker, so a result counts only when the shell actually joined the pieces.
4. Timing (optional, needs approval for the target): add `--allow-timing --sleep 5`. A timing candidate is only a candidate. Repeat it, compare with a control request, and check that the delay tracks the sleep value.
5. Out-of-band (authorized, your own host only): use a DNS or HTTP callback on a host you control, with a single `nslookup` or `curl` to that host. Record the hit with its timestamp.
6. Source review (if code is in scope): `python3 .agents/skills/command-injection-audit/scripts/sink_scan.py <source-dir> --out artifacts/<target>/sinks.json`. Treat `high` findings as priority, confirm the input path, then test the matching endpoint.
7. Save evidence to `artifacts/<target>/command_injection.json`.

## Classes

- `passive`: source review with `sink_scan.py`, reading error messages and headers.
- `bounded`: echo, arithmetic, and encoding probes on your own input; timing only with approval.
- `authorized-only`: anything beyond echo and arithmetic, including file writes, output redirection, environment-variable tricks (BASH_ENV, LD_PRELOAD, PERL5OPT, NODE_OPTIONS, PYTHONWARNINGS, RUBYOPT, GIT_*), network connections, and any persistence. Requires explicit written approval and an isolated lab.

## Rules

- Stop at proof of execution. A split-marker echo or arithmetic result is enough evidence for the report.
- Do not read secrets, system files, or other users' data to demonstrate impact. If a real identity check is needed, use `id` on a host you own or in an approved lab only.
- Use your own accounts and your own objects for any feature that is user-scoped (for example, your own backup name or your own upload).
- Keep timing requests to a single chain at a time, and never flood the endpoint.
- Redact any secrets in responses.
- Report the sink, the input path, the separator or context that worked, and the fix (argument arrays without a shell, strict allowlists, no string concatenation into commands).
