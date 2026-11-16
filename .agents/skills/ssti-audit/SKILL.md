---
name: ssti-audit
description: Audit authorized applications for server-side template injection (SSTI) across the main template engines (Jinja2, Twig, FreeMarker, ERB, Velocity, Thymeleaf, Pebble, Mako, Tornado, Smarty, Handlebars, Razor, Node and Vue/Angular client templates). Covers detection with arithmetic and syntax-break probes, engine fingerprinting by differential results, blind SSTI through replay and response search, injection points (name, template, preview, email, report, invoice, theme editor, PDF and search features), and SSTImap usage in detection mode. Triggers on "SSTI", "template injection", "{{7*7}}", "${7*7}", "server-side template", "Jinja", "Twig", "FreeMarker", "Velocity", "Thymeleaf", "email template", "report template", "invoice template", or when route_target.py routes template, preview, view, or content parameters.
---

# SSTI Audit

Find user input that is concatenated into a template instead of passed as data, identify the engine, and report proven template evaluation. Detection uses harmless arithmetic. Code execution, file reads, and object traversal are authorized-only, and this skill does not carry those payloads.

Checklist: `references/ssti_checklist.md` (engine matrix, injection points, methodology, and mitigation rows). Probe tool: `scripts/ssti_probe.py`.

## Why it matters

Template engines combine fixed templates with data. When user input becomes part of the template text, the engine evaluates it on the server. A confirmed SSTI on a server-side engine is usually critical, because the engine can reach the runtime. The impact must still be shown with approved, non-destructive evidence only.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Map injection points. Prioritize parameters named `template`, `preview`, `id`, `view`, `activity`, `name`, `content`, `redirect`, and any field that feeds email, notification, report, invoice, PDF, search results, error pages, or theme and page editors. Use `route_target.py --params` to get the list.
3. Baseline: send a unique marker and confirm it is reflected unchanged.
4. Detect: run the arithmetic probe set with `scripts/ssti_probe.py`. Example:

   ```
   python3 .agents/skills/ssti-audit/scripts/ssti_probe.py --target example.com \
     --workspace ~/Documents/bugbounty --url 'https://example.com/preview' \
     --param template --method POST --out artifacts/example.com/ssti.json
   ```

   The tool sends at most 40 requests, one per second by default, and only arithmetic, syntax-break, and marker probes.
5. Identify the engine: compare differential results from the matrix in the reference file (for example `{{7*'7'}}` returns `7777777` for Jinja2 or Tornado and `49` for Twig). Use error signatures as a secondary hint.
6. Confirm with a second, different probe (for example the long-form product `7*77777` = `544439`). Both must be evaluated and neither may appear in the baseline.
7. Blind SSTI: when the result is not returned in the same response, send the marker probe through all replayed requests and search responses for the computed value (see the blind section of the reference file).
8. Stop at proof of evaluation. Report the engine hint, the probe, the response evidence, and the affected endpoint.
9. Save evidence to `artifacts/<target>/ssti.json`.

## Classes

- `passive`: reading templates in source, JS, and error messages.
- `bounded`: arithmetic, syntax-break, and marker probes on your own test inputs.
- `authorized-only`: any evaluation beyond arithmetic, including execution, file reads, object traversal, and gadget chains. Requires written approval and an isolated lab.

## Rules

- Use your own accounts and your own content (own profile name, own draft template) whenever the feature is account-scoped.
- Do not send execution or file-read payloads to production, even when a public writeup shows them. Report the evaluated arithmetic and the engine, and propose the next step.
- If a feature sends email or notifications, test with your own addresses only.
- Redact any secret that appears in responses.
- Mitigation guidance for reports: use logic-less engines where possible, never let users author templates unless sandboxed, and run template rendering with least privilege or in a locked-down container.

## Sources

Primary references are PortSwigger's Web Security Academy (server-side template injection), CWE-1336, the PayloadsAllTheThings SSTI collection, the SSTImap project (detection mode), and the public HackerOne reports listed in the reference file.
