---
name: path-traversal
description: Audit authorized applications for path traversal, local/remote file inclusion and file-access flaws across 39 checks — ../ and ..\ sequences, URL / double / overlong-UTF-8 / Unicode / custom encodings, null-byte and extension bypasses, non-recursive stripping (....//), start-of-path validation, absolute paths, Windows drive/UNC/ADS/8.3 tricks, download / upload / image / PDF / template / log-viewer / config / backup / cloud-storage-key sinks, zip slip and symlink extraction, PHP wrappers (filter/data/zip/phar/expect), RFI and UNC hash leaks, LFI-to-RCE vectors (assessment only), Tomcat/Spring/Nginx-alias/Apache CVE-2021-41773/IIS server-level traversal, language path-join pitfalls, and safe impact mapping (/etc/passwd, /proc/self/*, win.ini, cloud/k8s secrets). Built on PortSwigger file-path-traversal and file-upload labs, OWASP WSTG-ATHZ-01 and INPV-11.1/11.2, PayloadsAllTheThings Directory Traversal & File Inclusion, and HackTricks.
---

# Path Traversal, LFI & File Access

Determine whether user input that names a file, path, template, key or archive entry can escape its intended directory (read/write arbitrary files) or be *included/executed* by the application (LFI/RFI). Start with read-only proof, escalate only within the execution class you are authorised for.

Primary methodology sources:

- PortSwigger Web Security Academy — *Path traversal* (labs: simple case, absolute path bypass, sequences stripped non-recursively, superfluous URL-decode, validation of start of path, file extension with null byte) and *File upload* (web shell upload via path traversal)
- OWASP WSTG v4.2 **WSTG-ATHZ-01** Testing Directory Traversal File Include, **WSTG-INPV-11.1** Local File Inclusion, **WSTG-INPV-11.2** Remote File Inclusion; OWASP *Path Traversal* attack page; File Upload and Input Validation cheat sheets
- PayloadsAllTheThings *Directory Traversal* and *File Inclusion*; HackTricks *File Inclusion / Path Traversal* and LFI2RCE pages; Snyk *Zip Slip*; Orange Tsai *Breaking Parser Logic*; Synacktiv PHP filter chains
- CWE-22, CWE-23, CWE-36, CWE-59, CWE-98

## Execution classes and safety boundary

Pass the scope gate before any request. Every check states the classes it may use:

| Class | Allowed actions | Requirement |
|---|---|---|
| **R** read-proof | Read a **benign, world-readable** file to prove traversal: `/etc/passwd` (first line only kept), `/etc/hostname`, `/etc/hosts`, `/proc/version`, `C:\Windows\win.ini`, or — preferred when possible — a known file of the application itself reached via traversal | Default for in-scope targets |
| **S** sensitive-read | Reading files that contain secrets: `/proc/self/environ`, `.env`, app config, cloud/k8s credentials, `/etc/shadow`, SSH keys | **Do not request** unless the program explicitly allows it. Infer impact instead (process UID from `/proc/self/status`, existence via error differential). If secrets are returned accidentally: stop, do not use them, redact evidence to key names only, report |
| **W** write | Upload/zip-slip/rename/save that writes outside the intended directory, log poisoning, session-file poisoning | Explicit permission, a unique canary filename (`bbtest_<rand>.txt`) with inert content, a location that cannot be executed or served to users, and a cleanup plan |
| **X** code execution | LFI/RFI that executes code (wrappers, log/session/upload inclusion, filter chains) | Explicit permission for RCE proof; payload limited to a harmless deterministic marker (`<?php echo 'bbtest'.(7*7); ?>` → `bbtest49`). **Never** web shells, reverse shells, `system()`/`passthru()`, `file_put_contents`, persistence, or lateral movement |

Without W/X permission, report the LFI/write primitive with R evidence and describe the escalation path (`INFO`/`FINDING` with `untested_class`), mark the RCE row `GATED`.

Other rules: rate ≤ 2 req/s; stop a payload family after the first confirmed hit (`traversal_probe.py` does this); never use third-party shell URLs from public notes — RFI markers are inert text files on infrastructure you control.

## Inputs

1. `artifacts/discovered_parameters.json`, `artifacts/discovered_endpoints.txt`, HARs — candidate parameters (`file`, `path`, `page`, `include`, `template`, `view`, `load`, `module`, `doc`, `lang`, `dir`, `folder`, `name`, `download`, `img`, `src`, `key`, `object`, `report`, `log`, `backup`, `theme`, `skin`, `locale`, `style`)
2. `artifacts/technology_profile.json` — OS, server (Nginx/Apache/IIS/Tomcat), language (PHP/Java/.NET/Node/Python/Ruby/Go); decides payload families
3. File features: download/view/preview/export, upload, image resize/thumbnail, PDF/report generation, theme/template/language loaders, log viewers, backup/restore, archive import
4. Wordlists: `wordlists/windows-lfi.txt`, `wordlists/reallysafe-not.txt`; [references/lfi_target_files.md](references/lfi_target_files.md)

## Workflow

1. **Map sinks.** For every candidate parameter/feature record: location (query, path segment, body, JSON, multipart filename, header, cookie), apparent behaviour (read/download, include/render, write/extract), and any visible prefix/suffix (`images/`, `.png`, `_en.php`). Write `artifacts/path_traversal/sink_map.md`.
2. **Baseline & safe confirmation.** Request the legitimate value, a non-existent value, and a traversal to a **known app file** (`../index.php`, `../static/app.js`, `..%2f` + legitimate filename). Response differences confirm traversal without touching system files (PT-38).
3. **Generate payloads** with `scripts/traversal_payloads.py` for the detected OS/stack and filters; **probe** with `scripts/traversal_probe.py` (class R signatures only by default).
4. **Run the 39-check ledger** in [references/checklist_39.md](references/checklist_39.md) with the subagent split.
5. **Assess impact** within your class: what can be read (R), what would be readable (S, inferred), whether writes/RCE are possible (W/X, gated).
6. **Report** artifacts and update `[ N / 39 ]`.

## Subagent split

| Subagent | Focus | Checks |
|---|---|---|
| **PT-A** Traversal Sequences & Encodings | `../`, `..\`, URL, double, overlong UTF-8/Unicode, `....//`, nested and custom encodings | 01, 02, 03, 04, 05, 17, 18, 25 |
| **PT-B** Validation Bypass & Platform Specifics | null byte / extension / start-of-path validation, absolute paths, Windows `..\Windows\` / drive / UNC / ADS / 8.3, Tomcat/Spring/Nginx/Apache/IIS, language path-join pitfalls, URL-path normalisation | 06, 07, 16, 26, 27, 31, 32, 33, 39 |
| **PT-C** Feature Sinks | download, upload destination, image processing, cloud storage keys, PDF generation, log viewers, config loading, backup download, non-parameter inputs, `file://` URL fetchers, write/rename/move targets | 08, 09, 10, 19, 20, 22, 23, 24, 34, 35, 36 |
| **PT-D** Inclusion & Archives | zip slip, symlinks, template file inclusion, PHP wrappers, RFI / UNC, LFI-to-RCE vectors (gated) | 14, 15, 21, 28, 29, 30 |
| **PT-E** Target Files & Impact | `/proc/self/environ`, `/etc/passwd`, `/etc/shadow` (gated/inferred), cloud & container secrets (gated), blind/differential confirmation | 11, 12, 13, 37, 38 |

## Status values

- `PASS` — applicable, payload families for the stack tested, no traversal/inclusion; evidence saved.
- `FINDING` — traversal/inclusion proven at the stated class; evidence saved and redacted.
- `INFO` — path disclosure, error differential without file read, or a primitive whose impact needs a gated class.
- `GATED` — escalation (S/W/X) not attempted for lack of permission; describe the expected impact.
- `NOT_APPLICABLE` — sink/feature/platform absent; evidence cited.
- `BLOCKED` — WAF, scope or tooling prevented testing.

## Severity guidance

| Condition | Typical severity |
|---|---|
| RCE via LFI/RFI/wrappers/zip slip (proved under class X/W) | Critical |
| Arbitrary file write outside intended directory (W), or read of secrets/credentials/source with secrets | Critical–High |
| Arbitrary file read of system/application files (R) | High |
| Read restricted to a subdirectory, or only existence oracle / path disclosure | Medium–Low |
| RFI fetch without execution (SSRF-like), UNC hash leak on Windows | Medium–High (context) |

## Helper scripts

```bash
S=.agents/skills/path-traversal/scripts

# Offline: payloads for a target file, OS and filter situation (TSV: family, payload)
python3 -I $S/traversal_payloads.py --os linux --file etc/passwd --depth 8 --prefix /var/www/images/ --suffix .png
python3 -I $S/traversal_payloads.py --os windows --file windows/win.ini --wrappers --rfi-host YOUR-COLLAB.oastify.com

# Scope-gated: probe one parameter (FUZZ marker in URL, --data or --header); class-R signatures only;
# stops each family on first hit; refuses sensitive targets (shadow, keys, credentials)
python3 -I $S/traversal_probe.py --target example.com --url 'https://app.example.com/download?file=FUZZ' \
  --os linux --delay 0.5 --out artifacts/path_traversal/probe_download.tsv

# Offline: build zip-slip / symlink test archives with inert canary content (upload only under class W)
python3 -I $S/zipslip_builder.py --out artifacts/path_traversal/archives --depth 6 --symlink-target /etc/hostname
```

On Windows Git Bash prefix commands that pass `/etc/...`-style arguments with `MSYS_NO_PATHCONV=1`.

Related tools: Burp Intruder with the grep-match `root:[^:]*:` / `\[fonts\]` and `wordlists/windows-lfi.txt`; `ffuf -mr 'root:[^:]*:'`; `dotdotpwn`; `lfifinder` (rix4uni); `php_filter_chain_generator` (Synacktiv; class X only).

## Required artifacts

- `artifacts/path_traversal/sink_map.md`
- `artifacts/path_traversal/probe_*.tsv`
- `artifacts/path_traversal/evidence/PT-XX_<short>.txt` (first matching line only; secrets redacted)
- `artifacts/path_traversal/path_traversal_checklist_39.tsv` — `check_id  status  class_performed  class_untested  severity  finding_id  evidence_path  notes`
- `artifacts/path_traversal_report.md` — findings, escalation paths, gated items, `[ N / 39 ]`

## Related skills

- `contentdiscovery` / `linkparamdiscovery` — parameters and file endpoints; `techfingerprint` — OS/server/language
- `server-config-audit` — server-level traversal CVEs and alias/IIS misconfiguration (shares PT-31/32)
- `ssrf-audit` — `file://` and RFI fetches (PT-29/35); `cloud-supplychain` — storage keys (PT-19)
- `authbypass` / `access-control` — `..;/` and path-normalisation access-control bypasses (PT-39)
- `idor` — file IDs vs file paths (ID-09)

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, uploads, archive submissions, inclusion tests, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- Classes S, W and X need explicit permission in addition to the scope gate; record it in the report.
- If the gate fails, stop the active steps and report the failure. Passive, offline, and read-only analysis of artifacts already collected may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise.

## Extended checklist (added)

- File: `references/lfi_extended.md` (LFI, RFI, wrappers, Windows variants, and archive traversal).
- Class policy: `passive` and `bounded` rows run in scope with the limits stated in the row. `authorized-only` rows need explicit approval for that check.
- Start automatically when `scripts/route_target.py` matches a parameter or technology listed in that file.
