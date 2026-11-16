# OS Command Injection Checklist

Class key: `passive` = source, headers, error text. `bounded` = echo, arithmetic, and encoding probes on your own input, up to 40 requests per parameter. `authorized-only` = anything beyond echo and arithmetic, timing included unless approved.

## Separators and operators (unix)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CMDI-SEP-001 | Unix shell | Semicolon chaining (`; cmd`) executes after the first command | bounded | `cmdi_probe.py` split-marker echo |
| CMDI-SEP-002 | Unix shell | Pipe (`| cmd`) executes | bounded | Split-marker echo |
| CMDI-SEP-003 | Unix shell | AND (`&& cmd`) executes when the first command succeeds | bounded | Split-marker echo |
| CMDI-SEP-004 | Unix shell | OR (`|| cmd`) executes when the first command fails | bounded | Use an input that makes the first command fail; split-marker echo |
| CMDI-SEP-005 | Unix shell | Background `& cmd` executes (output may not return) | bounded | Split-marker echo; check for a result on a second request |
| CMDI-SEP-006 | Unix shell | Newline (`%0a` or `\n`) separates commands | bounded | Split-marker echo with `%0a` |
| CMDI-SEP-007 | Unix shell | Commands run when both operands are evaluated (`;` vs `&&` with output) | bounded | Compare output for both forms |

## Substitution and context

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CMDI-SUB-001 | Unix shell | Backticks (`` `cmd` ``) substitution | bounded | Split-marker echo in backticks |
| CMDI-SUB-002 | Unix shell | `$(cmd)` substitution | bounded | Split-marker echo in `$()` |
| CMDI-SUB-003 | Unix shell | Arithmetic evaluated by the shell (`$((7*7))` = 49) | bounded | `;echo $((7*7))` |
| CMDI-CTX-001 | Unix shell | Single-quoted argument: break with `'` before the command | bounded | `';echo <split>;'` |
| CMDI-CTX-002 | Unix shell | Double-quoted argument: break with `"` before the command | bounded | `";echo <split>;"` |
| CMDI-CTX-003 | Unix shell | Input inside a shell here-string or heredoc | passive | Review the wrapper script |
| CMDI-CTX-004 | Windows cmd | Ampersand (`& cmd`) and pipe (`| cmd`) chaining | bounded | `& echo <split>` (use arithmetic `set /a 7*7` for evaluation evidence) |
| CMDI-CTX-005 | Windows cmd | Arithmetic evaluation (`set /a 7*7` = 49) | bounded | Arithmetic probe |
| CMDI-CTX-006 | Windows PowerShell | `;` and `$()` injection in PowerShell argument | bounded | `; Write-Output <split>` with approval; otherwise passive review |

## Encoding and filter bypass (benign markers only)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CMDI-ENC-001 | Unix shell | IFS whitespace substitution (`${IFS}` replaces a space) | bounded | `;echo${IFS}<split>` |
| CMDI-ENC-002 | Unix shell | Brace expansion as command (`{echo,<split>}`) works only in bash | bounded | Compare bash and sh behaviour |
| CMDI-ENC-003 | Unix shell | Quote splitting (`cm''d`, `c"m"d`, `c\md`) defeats keyword blocklists | bounded | Split-marker probes |
| CMDI-ENC-004 | Unix shell | Glob paths (`/???/???/??`) avoid literal command names | bounded | Benign glob resolving to `echo` only |
| CMDI-ENC-005 | Unix shell | Hex or octal character encoding in `$'...'` and `echo -e` | bounded | Encode the marker, not the command name |
| CMDI-ENC-006 | Unix shell | URL-encoded and double-encoded separators (`%3B`, `%253B`, `%0a`) | bounded | Encoded separator variants |
| CMDI-ENC-007 | Unix shell | Unicode normalization of separators or letters | bounded | Full-width or compatibility characters |
| CMDI-ENC-008 | Generic | Keyword blocklist keyed on `cat`, `id`, `whoami` only | bounded | Split-marker echo to confirm bypass without executing sensitive commands |
| CMDI-ENC-009 | Generic | WAF rule on separators only; newline or `%0a` gets through | bounded | Split-marker echo with `%0a` |

## Blind detection

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CMDI-BLD-001 | Time delay | `;sleep N`, `|sleep N`, `&&sleep N` causes a response delay | authorized-only | `cmdi_probe.py --allow-timing --sleep 5`; repeat and compare with a control |
| CMDI-BLD-002 | Time delay | Delay tracks sleep value (5 vs 1 second) | authorized-only | Two sleep values; check proportional delay |
| CMDI-BLD-003 | Output redirection | Command output written to a file served by the app | authorized-only | Requires approval and a file the test owns; not part of this skill's default run |
| CMDI-BLD-004 | Out-of-band DNS | `nslookup <split-or-token>.<your-oob-host>` produces a DNS hit | bounded | Single lookup to your own host; record timestamp |
| CMDI-BLD-005 | Out-of-band HTTP | `curl` or `wget` to your own host produces an HTTP hit | bounded | Single request to your own host |
| CMDI-BLD-006 | Out-of-band data | Exfiltration of command output through DNS labels | authorized-only | Requires approval; never exfiltrate real data |

## Parameter names and features

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CMDI-PAR-001 | Parameters | cmd, exec, command, execute, ping, query, jump, code, reg, do, func, arg, option, load, process, step, read, function, req, feature, exe, module, payload, run, print | bounded | Route with `route_target.py --params`, probe each |
| CMDI-FEAT-001 | Ping and traceroute | Host field passed to ping or traceroute | bounded | Split-marker probe in host field |
| CMDI-FEAT-002 | DNS lookup | Domain field passed to nslookup or dig | bounded | Split-marker probe |
| CMDI-FEAT-003 | File upload filename | Filename passed to a shell (convert, unzip, tar) | bounded | Benign filename with split marker (no executable content) |
| CMDI-FEAT-004 | Image processing | ImageMagick, GraphicsMagick, or Ghostscript arguments built from user input | bounded | Version check first; then benign argument probe |
| CMDI-FEAT-005 | PDF generation | wkhtmltopdf or similar invoked with user URL or option | bounded | Own document with marker |
| CMDI-FEAT-006 | Backup and restore | Backup name or path concatenated into tar or mysqldump command | bounded | Own backup name with split marker |
| CMDI-FEAT-007 | Cron job parameters | User-set schedule or command field stored and later executed | bounded | Own job with marker; check output after the next run |
| CMDI-FEAT-008 | Email headers | Subject or recipient passed to sendmail or mail command | bounded | Own address and benign split marker |
| CMDI-FEAT-009 | Log processing | Log line values passed to awk, grep, or sed in a script | bounded | Own log entry with split marker |
| CMDI-FEAT-010 | Archive extraction | Archive member names passed to unzip or tar | bounded | Benign member name with split marker |
| CMDI-FEAT-011 | Binary name | Path or binary name taken from input and executed | bounded | Own input with split marker |
| CMDI-FEAT-012 | Environment | User-controlled environment variables passed to a child process | passive | Review code that sets env for child processes |

## Source sinks (passive, `scripts/sink_scan.py`)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CMDI-SRC-001 | Python | `subprocess` with `shell=True`, `os.system`, `os.popen`, `os.spawn*`, `os.exec*` | passive | `sink_scan.py` high findings first |
| CMDI-SRC-002 | Python | `subprocess.getoutput` and `getstatusoutput` | passive | Review arguments |
| CMDI-SRC-003 | Node.js | `child_process.exec`, `execSync`, `spawn` with `shell: true` | passive | `sink_scan.py` |
| CMDI-SRC-004 | Node.js | `shelljs.exec`, `execa` templates with interpolation | passive | Review tagged templates |
| CMDI-SRC-005 | Java | `Runtime.exec`, `ProcessBuilder` with a single string | passive | Review argument form |
| CMDI-SRC-006 | Java | Script engines (`ScriptEngine.eval`, `GroovyShell`) on user data | passive | Review; a common RCE class |
| CMDI-SRC-007 | Ruby | Backticks, `%x`, `system`, `exec`, `spawn`, `IO.popen`, `Open3` | passive | `sink_scan.py` |
| CMDI-SRC-008 | Ruby | `open("| cmd")`, `IO.read("| cmd")` pipe forms | passive | Review for pipe-prefixed strings |
| CMDI-SRC-009 | PHP | `shell_exec`, `exec`, `system`, `passthru`, `popen`, `proc_open`, backticks | passive | `sink_scan.py` |
| CMDI-SRC-010 | Go | `exec.Command` with `bash -c` and string arguments | passive | Review arguments |
| CMDI-SRC-011 | .NET | `Process.Start` with `UseShellExecute` or `cmd /c` | passive | Review |
| CMDI-SRC-012 | Shell scripts | Unquoted `$var` in command arguments, `eval` | passive | Review shell scripts in scope |

## Environment-variable and interpreter tricks (authorized-only, research reference)

These techniques matter when a user controls environment variables or interpreter options. They are not run by this skill. Report them as a class with the review findings, and test only in an approved lab.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CMDI-ENV-001 | Bash | BASH_ENV or BASH_FUNC_* controls startup code | authorized-only | Code review: check whether env is user-controlled |
| CMDI-ENV-002 | dash and sh | ENV variable read in interactive mode | authorized-only | Code review only |
| CMDI-ENV-003 | Git | GIT_DIR, GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF, GIT_CONFIG_* settable by users | authorized-only | Review env passed to git |
| CMDI-ENV-004 | Linux loader | LD_PRELOAD loads attacker shared object | authorized-only | Review env passed to child processes |
| CMDI-ENV-005 | Perl | PERL5OPT, PERL5DB, PERLLIB, PERL5LIB | authorized-only | Review env passed to perl |
| CMDI-ENV-006 | Python | PYTHONWARNINGS and PYTHONPATH influence imports | authorized-only | Review env passed to python |
| CMDI-ENV-007 | Node.js | NODE_OPTIONS `--require` | authorized-only | Review env passed to node |
| CMDI-ENV-008 | Ruby | RUBYOPT `-r` | authorized-only | Review env passed to ruby |
| CMDI-ENV-009 | System | /etc/environment read by cron jobs | authorized-only | Review cron and environment handling |

## Reporting

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CMDI-RPT-001 | Evidence | Request, response excerpt, split-marker or arithmetic output, timing table if used | passive | Include in the report |
| CMDI-RPT-002 | Fix | Use argument arrays with no shell, allowlist inputs, avoid string concatenation into commands | passive | Recommendation |
| CMDI-RPT-003 | Fix | Use language APIs for the job (DNS library instead of nslookup, image library instead of convert) | passive | Recommendation |
| CMDI-RPT-004 | Fix | Run child processes with least privilege and a clean environment | passive | Recommendation |
