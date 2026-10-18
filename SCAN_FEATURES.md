# SkillGuard: What It Scans

## At a glance

**SkillGuard checks local AI skills and agent files for 21 security indicators.**
It scans instructions, configurations, and supporting scripts without running them
or contacting the internet. No API key is needed.

The checks help reviewers **spot potential risks before enabling a skill**. A match
is a reason to investigate, not confirmation of a vulnerability or malicious intent.

## The 21 checks

### 1. Agent instructions and permissions

- **SG001 · HIGH — Instruction override:** Asks an agent to ignore or bypass
  higher-priority instructions or security rules.
- **SG002 · HIGH — Concealed activity:** Asks an agent to hide actions from the user
  or suppress audit logs or command history.
- **SG003 · HIGH — Permission bypass:** Requests skipped approvals, permission
  checks, or sandbox protections.
- **SG014 · HIGH — Unrestricted tools:** Declares wildcard access to agent tools
  or permissions, such as `Bash(*)`.

### 2. Credentials and secrets

- **SG004 · CRITICAL — Possible credential exfiltration:** Mentions transferring
  secrets or credentials to a network destination.
- **SG005 · MEDIUM — Sensitive file access:** References SSH keys, AWS credentials,
  Kubernetes config, shadow files, or reading `.env`.
- **SG011 · HIGH — Embedded access token:** Matches selected AWS, GitHub, or Slack
  token formats; a token-shaped match may not be a real credential.
- **SG012 · CRITICAL — Embedded private key:** Detects a private-key header in text.
- **SG016 · CRITICAL — Credential-file upload:** Finds `curl`/`wget` upload arguments
  referencing selected sensitive local files.

### 3. Code execution and unsafe APIs

- **SG006 · HIGH — Download-to-shell:** Finds `curl`/`wget` download commands piped
  directly into a shell. This is risky but not proof of a critical exploit.
- **SG010 · HIGH — Encoded execution:** Flags selected Base64-to-interpreter and
  encoded PowerShell command patterns.
- **SG015 · MEDIUM — JavaScript dynamic evaluation:** Finds `eval` or `new Function`
  in JavaScript/TypeScript files.
- **SG101 · MEDIUM — Python dynamic execution:** Finds `eval`, `exec`, or `compile`
  calls in Python files.
- **SG102 · MEDIUM — Python shell execution:** Finds selected shell APIs or
  subprocess calls with a `shell` argument that is not explicitly false.
- **SG103 · HIGH — Unsafe Python deserialization:** Finds selected pickle-like
  loaders or YAML loading without a recognized safe loader.

### 4. System and network settings

- **SG007 · HIGH — Destructive deletion:** Flags selected `rm` commands targeting
  the filesystem root or a home-directory path.
- **SG008 · HIGH — World-writable permissions:** Finds broad `chmod` settings,
  including `777` and `a+rwx`.
- **SG009 · MEDIUM — TLS verification disabled:** Finds selected insecure
  certificate-verification settings in code or commands, including combined curl
  flags such as `-fkL` and `--blackduck.trust.cert=true`.
- **SG013 · HIGH — Startup persistence:** Finds crontab, macOS launch-agent/daemon,
  or shell startup-file modification indicators.

### 5. Security scanner result handling

- **SG017 · HIGH — Scanner failure masked by logging:** Finds recognized security
  scanners piped to `tee` without visible `pipefail` or recognized explicit
  scanner-status propagation. `set -e` and a nonempty log are insufficient. High
  impact assumes the result is used as a required CI/release gate.
- **SG018 · MEDIUM — Detached validator status not propagated:** Finds recognized
  validation containers started detached and followed via logs without recognized
  propagation of the same container's exit code. `docker wait` alone is not enough.

**How to read severity:** CRITICAL indicates potential direct compromise; HIGH
signals a serious concern; MEDIUM is more context-dependent. LOW is reserved for
future use. Severity describes potential impact, **not certainty**. Quoted examples
and legitimate administration tasks can also produce matches.

## What can be scanned?

- **CLI:** One local file or folder; folders are scanned recursively.
- **Desktop app:** Files, folders, or a project whose conventional skill/agent
  locations are discovered by filename and folder layout. Multiple targets can
  be queued together.
- **Readable text:** Markdown, JSON, YAML, TOML, shell scripts, and other text
  files. Supports UTF-8 (including BOM) and BOM-marked UTF-16. Text checks also
  inspect comments and code examples.
- **Python-only checks:** SG101–SG103 analyze syntax in `.py` and `.pyw` files,
  including straightforward import aliases. Python snippets in Markdown get only
  the general text checks. SG015 applies only to JavaScript/TypeScript extensions.
- **Shell-gate checks:** SG017/SG018 analyze shell scripts, shell-shebang files,
  and fenced shell examples, including continued commands. Option state is local
  to each example, not shared across Markdown blocks.

### Reducing false positives

Markdown checks suppress narrowly recognized, directly negated prose actions,
such as instructions not to override safety rules or read credentials. Negation
does not exempt fenced code, embedded secrets, or a later unsafe instruction.
Markdown bold labels such as `**DevTools:**` are not wildcard permissions.
The argument-free shorthand `curl | bash` is not an executable-download finding.

## Scan settings and limits

**Default CLI limits** (configurable for each scan):

- `--max-file-bytes`: **1 MiB per file** (1,048,576 bytes).
- `--max-entries`: **10,000** filesystem entries.
- `--max-findings`: **10,000** findings.
- `--fail-on`: **HIGH** by default; accepts LOW, MEDIUM, HIGH, or CRITICAL.
  This changes the exit code, not which findings appear in the report.
- `--format`: `text` or `json`; `--output` writes to a **new** report file.
- `--no-default-excludes`: Includes directories otherwise skipped by default:
  `.git`, `.venv`, `venv`, `__pycache__`, and `node_modules`. The desktop app has
  a corresponding exclusion control.

**Desktop batch limits:** 128 selections, 256 scan targets, 50,000 total entries,
and 20,000 total findings. Project discovery has additional per-project limits.
Hitting a scan limit is reported as **incomplete coverage**, not a clean scan.

## What does a report show?

Each finding includes a rule ID, severity, confidence in the indicator match,
file and line location, explanation, and recommended action. Reports include
counts, skipped-file issues, exclusions, and a **complete/incomplete** status.
The desktop app groups findings by target, filters by severity, and exports JSON.
Reports omit source snippets, but paths can still be sensitive.

**CLI exit codes:** `0` = completed below the configured threshold;
`1` = completed with a finding at or above it; `2` = incomplete scan,
invalid arguments, or report-write error. A `0` does **not** mean safe.

## Quick demonstration

Run these from the project directory:

```sh
python3 main.py rules
python3 main.py scan examples/review-required
python3 main.py gui
```

The bundled example is an inert demonstration fixture. For a real review, stage
the skill separately and scan the **entire bundle**, including helper scripts,
before enabling it.

## Important limitations

- This is **static, heuristic screening**, not a safety certification. Checks
  may miss obfuscated, indirect, runtime-generated, or non-English behavior;
  Python checks do not perform full data-flow analysis.
- Prose context is not full intent analysis. Shell checks recognize selected tools
  and common local status-handling patterns, not full shell control flow. Functions,
  heredocs, sourced options, wrappers, or custom handling can produce missed or
  misleading findings. Container follow-up is bounded to 256 commands. Recognized
  `pipefail` does not certify downstream enforcement; review CI behavior as well.
- SkillGuard does **not** run code, fetch URLs, unpack archives, audit dependency
  CVEs, verify signatures, scan malicious binaries, or monitor runtime behavior.
- Symlinks, inaccessible or oversized files, unsupported encodings, and Python
  syntax failures are reported as coverage issues. Excluded directories remain
  outside scan coverage.

**Source of truth:** `skillguard/rules.py` contains the rules;
`skillguard/scanner.py` applies them; `skillguard/context.py` handles prose context
and shell-gate patterns; `skillguard/cli.py` defines CLI options.
See `README.md` for the full workflow and caveats.
