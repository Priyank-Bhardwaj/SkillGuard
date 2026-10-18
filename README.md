# SkillGuard

An **offline, read-only Python scanner** for downloaded or locally created AI
skills and agents. Point it at a skill bundle, `SKILL.md`, `AGENTS.md`, agent
configuration, or scripts. It recursively inspects text without importing or
executing scanned code. No LLM, API key, network requests, or third-party Python
packages are needed. The optional desktop UI requires Python's Tkinter/Tk support.

**Requires Python 3.10 or newer.** This is a heuristic security triage tool, not an
antivirus, sandbox, vulnerability database, or certification that a skill is safe.

## Desktop UI: files, folders, or whole-project discovery

Launch from this project:

```sh
cd /Users/gymbdvj/PycharmProjects/SkillGuard
python3 main.py gui
```

You can also use `python3 -m skillguard gui` or, after installing the package,
`skillguard-ui`. In PyCharm, run `main.py` with **Parameters: `gui`** and this
project as the working directory.

### Modern review workspace

The desktop UI uses a consistent dark theme with high-contrast text, violet
actions, and severity colors. No additional Python dependencies are required.

- **Left sidebar:** all three scan modes, the multi-source queue, exclusion
  settings, and the primary scan button.
- **Summary cards:** targets scanned, targets with findings (**Need review**),
  total findings, and files inspected. Counts describe the last scan, not filters.
- **Review center:** a targets table above a side-by-side findings list and
  inspection panel. Drag the dividers to give tables or explanations more space;
  scroll tables horizontally to inspect long paths.
- **Readable details:** highlighted severity badges, section headings, and
  muted file metadata separate the risk explanation from recommended actions.
- **Explicit states:** ready, scanning, incomplete, cancelled, no text scanned,
  and review required are labeled, not communicated by color alone.

Existing windows do not reload automatically after an update. Launch a new window
with the command above to use the redesigned interface.

### Three ways to scan

1. **Browse files…** opens a native file picker. Select one or many skill/agent
   definitions, Markdown instructions, configurations, or scripts. On macOS use
   Command-click to select multiple files.
2. **Add skill / agent folder…** selects a bundle or any folder and recursively
   scans its files, subject to exclusions and size limits. This is best for custom
   layouts and for checking helper scripts along with a definition.
3. **Discover in project…** selects a project root, automatically discovers
   conventional skill/agent locations, then scans each discovered item separately.

You may combine all three modes and add multiple projects/folders to the queue.
Use **Remove selected** or **Clear**, then press **Scan queued items**.
Overlapping targets are merged: an explicitly selected outer folder takes
precedence over separately discovered files inside it and appears as one result.
For separate per-skill results, select the project in discovery mode only.

### Reading results

- Each target has a row with **review status, highest severity, finding count,
  type, and full path**. Targets with findings are listed ahead of unflagged ones.
- Select a target, then a finding to see the **risk explanation**, **file/line
  location**, and **what to fix or when to reject/remove the skill**.
- **Only targets with findings** narrows the target list; the severity dropdown
  filters the selected target's findings. Neither changes the scan or export.
- **Coverage & discovery** lists project discovery counts, excluded directories,
  and skipped/inaccessible files. **INCOMPLETE** is not a clean result.
- **No indicators** means no configured rule matched, not that the skill is safe.
  **No text scanned** means the target had no analyzed text. A project with no
  recognizable definitions explicitly says no candidates were found; custom
  layouts still need a manual file/folder scan.
- **Cancel scan** retains partial results and marks the batch incomplete. Cancellation
  is checked between filesystem entries; the current bounded file analysis may
  finish first. Closing the window also requests cancellation.
- **Export JSON…** writes all grouped results, including filtered-out findings,
  to a **new** filename. Source snippets are omitted; paths can still be sensitive.

Scans run in a background thread; the UI never executes or renders scanned
instructions as code/HTML. It does not automatically delete or quarantine skills.

### What project discovery recognizes

Recognition is case-insensitive for definition names:

- `SKILL.md` anywhere identifies its **containing bundle**, including helper files.
- Direct child directories of `skills/` and `agents/` are candidate bundles,
  including `.agents/skills`, `.claude/skills`, and `.github/agents` layouts.
- Definition files directly inside `skills/` or `agents/` with `.md`, `.mdc`,
  `.json`, `.yaml`, `.yml`, `.toml`, or `.txt` extensions.
- `AGENTS.md`, `agent.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`,
  `copilot-instructions.md`, `.cursorrules`, and `.windsurfrules`.
- Standalone `agent`/`skill` definitions ending in `.json`, `.yaml`, `.yml`, or
  `.toml`; `mcp.json`, `.mcp.json`, and `.claude/settings*.json` (specifically
  `settings.json` and `settings.local.json`).
- Files ending in `.agent.md`, `.instructions.md`, or `.prompt.md`.
- Definitions in `.cursor/rules`, `.windsurf/rules`, `.github/prompts`,
  `.github/instructions`, and `.claude/commands`.

Discovery is **filename/folder-based**, not a semantic inventory of every possible
agent framework. An unrelated folder named `skills` may also be selected. Scripts
outside discovered bundles, or merely referenced by standalone instructions, are
not automatically followed. Use folder mode for those custom layouts. Symlinks
are skipped and reported; remote references and archives are not fetched/opened.

The UI defaults to excluding `.git`, `.venv`, `venv`, `__pycache__`, and
`node_modules`. Uncheck **Exclude dependencies / caches** before scanning to include
those directories. A batch allows up to **128 selections**, **256 scan targets**,
**50,000 total filesystem entries** across discovery and scanning, and **20,000
total findings**. Per-project discovery is limited to 20,000 entries and 256
candidate matches (before deduplication); ordinary per-target scan limits below
still apply. Limits are reported as incomplete coverage. Split very large scans
into smaller selections or use the CLI for larger per-target limits.

To keep the window responsive, it displays up to **500 matching findings for the
selected target** and **500 coverage issues**. The counts and JSON export include
all collected results. GUI exports use `report_type: skillguard-batch`, with a
`summary`, `units` (each containing a normal scanner report), `discoveries`, and
batch `issues`; CLI single-target JSON retains its existing format.

### Tkinter setup / troubleshooting

Check support in the same Python interpreter used to run the project:

```sh
python3 -c 'import tkinter; print(tkinter.TkVersion)'
```

If Homebrew Python 3.14 reports missing `_tkinter`:

```sh
brew install python-tk@3.14
```

Match the package to your Python minor version. Homebrew may update Python and
supporting dependencies; restart PyCharm or reselect its interpreter if needed.
On Debian/Ubuntu, install `python3-tk` for the relevant system interpreter. A
graphical desktop session is required. The CLI continues to work without Tk.

## Start scanning (macOS / Linux)

Open a terminal in this project:

```sh
cd /Users/gymbdvj/PycharmProjects/SkillGuard
python3 main.py --help
```

**Scan a downloaded skill before installing or enabling it:**

```sh
python3 main.py scan "$HOME/Downloads/my-skill"
```

Replace `my-skill` with the actual folder name. Scan the **whole bundle**, not just
the Markdown file: supporting scripts and configuration may contain the risk.

**Scan skills or agents already on this machine:**

```sh
python3 main.py scan "$HOME/.agents/skills"
python3 main.py scan "/absolute/path/to/your/project/AGENTS.md"
python3 main.py scan "/absolute/path/to/your/project/.claude/agents"
```

Paths depend on your agent application; a missing path is reported as incomplete,
not as a clean scan. The scanner does not automatically search your entire home
directory or enable/install anything.

**Try the included inert example:**

```sh
python3 main.py scan examples/review-required
```

Expect HIGH and CRITICAL findings and exit code `1`. The fixture is intentionally
not a usable skill. Its findings illustrate why quoted examples need human review.

**Save a machine-readable report:**

```sh
python3 main.py scan "$HOME/Downloads/my-skill" --format json --output "$HOME/skillguard-report.json"
```

Choose a **new** output filename each time. Existing files and symlinks will not be
overwritten. Keep reports outside the scanned bundle, otherwise previous reports
may be scanned as input on subsequent runs. Reports omit source snippets and token
values from source content, but **filenames/paths are included** and may themselves
contain sensitive information. Share reports carefully.

**List rules or adjust the CI failure threshold:**

```sh
python3 main.py rules
python3 main.py scan "$HOME/Downloads/my-skill" --fail-on MEDIUM
```

All severities remain visible regardless of `--fail-on`. Default threshold: HIGH.

## What a finding contains

- **Rule ID and title**, e.g. `SG004: Possible credential exfiltration`.
- **Severity**: potential impact if the detected behavior is real and reachable.
- **Match confidence**: confidence in the indicator match, not proof of exploitation.
- **File and line range** for local inspection, without printing hostile source text.
- **Why risky**: how the behavior could compromise the machine or the agent.
- **What to do / when to remove**: verification, remediation, and rejection guidance.

### How to decide whether the skill should remain installed

| Severity | Meaning and suggested response |
| --- | --- |
| CRITICAL | Potential direct compromise, such as credential transfer or exposed private keys. Keep disabled/quarantined until reviewed; reject unauthorized behavior. |
| HIGH | Serious trust-boundary, persistence, permission, download-to-shell, or security-gate concerns. Do not enable before reviewing and fixing the finding. |
| MEDIUM | Context-dependent risk such as shell use or dynamic evaluation. Trace inputs and verify necessity and constraints. |
| LOW | Reserved for future informational/low-impact rules; currently no rules emit LOW. |

A match **does not automatically mean “delete this skill.”** Documentation may
describe an attack defensively; a legitimate administration skill may need shell
access. Remove/reject a skill when the behavior is unauthorized, unrelated to its
purpose, concealed, or cannot be adequately constrained. The scanner intentionally
does not execute, fix, delete, quarantine, or disable files itself.

If an untrusted skill has already run, a source scan cannot undo its effects.
Disable it, review tool/audit logs and persistence, and rotate credentials that
may have been exposed. Escalate suspected compromise through your incident process.

## Detection coverage

The **21 rules** cover:

- Instruction-hierarchy overrides and concealed actions/audit suppression.
- Approval/sandbox bypasses and wildcard tool permissions.
- Credential transfer instructions and curl/wget credential-file uploads.
- Sensitive credential-store references and selected token/private-key formats.
- Download-to-shell commands, broad deletion, and world-writable permissions.
- Disabled TLS verification, encoded execution, and startup persistence indicators.
- JavaScript/TypeScript `eval` and `new Function` indicators.
- Python AST checks for dynamic evaluation, shell invocation, and unsafe
  deserialization. Straightforward import aliases are recognized. Safe YAML
  loaders and `shell=False` argument-list calls are not flagged by those AST rules.
- **SG017 (HIGH):** Recognized security scanners piped to `tee` without visible
  `pipefail` or recognized explicit scanner-status propagation. `set -e` and a
  nonempty log alone do not establish successful scanning. Impact is high when
  downstream CI relies on the script as a required security gate.
- **SG018 (MEDIUM):** Recognized detached validation containers whose logs are
  collected without recognized propagation of that container's exit status.
  Merely calling `docker wait` is insufficient: its printed result must be checked.

General text rules inspect Markdown, JSON, YAML, shell, and other readable files;
no specific filename is required. Comments and code blocks are also inspected.
Python AST checks run only on `.py`/`.pyw` files; Python snippets inside Markdown
receive text checks only. Configuration is inspected as text, not schema-validated.

### Context and false-positive handling

Markdown checks distinguish narrowly recognized defensive prohibitions from
operative instructions. For example, instructions **not** to override safety
rules or read `.env` are not themselves reported as those actions. A prohibition
does not exempt later sentences, list items, fenced code, or embedded secret
literals. Markdown emphasis such as `**DevTools:**` is not wildcard configuration.
The shorthand `curl | bash` without a download argument is not treated as an
executable download. Actual download-to-shell commands remain HIGH findings;
the pattern alone does not establish a critical vulnerability.

SG017/SG018 inspect shell files, shell-shebang files, and fenced shell examples,
including continued command lines. Each fenced example has independent option
state. Recognized tools include Detect, Trivy, Semgrep, Grype, Bandit, pip-audit,
Checkov, Gitleaks, SonarScanner, package-manager audit commands, and PlausiCheck.
TLS checks also recognize combined curl options such as `-fkL` and Black Duck's
explicit certificate-trust override; those indicators remain context-dependent.

## Coverage limits and safe workflow

1. Obtain an untrusted bundle in a **separate staging directory**. Do not invoke
   its installer, helpers, package lifecycle scripts, or agent instructions.
2. Scan it, review findings and every coverage issue, and inspect its provenance,
   requested permissions, network destinations, and supporting files.
3. If a bundle is archived, inspect/extract it with a trusted archive utility in
   an isolated staging environment. Guard against traversal paths, symlinks, and
   archive bombs. SkillGuard does **not** extract archives or fetch URLs.
4. Fix/reject unauthorized behavior and rescan. If testing remains necessary, use
   a disposable isolated environment with no real secrets and minimal permissions.

Defaults:

- Maximum **1 MiB per file**, **10,000 filesystem entries**, **10,000 findings**,
  and 100 traversal frames. Reaching a limit produces an incomplete scan.
- UTF-8 (including BOM) and BOM-marked UTF-16 are supported.
- Unreadable files, binary/unsupported encodings, symlinks, special files, and
  Python parsing failures produce coverage issues. Remaining files are still
  scanned where possible. Symlink targets must be inspected separately.
- `.git`, `.venv`, `venv`, `__pycache__`, and `node_modules` directories are excluded
  by default and explicitly listed in reports. “Complete” means complete **within
  configured scope**, not that excluded dependencies were audited.

For broader coverage:

```sh
python3 main.py scan "$HOME/Downloads/my-skill" --no-default-excludes --max-file-bytes 4194304 --max-entries 50000
```

The scanner does not follow encountered symlink entries. It is **not a filesystem
sandbox**: ancestor path symlinks can resolve normally, and concurrent directory
replacement is not prevented. Scan a stable staging copy, not a tree being modified
by an adversarial process. Resource limits reduce risk, but do not make parsing
arbitrary hostile files a hardened sandbox; use OS-level isolation where needed.

### Known blind spots

Detection is mainly English, pattern-based, and bounded-context. It can miss
obfuscation, indirect network transfers, split commands, runtime-generated code,
non-English injection, new secret formats, and malicious binaries. Python checks
are not full data-flow or scope analysis: alias rebinding and wrapper functions
may cause missed or misleading matches. It does not resolve external URLs, audit
dependency CVEs, verify signatures, or monitor runtime behavior. Use dedicated
dependency auditing and secret scanning alongside it. **No findings is not proof
of safety**, even when exit code is zero.

Context recognition is conservative and English-only, not a general intent
classifier. Defensive examples may still need review. Shell checks are not a
complete parser or control-flow analysis: wrappers, functions, heredocs, sourced
options, unrecognized tools, and custom status handling can cause missed or
misleading findings. Container follow-up inspection is bounded to 256 commands,
and recognized status checks are local. A recognized `pipefail` setting suppresses
SG017, but does not certify that later commands or CI correctly enforce the result.

## CLI scan exit codes / automation

| Code | Meaning |
| --- | --- |
| `0` | Scan completed within configured scope; no finding reached `--fail-on`. Lower-severity findings can still exist. |
| `1` | Scan completed; at least one finding reached the failure threshold. |
| `2` | Incomplete scan, invalid arguments, or report-writing error. Takes precedence over `1`. |

JSON includes `schema_version`, `target`, `files_scanned`, `entries_examined`,
`complete`, `severity_counts`, `findings`, `issues`, and exclusions. Treat both
`1` and `2` as blocking in CI, and review excluded directories separately.
The GUI command returns after the window closes; its exit status is not a scan
verdict. Use the UI's coverage/status fields or exported report for batch results.

## Optional installation and development

Direct invocation needs no installation. Alternatively, from the project folder:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
skillguard scan "$HOME/Downloads/my-skill"
```

Installation may fetch the setuptools build dependency; scanning itself is offline.
`python3 -m skillguard scan PATH` also works from this folder or after installation.

Run tests (no third-party test runner needed):

```sh
python3 -m unittest discover -s tests -v
```

Tests cover scanning, project discovery, grouped reports, cancellation, workers,
and native UI controls. Native widget tests are skipped if Tk or a graphical
desktop is unavailable; the remaining tests still run.

Project layout:

```text
main.py                 Direct CLI entry point
skillguard/cli.py        Arguments, text/JSON reports, exit codes
skillguard/scanner.py    Bounded traversal and Python AST checks
skillguard/context.py    Markdown context and shell security-gate heuristics
skillguard/rules.py      Rule catalog, severity, explanations, recommendations
skillguard/discovery.py  Convention-based project skill/agent discovery
skillguard/batch.py      Multi-target scans, grouped reports, cancellation, export
skillguard/gui.py        Native Tkinter interface and background worker
tests/test_skillguard.py Regression tests with inert fixtures
tests/test_context.py    Defensive-prose and shell-gate regression tests
tests/test_discovery_batch.py  Discovery and batch regression tests
tests/test_gui.py        Worker and native desktop tests
examples/               Demonstration content (not skills to install)
```

To add a text rule, extend `RULES` in `skillguard/rules.py` with a unique ID,
bounded regex, severity, explanation, and recommendation; add a fixture in the
rule-coverage test. Prefer specific indicators over broad keywords to reduce
false positives. Do not execute fixture content.
