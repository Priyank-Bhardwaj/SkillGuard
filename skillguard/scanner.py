"""Read-only, bounded inspection of local skill and agent files."""

import ast
from bisect import bisect_right
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
import stat

from .context import MARKDOWN_SUFFIXES, defensive_reference, fenced_blocks, shell_matches
from .rules import PYTHON_RULES, RULES, SEVERITIES, Rule


DEFAULT_EXCLUDES = frozenset({".git", ".venv", "venv", "__pycache__", "node_modules"})
COMPILED_RULES = tuple((rule, rule.compile()) for rule in RULES)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    category: str
    file: str
    line: int
    end_line: int
    explanation: str
    recommendation: str


@dataclass
class ScanIssue:
    path: str
    reason: str


@dataclass
class Report:
    target: str
    files_scanned: int = 0
    entries_examined: int = 0
    findings: list[Finding] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    excluded_directories: int = 0
    default_exclusions: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            **asdict(self),
            "complete": self.complete,
            "severity_counts": {
                severity: sum(f.severity == severity for f in self.findings)
                for severity in reversed(SEVERITIES)
            },
            "notice": "Heuristic static analysis, not a safety certification. No source "
                      "snippets are included. Excluded directories are outside scan coverage.",
        }


def _finding(rule: Rule, path: str, line: int, end_line: int) -> Finding:
    return Finding(
        rule.id, rule.title, rule.severity, rule.confidence, rule.category,
        path, line, end_line, rule.explanation, rule.recommendation,
    )


def _python_matches(text: str):
    tree = ast.parse(text)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        return ""

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = name(node.func)
        rule_id = None
        if function in {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}:
            rule_id = "SG101"
        elif function in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}:
            rule_id = "SG102"
        elif function in {"subprocess.run", "subprocess.call", "subprocess.check_call",
                          "subprocess.check_output", "subprocess.Popen"}:
            if any(kw.arg == "shell" and not (
                isinstance(kw.value, ast.Constant) and kw.value.value in (False, None, 0)
            ) for kw in node.keywords):
                rule_id = "SG102"
        elif function in {"pickle.load", "pickle.loads", "dill.load", "dill.loads",
                          "cloudpickle.load", "cloudpickle.loads", "joblib.load",
                          "yaml.unsafe_load", "yaml.unsafe_load_all"}:
            rule_id = "SG103"
        elif function in {"yaml.load", "yaml.load_all"}:
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"),
                          node.args[1] if len(node.args) > 1 else None)
            if name(loader) not in {"yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader", "yaml.CBaseLoader"}:
                rule_id = "SG103"
        if rule_id:
            yield PYTHON_RULES[rule_id], node.lineno, node.end_lineno or node.lineno


class Scanner:
    def __init__(self, *, max_file_bytes: int = 1_048_576, max_entries: int = 10_000,
                 max_findings: int = 10_000, use_default_excludes: bool = True):
        if min(max_file_bytes, max_entries, max_findings) < 1:
            raise ValueError("Scan limits must be positive")
        self.max_file_bytes = max_file_bytes
        self.max_entries = max_entries
        self.max_findings = max_findings
        self.excludes = DEFAULT_EXCLUDES if use_default_excludes else frozenset()

    def scan(self, target: str | Path, *, cancelled: Callable[[], bool] | None = None) -> Report:
        # abspath normalizes without resolving the target symlink.
        root = Path(os.path.abspath(os.path.expanduser(str(target))))
        report = Report(str(root), default_exclusions=sorted(self.excludes))
        # Iterator frames bound traversal memory even in directories with many entries.
        frames: list[Iterator[Path | os.DirEntry[str]]] = [iter([root])]
        try:
            while frames:
                if cancelled and cancelled():
                    report.issues.append(ScanIssue(str(root), "Scan cancelled; remaining paths were not scanned"))
                    break
                try:
                    path = next(frames[-1])
                except StopIteration:
                    frame = frames.pop()
                    if hasattr(frame, "close"):
                        frame.close()
                    continue
                except OSError:
                    report.issues.append(ScanIssue(str(root), "Directory enumeration failed"))
                    frame = frames.pop()
                    if hasattr(frame, "close"):
                        frame.close()
                    continue

                path = Path(path.path) if isinstance(path, os.DirEntry) else path
                if report.entries_examined >= self.max_entries:
                    report.issues.append(ScanIssue(str(root), "Entry limit reached; remaining paths were not scanned"))
                    break
                report.entries_examined += 1
                try:
                    mode = path.lstat().st_mode
                    if stat.S_ISLNK(mode):
                        report.issues.append(ScanIssue(str(path), "Symlink skipped; inspect its target separately"))
                    elif stat.S_ISDIR(mode):
                        if path != root and path.name in self.excludes:
                            report.excluded_directories += 1
                        elif len(frames) >= 100:
                            report.issues.append(ScanIssue(str(path), "Directory depth limit reached"))
                        else:
                            frames.append(os.scandir(path))
                    elif stat.S_ISREG(mode):
                        self._scan_file(path, report)
                    else:
                        report.issues.append(ScanIssue(str(path), "Special file skipped"))
                except OSError:
                    report.issues.append(ScanIssue(str(path), "Path cannot be accessed or safely read"))
                if len(report.findings) >= self.max_findings:
                    report.issues.append(ScanIssue(str(root), "Finding limit reached; scan stopped"))
                    break
        finally:
            for frame in frames:
                if hasattr(frame, "close"):
                    frame.close()
        report.findings.sort(key=lambda f: (-SEVERITIES[f.severity], f.file, f.line, f.rule_id))
        return report

    def _scan_file(self, path: Path, report: Report) -> None:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                report.issues.append(ScanIssue(str(path), "File type changed during scan"))
                return
            if info.st_size > self.max_file_bytes:
                report.issues.append(ScanIssue(str(path), "File exceeds configured byte limit"))
                return
            data = stream.read(self.max_file_bytes + 1)
        if len(data) > self.max_file_bytes:
            report.issues.append(ScanIssue(str(path), "File grew beyond configured byte limit"))
            return
        try:
            if data.startswith((b"\xff\xfe", b"\xfe\xff")):
                text = data.decode("utf-16")
            else:
                text = data.decode("utf-8-sig")
            if "\x00" in text:
                raise ValueError("Binary content")
        except (UnicodeError, ValueError):
            report.issues.append(ScanIssue(str(path), "Binary or unsupported text encoding; not analyzed"))
            return

        text = text.replace("\r\n", "\n").replace("\r", "\n")
        report.files_scanned += 1
        # Precompute line offsets to avoid rescanning the entire file per finding.
        line_starts = [0] + [i + 1 for i, char in enumerate(text) if char == "\n"]
        seen = set()
        suffix = path.suffix.lower()
        blocks = list(fenced_blocks(text)) if suffix in MARKDOWN_SUFFIXES else []
        code_lines = {number for _, lines in blocks for number, _ in lines}

        def append(rule, line, end_line):
            key = (rule.id, line)
            if key not in seen and len(report.findings) < self.max_findings:
                seen.add(key)
                report.findings.append(_finding(rule, str(path), line, end_line))

        for rule, regex in COMPILED_RULES:
            if rule.extensions and suffix not in rule.extensions:
                continue
            position = 0
            while match := regex.search(text, position):
                position = max(match.end(), match.start() + 1)
                if suffix in MARKDOWN_SUFFIXES and defensive_reference(
                    rule.id, text, match.start(), match.end(), code_lines, line_starts,
                ):
                    # A broad match can contain a later operative instruction.
                    # Rejecting its first clause must not hide that later action.
                    position = match.start() + 1
                    continue
                append(rule, bisect_right(line_starts, match.start()),
                       bisect_right(line_starts, max(match.start(), match.end() - 1)))
                if len(report.findings) >= self.max_findings:
                    return
        for rule, line, end_line in shell_matches(text, suffix, blocks):
            append(rule, line, end_line)
            if len(report.findings) >= self.max_findings:
                return
        if suffix in {".py", ".pyw"}:
            try:
                for rule, line, end_line in _python_matches(text):
                    append(rule, line, end_line)
                    if len(report.findings) >= self.max_findings:
                        return
            except (SyntaxError, ValueError, RecursionError):
                report.issues.append(ScanIssue(str(path), "Python syntax analysis failed; text rules still ran"))

