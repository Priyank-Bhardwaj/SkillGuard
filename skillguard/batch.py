"""UI-independent batch scanning and grouped reports."""

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path

from .discovery import Discovery, Target, absolute_path, discover_project, unique_targets
from .rules import SEVERITIES
from .scanner import Report, ScanIssue, Scanner


@dataclass(frozen=True)
class Selection:
    path: str
    mode: str  # file, folder, or project


@dataclass
class UnitResult:
    target: Target
    report: Report

    @property
    def highest_severity(self) -> str:
        return max((f.severity for f in self.report.findings), key=SEVERITIES.get, default="NONE")

    @property
    def status(self) -> str:
        if not self.report.complete:
            return "INCOMPLETE / findings" if self.report.findings else "INCOMPLETE"
        if self.report.findings:
            return "Needs review"
        return "No indicators" if self.report.files_scanned else "No text scanned"

    def to_dict(self) -> dict:
        return {"target": asdict(self.target), "status": self.status,
                "highest_severity": self.highest_severity, "report": self.report.to_dict()}


@dataclass
class BatchReport:
    selections: list[Selection]
    units: list[UnitResult] = field(default_factory=list)
    discoveries: list[Discovery] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    cancelled: bool = False

    @property
    def complete(self) -> bool:
        return not (self.cancelled or self.issues or any(d.issues for d in self.discoveries)
                    or any(not u.report.complete for u in self.units))

    def summary(self) -> dict:
        return {
            "units_scanned": len(self.units),
            "units_with_findings": sum(bool(u.report.findings) for u in self.units),
            "incomplete_units": sum(not u.report.complete for u in self.units),
            "files_scanned": sum(u.report.files_scanned for u in self.units),
            "findings": sum(len(u.report.findings) for u in self.units),
        }

    def to_dict(self) -> dict:
        return {
            "schema_version": 1, "report_type": "skillguard-batch",
            "complete": self.complete, "cancelled": self.cancelled,
            "summary": self.summary(), "selections": [asdict(s) for s in self.selections],
            "units": [u.to_dict() for u in self.units],
            "discoveries": [d.to_dict() for d in self.discoveries],
            "issues": [asdict(i) for i in self.issues],
            "notice": "Convention-based discovery and heuristic scanning, not proof of safety. "
                      "Undiscovered files and default directory exclusions are outside coverage.",
        }


def scan_batch(selections: list[Selection], *, cancelled: Callable[[], bool] | None = None,
               progress: Callable[[str], None] | None = None,
               use_default_excludes: bool = True, max_units: int = 256,
               max_entries: int = 50_000, max_findings: int = 20_000) -> BatchReport:
    if min(max_units, max_entries, max_findings) < 1:
        raise ValueError("Batch limits must be positive")
    result = BatchReport(list(selections))
    stopped = cancelled or (lambda: False)
    notify = progress or (lambda message: None)
    targets = []
    entries_left = max_entries
    findings_left = max_findings
    for selection in selections[:128]:
        if stopped():
            result.cancelled = True
            break
        path = str(absolute_path(selection.path))
        if selection.mode == "project":
            if entries_left <= 0:
                result.issues.append(ScanIssue(path, "Batch entry budget exhausted before discovery"))
                break
            notify(f"Discovering project: {json.dumps(path, ensure_ascii=True)}")
            discovery = discover_project(path, max_entries=min(20_000, entries_left),
                                         max_targets=max_units, cancelled=stopped,
                                         use_default_excludes=use_default_excludes)
            result.discoveries.append(discovery)
            entries_left -= discovery.entries_examined
            targets.extend(discovery.targets)
        elif selection.mode in {"file", "folder"}:
            targets.append(Target(path, "Selected " + selection.mode, selection.mode == "folder"))
        else:
            result.issues.append(ScanIssue(path, "Unknown selection mode"))
        targets = unique_targets(targets)
        if len(targets) > max_units:
            result.issues.append(ScanIssue("Batch", "Unit limit exceeded; remaining targets/selections were not scanned"))
            targets = targets[:max_units]
            break
    if len(selections) > 128:
        result.issues.append(ScanIssue("Batch", "Selection limit exceeded; only the first 128 selections were considered"))
    for index, target in enumerate(targets, start=1):
        if stopped():
            result.cancelled = True
            break
        if min(entries_left, findings_left) <= 0:
            result.issues.append(ScanIssue(target.path, "Batch resource budget exhausted; remaining targets were not scanned"))
            break
        notify(f"Scanning {index}/{len(targets)}: {json.dumps(target.path, ensure_ascii=True)}")
        report = Scanner(max_entries=min(10_000, entries_left),
                         max_findings=min(10_000, findings_left),
                         use_default_excludes=use_default_excludes).scan(target.path, cancelled=stopped)
        entries_left -= report.entries_examined
        findings_left -= len(report.findings)
        result.units.append(UnitResult(target, report))
    result.cancelled = bool(result.cancelled or stopped())
    return result


def export_batch(report: BatchReport, path: str | Path) -> None:
    """Create a private NEW report; never overwrite source or follow a file symlink."""
    content = json.dumps(report.to_dict(), indent=2, ensure_ascii=True) + "\n"
    fd = os.open(Path(path).expanduser(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
