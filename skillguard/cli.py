"""Command-line interface. Exit 0: below threshold; 1: findings; 2: incomplete/error."""

import argparse
import json
import os
from pathlib import Path
import sys

from .rules import ALL_RULES, SEVERITIES
from .scanner import Report, Scanner


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _display_path(value: str) -> str:
    # Paths come from untrusted bundles; escape terminal controls and bidi characters.
    return json.dumps(value, ensure_ascii=True)


def render_text(report: Report) -> str:
    counts = report.to_dict()["severity_counts"]
    lines = [
        "SkillGuard - offline skill/agent static scanner",
        f"Target: {_display_path(report.target)}",
        f"Coverage: {'COMPLETE within configured scope' if report.complete else 'INCOMPLETE'}",
        f"Text files scanned: {report.files_scanned}; directories excluded: {report.excluded_directories}",
        "Default directory exclusions: " + (", ".join(report.default_exclusions) or "none"),
        "Findings: " + ", ".join(f"{severity}={count}" for severity, count in counts.items()),
        "",
    ]
    if any(SEVERITIES[f.severity] >= SEVERITIES["HIGH"] for f in report.findings):
        lines.append("Recommendation: keep this skill disabled/quarantined until HIGH/CRITICAL findings are reviewed.")
    elif report.findings:
        lines.append("Recommendation: review findings and tool permissions before enabling this skill.")
    else:
        lines.append("No configured indicators found in analyzed content. This does NOT prove safety.")
    for finding in report.findings:
        lines.extend([
            "",
            f"[{finding.severity}] {finding.rule_id}: {finding.title}",
            f"  Location: {_display_path(finding.file)}:{finding.line}-{finding.end_line}",
            f"  Category: {finding.category}; match confidence: {finding.confidence}",
            f"  Why risky: {finding.explanation}",
            f"  What to do / when to remove: {finding.recommendation}",
        ])
    if report.issues:
        lines.extend(["", "Coverage issues (not vulnerability findings):"])
        lines.extend(f"  {_display_path(issue.path)}: {issue.reason}" for issue in report.issues)
    lines.extend([
        "", "Heuristics can produce false positives and miss threats. Review context and provenance.",
        "Source snippets are intentionally omitted to avoid leaking credentials or printing hostile content.",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="skillguard", description="Inspect local skills/agents without running their code."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a local file or directory recursively")
    scan.add_argument("path", help="downloaded/existing skill file or directory; URLs are not fetched")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--output", type=Path, help="write a NEW report file instead of stdout")
    scan.add_argument("--fail-on", type=str.upper, choices=tuple(SEVERITIES), default="HIGH",
                      help="exit 1 at or above this severity (default: HIGH); all findings remain visible")
    scan.add_argument("--max-file-bytes", type=_positive_int, default=1_048_576)
    scan.add_argument("--max-entries", type=_positive_int, default=10_000,
                      help="maximum filesystem entries examined, including directories")
    scan.add_argument("--max-findings", type=_positive_int, default=10_000)
    scan.add_argument("--no-default-excludes", action="store_true",
                      help="also traverse .git, .venv, venv, __pycache__, node_modules")
    commands.add_parser("rules", help="list detection rules and their explanations")
    commands.add_parser("gui", help="open the desktop file/folder/project scanner")
    args = parser.parse_args(argv)

    if args.command == "gui":
        # Keep Tk optional for CLI-only environments.
        from .gui import main as gui_main
        return gui_main()

    if args.command == "rules":
        for rule in ALL_RULES:
            print(f"{rule.id} [{rule.severity}] {rule.title}\n  {rule.explanation}\n  {rule.recommendation}\n")
        return 0

    report = Scanner(
        max_file_bytes=args.max_file_bytes, max_entries=args.max_entries,
        max_findings=args.max_findings, use_default_excludes=not args.no_default_excludes,
    ).scan(args.path)
    content = (json.dumps(report.to_dict(), indent=2, ensure_ascii=True) + "\n"
               if args.format == "json" else render_text(report))
    try:
        if args.output:
            # Exclusive creation avoids overwriting source, old reports, or symlink targets.
            fd = os.open(args.output.expanduser(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
        else:
            sys.stdout.write(content)
    except OSError:
        print("Unable to write report. Check permissions and use a new output filename.", file=sys.stderr)
        return 2
    if not report.complete:
        return 2
    return int(any(SEVERITIES[f.severity] >= SEVERITIES[args.fail_on] for f in report.findings))
