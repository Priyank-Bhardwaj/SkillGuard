"""Bounded, convention-based discovery; never executes project content."""

from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
import stat

from .scanner import DEFAULT_EXCLUDES, ScanIssue


INSTRUCTION_NAMES = frozenset({
    "agents.md", "agent.md", "claude.md", "claude.local.md", "gemini.md", "copilot-instructions.md",
    ".cursorrules", ".windsurfrules", ".mcp.json", "mcp.json",
    "agent.json", "agent.yaml", "agent.yml", "agent.toml",
    "skill.json", "skill.yaml", "skill.yml", "skill.toml",
})
DEFINITION_EXTENSIONS = frozenset({".md", ".mdc", ".json", ".yaml", ".yml", ".toml", ".txt"})


def absolute_path(path: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


@dataclass(frozen=True)
class Target:
    path: str
    kind: str
    bundle: bool = False


@dataclass
class Discovery:
    project: str
    targets: list[Target] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    entries_examined: int = 0
    excluded_directories: int = 0
    default_exclusions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {**asdict(self), "complete": not self.issues}


def unique_targets(targets: list[Target]) -> list[Target]:
    """Keep outer bundles once; a bundle scan already covers its nested definitions."""
    result = []
    for target in sorted(targets, key=lambda t: (len(Path(t.path).parts), not t.bundle, t.path)):
        path = Path(target.path)
        if any(path == Path(t.path) or (t.bundle and path.is_relative_to(t.path)) for t in result):
            continue
        result.append(target)
    return result


def _definition(path: Path) -> bool:
    name = path.name.lower()
    parts = tuple(p.lower() for p in path.parts)
    if name in INSTRUCTION_NAMES or name.endswith((".agent.md", ".instructions.md", ".prompt.md")):
        return True
    if path.parent.name.lower() == ".claude" and name in {"settings.json", "settings.local.json"}:
        return True
    if path.parent.name.lower() in {"skills", "agents"}:
        return path.suffix.lower() in DEFINITION_EXTENSIONS
    return any(
        parts[i:i + 2] in {(".cursor", "rules"), (".windsurf", "rules"),
                          (".github", "prompts"), (".github", "instructions"),
                          (".claude", "commands")}
        for i in range(len(parts) - 1)
    ) and path.suffix.lower() in DEFINITION_EXTENSIONS


def discover_project(project: str | Path, *, max_entries: int = 20_000,
                     max_targets: int = 256, use_default_excludes: bool = True,
                     cancelled: Callable[[], bool] | None = None) -> Discovery:
    if min(max_entries, max_targets) < 1:
        raise ValueError("Discovery limits must be positive")
    root = absolute_path(project)
    excludes = DEFAULT_EXCLUDES if use_default_excludes else frozenset()
    result = Discovery(str(root), default_exclusions=sorted(excludes))
    try:
        mode = root.lstat().st_mode
        if not stat.S_ISDIR(mode):
            result.issues.append(ScanIssue(str(root), "Project must be a directory, not a file or symlink"))
            return result
    except OSError:
        result.issues.append(ScanIssue(str(root), "Project directory is inaccessible"))
        return result

    frames: list[Iterator[Path | os.DirEntry[str]]] = [iter([root])]
    candidates = []
    try:
        while frames:
            if cancelled and cancelled():
                result.issues.append(ScanIssue(str(root), "Project discovery cancelled"))
                break
            try:
                entry = next(frames[-1])
            except (StopIteration, OSError) as error:
                if isinstance(error, OSError):
                    result.issues.append(ScanIssue(str(root), "Directory enumeration failed"))
                frame = frames.pop()
                if hasattr(frame, "close"):
                    frame.close()
                continue
            path = Path(entry.path) if isinstance(entry, os.DirEntry) else entry
            if result.entries_examined >= max_entries:
                result.issues.append(ScanIssue(str(root), "Discovery entry limit reached"))
                break
            result.entries_examined += 1
            try:
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    result.issues.append(ScanIssue(str(path), "Symlink skipped during discovery"))
                elif stat.S_ISDIR(mode):
                    if path != root and path.name in excludes:
                        result.excluded_directories += 1
                    elif path != root and path.parent.name.lower() in {"skills", "agents"}:
                        candidates.append(Target(str(path), "Skill/agent bundle", True))
                    elif len(frames) >= 100:
                        result.issues.append(ScanIssue(str(path), "Discovery depth limit reached"))
                    else:
                        frames.append(os.scandir(path))
                elif stat.S_ISREG(mode):
                    if path.name.lower() == "skill.md":
                        candidates.append(Target(str(path.parent), "Skill bundle", True))
                    elif _definition(path):
                        candidates.append(Target(str(path), "Agent/instruction file"))
                else:
                    result.issues.append(ScanIssue(str(path), "Special file skipped during discovery"))
            except OSError:
                result.issues.append(ScanIssue(str(path), "Path inaccessible during discovery"))
            if len(candidates) >= max_targets:
                result.issues.append(ScanIssue(str(root), "Discovery candidate limit reached"))
                break
    finally:
        for frame in frames:
            if hasattr(frame, "close"):
                frame.close()
    result.targets = unique_targets(candidates)
    return result
