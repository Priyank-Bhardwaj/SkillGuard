"""Bounded source-context heuristics; never evaluate or execute scanned content."""

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
import shlex

from .rules import SHELL_RULES


MARKDOWN_SUFFIXES = {".md", ".markdown", ".mdc"}
SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".ksh"}
SHELL_LANGUAGES = {"sh", "shell", "bash", "zsh", "ksh", "shellscript"}
SCANNERS = {
    "detect.sh", "blackduck.sh", "detect", "trivy", "grype", "semgrep", "bandit",
    "pip-audit", "safety", "checkov", "kics", "gitleaks", "sonar-scanner",
    "plausicheck",
}
PROSE_RULES = {"SG001", "SG002", "SG003", "SG004", "SG005", "SG006",
               "SG007", "SG008", "SG009", "SG010", "SG013", "SG014", "SG016"}
NEGATED_ACTION = re.compile(
    r"\b(?:do\s+not|don't|must\s+not|should\s+not|never|cannot)\s+"
    r"(?:(?:ever|attempt\s+to|allow\s+agents?\s+to|"
    r"(?:print|read(?:\s+aloud)?|commit|expose|execute|run|use|send|upload|"
    r"forward|override|bypass|disable|access|open|load)\b)[\s,]*)*"
    r"(?:(?:or|and)\s+)?$", re.IGNORECASE,
)


def fenced_blocks(text):
    """Yield (language, [(original line number, source)]) for Markdown fences."""
    fence = None
    language = ""
    lines = []
    for number, line in enumerate(text.splitlines(), 1):
        if fence is None:
            opening = re.match(r"^\s{0,3}(`{3,}|~{3,})([^\n]*)$", line)
            if opening:
                fence = opening[1]
                language = opening[2].strip().split(maxsplit=1)[0].lower() if opening[2].strip() else ""
                lines = []
        elif re.fullmatch(r"\s{0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}\s*", line):
            yield language, lines
            fence = None
        else:
            lines.append((number, line))
    if fence is not None:
        yield language, lines


def defensive_reference(rule_id, text, start, end, code_lines, line_starts):
    """Suppress only a directly negated prose action, not neighboring commands.

    A warning elsewhere in a paragraph/file is not an allowlist. Fenced examples
    remain inspectable, and secret-shaped literals are never exempted by prose.
    """
    if rule_id not in PROSE_RULES:
        return False
    line = bisect_right(line_starts, start)
    end_line = line + text.count("\n", start, end)
    if any(number in code_lines for number in range(line, end_line + 1)):
        return False
    # Include at most one wrapped line; do not carry negation over sentences,
    # contrast clauses, or Markdown list items.
    current_start = text.rfind("\n", 0, start) + 1
    previous_start = text.rfind("\n", 0, max(0, current_start - 1)) + 1
    prefix = text[max(previous_start, start - 240):start]
    current = text[current_start:start]
    if re.match(r"\s*(?:[-*+]\s|\d+[.)]\s)", current):
        prefix = current
    prefix = re.split(r"[;.!?]|\b(?:but|however|instead|then)\b", prefix, flags=re.IGNORECASE)[-1]
    prefix = prefix.replace("`", "").replace("**", "").replace("__", "")
    if NEGATED_ACTION.search(prefix):
        return True
    return rule_id == "SG001" and bool(re.search(
        r"\b(?:not\s+as\s+instructions?\s+that|(?:do\s+not|never)\s+"
        r"(?:follow|obey|accept)\s+instructions?\s+(?:that|to))\s*$",
        prefix, re.IGNORECASE,
    ))


@dataclass
class Command:
    line: int
    end_line: int
    tokens: list[str]


def _commands(lines):
    """Tokenize logical shell lines; comments and quoted operators stay inert."""
    pending = ""
    start = 0
    for number, line in lines:
        if not pending:
            start = number
        continued = line.rstrip().endswith("\\")
        pending += line.rstrip()[:-1] + " " if continued else line
        if continued:
            continue
        try:
            lexer = shlex.shlex(pending, posix=True, punctuation_chars="|;&()<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            tokens = []  # Complex/unbalanced constructs are outside this heuristic.
        command = []
        for token in tokens + [";"]:
            if token in {";", "&&", "||"}:
                if command:
                    yield Command(start, number, command)
                command = []
            else:
                command.append(token)
        pending = ""


def _scanner(tokens):
    if not tokens:
        return False
    tokens = list(tokens)
    while tokens and (tokens[0] in {"env", "sudo", "if", "!"} or
                      re.match(r"^[A-Za-z_]\w*=", tokens[0])):
        tokens.pop(0)
    if not tokens:
        return False
    executable = PurePosixPath(tokens[0]).name.lower()
    return (executable in SCANNERS or
            bool(re.fullmatch(r"detect\d+\.sh", executable)) or
            executable in {"npm", "pnpm", "yarn"} and tokens[1:2] == ["audit"] or
            executable in {"python", "python3"} and tokens[1:2] == ["-m"] and
            tokens[2:3] and tokens[2].replace("_", "-") in SCANNERS)


def _propagates(commands, expression):
    """Recognize explicit exits or an immediate capture followed by a checked exit."""
    if not commands:
        return False
    first = commands[0].tokens
    if first in (["exit", expression], ["return", expression]):
        return True
    assignment = re.fullmatch(r"([A-Za-z_]\w*)=" + re.escape(expression), first[0])
    if not assignment:
        return False
    return _checked_variable(commands[1:9], assignment[1])


def _checked_variable(commands, variable):
    references = {"$" + variable, "${" + variable + "}"}
    for index, command in enumerate(commands):
        tokens = command.tokens
        if re.match(re.escape(variable) + r"=", tokens[0]):
            return False
        if tokens[0] in {"exit", "return"} and tokens[1:2] and tokens[1] in references:
            return True
        # Recognize a narrow guard, not an unrelated reference or exit.
        if (len(tokens) == 6 and tokens[:2] in (["if", "["], ["if", "[["]) and
                tokens[2] in references and tokens[3:5] in (["-ne", "0"], ["!=", "0"]) and
                tokens[5] in {"]", "]]"}):
            following = [t for c in commands[index + 1:index + 3] for t in c.tokens]
            if following[:3] in (["then", "exit", "1"], ["then", "return", "1"]):
                return True
    return False


def _container_checked(commands, variable):
    references = {"$" + variable, "${" + variable + "}"}
    for index, command in enumerate(commands):
        tokens = command.tokens
        if tokens[0] in {"exit", "return"} and len(tokens) == 2:
            # Quoted command substitutions are retained as one shlex token.
            if tokens[1] in {"$(docker wait " + ref + ")" for ref in references}:
                return True
        if not any(ref in tokens for ref in references):
            continue
        if ["docker", "wait"] != tokens[2:4]:
            continue
        assignment = re.fullmatch(r"([A-Za-z_]\w*)=\$", tokens[0])
        if assignment and _checked_variable(commands[index + 1:index + 9], assignment[1]):
            return True
    return False


def shell_matches(text, suffix, blocks):
    """Check recognized scanners, scoped to each shell file or fenced example.

    This is not a shell parser/control-flow proof. Unrecognized tools, wrappers,
    heredocs, sourced settings, and complex status handling require manual review.
    """
    if suffix in SHELL_SUFFIXES or (suffix not in MARKDOWN_SUFFIXES and
                                   re.match(r"^#![^\n]*\b(?:ba|z|k|da)?sh\b", text)):
        regions = [list(enumerate(text.splitlines(), 1))]
    elif suffix in MARKDOWN_SUFFIXES:
        regions = [lines for language, lines in blocks
                   if language in SHELL_LANGUAGES or
                   not language and lines and lines[0][1].startswith("#!")]
    else:
        return
    for region in regions:
        commands = list(_commands(region))
        pipefail = False
        for index, command in enumerate(commands):
            tokens = command.tokens
            if tokens[0] == "set":
                for option_index, option in enumerate(tokens[1:], 1):
                    if (re.fullmatch(r"[-+][A-Za-z]*o", option) and
                            tokens[option_index + 1:option_index + 2] == ["pipefail"]):
                        pipefail = option.startswith("-")
            if "|" in tokens:
                pipe = tokens.index("|")
                tail = tokens[pipe + 1:]
                handled = any(_propagates(commands[index + 1:index + 10], expression)
                              for expression in ("${PIPESTATUS[0]}", "${pipestatus[1]}"))
                if _scanner(tokens[:pipe]) and tail[:1] == ["tee"] and not pipefail and not handled:
                    yield SHELL_RULES["SG017"], command.line, command.end_line
            # Only recognize assigned container IDs, known validation images,
            # and subsequent logs of that same ID (not unrelated services).
            if len(tokens) < 5 or tokens[1:4] != ["(", "docker", "run"]:
                continue
            assignment = re.fullmatch(r"([A-Za-z_]\w*)=\$", tokens[0])
            detached = any(t in {"-d", "--detach", "--detach=true"} for t in tokens)
            image = any(t.rsplit("/", 1)[-1].split(":", 1)[0].lower() in SCANNERS for t in tokens[4:])
            if not assignment or not detached or not image:
                continue
            # Bound cross-command inspection; custom/distant handling needs review.
            remaining = commands[index + 1:index + 257]
            references = {"$" + assignment[1], "${" + assignment[1] + "}"}
            logs = next((c for c in remaining if c.tokens[:2] == ["docker", "logs"] and
                         any(ref in c.tokens for ref in references)), None)
            if logs and not _container_checked(remaining, assignment[1]):
                yield SHELL_RULES["SG018"], command.line, command.end_line
