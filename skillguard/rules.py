"""Offline indicators, not proof of malicious intent or a complete security audit."""

from dataclasses import dataclass
import re


SEVERITIES = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    pattern: str
    explanation: str
    recommendation: str
    confidence: str = "medium"
    extensions: tuple[str, ...] = ()

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


RULES = (
    Rule(
        "SG001", "Instruction hierarchy override", "HIGH", "prompt-injection",
        r"\b(?:ignore|disregard|override|bypass)\b[^\n]{0,90}\b(?:previous|prior|system|developer|safety|security)\b[^\n]{0,60}\b(?:instructions?|prompts?|rules?|polic(?:y|ies)|checks?|restrictions?)\b",
        "The content asks an agent to override trusted instructions or security controls. "
        "If obeyed, downloaded content could change the agent's authorized behavior.",
        "Quarantine an untrusted skill if this is an operative instruction, not a quoted "
        "example. Remove the override and keep downloaded content below system instructions.",
    ),
    Rule(
        "SG002", "Concealed activity or suppressed audit trail", "HIGH", "prompt-injection",
        r"\b(?:(?:do\s+not|don't|never)\s+(?:tell|inform|notify|alert)\s+(?:the\s+)?user|"
        r"(?:hide|conceal)\s+(?:this|these|the)\s+(?:action|activity|operation|command|behavior)|"
        r"(?:disable|delete|erase|clear)\s+(?:the\s+)?(?:audit\s+logs?|security\s+logs?|command\s+history))\b",
        "Instructions to conceal actions or remove audit records undermine informed "
        "approval and incident investigation.",
        "Remove the skill if covert behavior is intentional. Require visible approvals "
        "and retain audit logs; verify whether the text is merely a defensive example.",
    ),
    Rule(
        "SG003", "Unattended permission bypass", "HIGH", "excessive-permissions",
        r"(?:--dangerously-skip-permissions\b|--no-sandbox\b|"
        r"\b(?:skip|bypass|disable)\s+(?:all\s+)?(?:permission\s+checks?|user\s+approval|confirmation\s+prompts?)\b)",
        "The skill requests fewer approval or isolation safeguards, increasing the impact "
        "of compromised instructions or scripts.",
        "Do not enable this skill with unrestricted tools. Remove the bypass and grant "
        "only narrowly scoped permissions with explicit approval for sensitive actions.",
    ),
    Rule(
        "SG004", "Possible credential exfiltration", "CRITICAL", "credential-access",
        r"\b(?:send|upload|post|exfiltrate|transmit|forward)\b[\s\S]{0,240}?"
        r"(?:\b(?:api[_ -]?keys?|access[_ -]?tokens?|credentials?|passwords?|secrets?|private[_ -]?keys?)\b|"
        r"\.env\b|\.ssh\b)[\s\S]{0,160}?(?:https?://|webhook\b|remote\s+server\b)",
        "A transfer instruction references credentials and a network destination nearby. "
        "Following it could disclose secrets outside the machine.",
        "Quarantine until the transfer's purpose, data, and destination are verified. "
        "Remove unauthorized transfers; revoke exposed credentials if the skill already ran.",
    ),
    Rule(
        "SG005", "Sensitive credential-file access", "MEDIUM", "credential-access",
        r"(?:\.ssh[/\\](?:id_rsa|id_ed25519|authorized_keys)|\.aws[/\\]credentials|"
        r"\.kube[/\\]config|(?:/|~/)etc/shadow|\b(?:cat|read|open|load)\b[^\n]{0,60}(?<!\w)\.env\b)",
        "The content references sensitive credential stores. Access may be legitimate, "
        "but an unrelated skill should not need these files.",
        "Verify necessity and prevent access to real credentials while testing. Remove "
        "the skill if its purpose does not justify this access; use scoped test credentials.",
    ),
    Rule(
        "SG006", "Downloaded code executed by a shell", "HIGH", "remote-code-execution",
        r"\b(?:curl|wget)\b(?=[ \t]+[^\s|`])[^\n`]{1,500}\|[ \t]*(?:(?:sudo|env)[ \t]+)?(?:ba|z|da|k)?sh\b",
        "Network content is piped directly into a shell without inspection or integrity "
        "verification. A compromised source can execute arbitrary commands; this pattern "
        "alone does not prove source compromise or a critical vulnerability.",
        "Do not run this installation step. Download separately, review it, and verify "
        "a trusted signature or pinned digest before considering execution.",
        confidence="high",
    ),
    Rule(
        "SG007", "Potentially destructive recursive deletion", "HIGH", "destructive-operation",
        r"\brm\s+(?:-[A-Za-z]+\s+){1,4}(?:/|~(?:/[^\s;|]*)?|\$HOME(?:/[^\s;|]*)?|"
        r"\$\{HOME\}(?:/[^\s;|]*)?)(?=[\s;|]|$)",
        "A deletion command targets the filesystem root or a home-directory path. "
        "An unexpected expansion or overly broad target could destroy user data.",
        "Do not execute until the target and flags are reviewed. Remove destructive "
        "steps unrelated to the skill and constrain cleanup to a dedicated workspace.",
    ),
    Rule(
        "SG008", "World-writable permissions", "HIGH", "insecure-permissions",
        r"\bchmod\s+(?:-[A-Za-z]+\s+){0,3}(?:777|a\+rwx|o\+w)\b",
        "World-writable paths allow other users or processes to modify data or executable "
        "content that the agent may later trust.",
        "Replace broad permissions with the minimum required user/group access. Do not "
        "install a skill that relies on writable-by-everyone trusted scripts or secrets.",
        confidence="high",
    ),
    Rule(
        "SG009", "Disabled TLS certificate verification", "MEDIUM", "insecure-network",
        r"(?:\bverify\s*=\s*False\b|\b(?:curl|wget)\b[^\n]{0,180}"
        r"(?:\s--insecure\b|\s-(?!-)[A-Za-z]*k[A-Za-z]*(?=\s|$|[;|`])|\s--no-check-certificate\b)|"
        r"--blackduck\.trust\.cert(?:=|\s+)true\b|"
        r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0\b)",
        "Disabling certificate verification permits an attacker on the network to "
        "impersonate a server, potentially replacing downloads or collecting credentials.",
        "Enable certificate verification and configure the correct trust store. Block "
        "deployment when unverified connections handle sensitive data or executable content.",
        confidence="high",
    ),
    Rule(
        "SG010", "Encoded payload passed to an interpreter", "HIGH", "obfuscation",
        r"(?:\b(?:exec|eval)\s*\(\s*(?:base64\.)?b64decode\s*\(|"
        r"\bbase64\s+(?:--decode|-d|-D)\b[^\n]{0,120}\|\s*(?:ba|z)?sh\b|"
        r"\bpowershell(?:\.exe)?\b[^\n]{0,100}\s-(?:enc|encodedcommand)\b)",
        "Encoded data is being interpreted as executable code. Encoding can conceal "
        "behavior from reviewers, although some administrative uses are legitimate.",
        "Quarantine until the payload is decoded and reviewed without executing it. "
        "Prefer readable, version-controlled scripts over opaque executable payloads.",
    ),
    Rule(
        "SG011", "Potential embedded access credential", "HIGH", "embedded-secret",
        r"(?:\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,255}\b|"
        r"\bgithub_pat_[A-Za-z0-9_]{30,255}\b|\bxox[baprs]-[A-Za-z0-9-]{20,200}\b)",
        "The content contains a token-shaped value matching common access credential "
        "formats. If genuine, sharing or installing this skill exposes a credential.",
        "Verify without posting the value elsewhere. Revoke and rotate genuine tokens, "
        "remove them from the skill and its history, and use a secret manager instead.",
    ),
    Rule(
        "SG012", "Embedded private key", "CRITICAL", "embedded-secret",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "A private-key block is embedded in the skill. Distributing a real private key "
        "can compromise every system or identity that trusts it.",
        "Do not distribute or install real private keys in skills. Remove the key and "
        "rotate/revoke it if exposed; verify whether this is an intentionally inert fixture.",
        confidence="high",
    ),
    Rule(
        "SG013", "Persistent startup modification", "HIGH", "persistence",
        r"(?:\bcrontab\s+(?:-|[^\s;|]+)|\bLaunchAgents/|\bLaunchDaemons/|"
        r"(?:>>|tee\s+-a)\s*[\"']?~?/(?:[^\n]{0,80}/)?\.(?:bashrc|zshrc|profile)\b)",
        "The content installs or modifies recurring/startup behavior. An untrusted skill "
        "could continue running after the task ends or hijack later shell sessions.",
        "Require explicit approval, inspect the installed command, and document removal. "
        "Reject persistence that is unrelated to the skill's stated purpose.",
    ),
    Rule(
        "SG014", "Unrestricted agent tool configuration", "HIGH", "excessive-permissions",
        r"(?:(?<![\w-])[\"']?(?:allowed[_-]?tools|permissions|tools)[\"']?\s*[:=]\s*"
        r"(?:\[\s*)?(?:[\"']\*[\"']|\*(?=\s*(?:[\]},\n]|$)))|\bBash\(\*\))",
        "A configuration appears to grant wildcard tool or permission access. A "
        "compromised skill could use capabilities unrelated to its intended task.",
        "Use an explicit allowlist and isolate filesystem/network access. Do not trust "
        "downloaded permission declarations as authorization to grant those permissions.",
    ),
    Rule(
        "SG015", "JavaScript dynamic code evaluation", "MEDIUM", "unsafe-api",
        r"\b(?:eval\s*\(|new\s+Function\s*\()",
        "Dynamic evaluation treats strings as executable code. It becomes code execution "
        "if instructions, network data, or other untrusted input reach the expression.",
        "Trace the evaluated input. Replace evaluation with structured parsing and reject "
        "the skill if it evaluates untrusted data without a strong isolation boundary.",
        extensions=(".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"),
    ),
    Rule(
        "SG016", "Credential file attached to an upload command", "CRITICAL", "credential-access",
        r"\b(?:curl|wget)\b[^\n]{0,300}?(?:--data(?:-binary|-raw)?|--upload-file|"
        r"--post-file|--form|-d|-T|-F)(?:\s+|=)[^\n]{0,160}?"
        r"(?:\.env\b|\.ssh[/\\]id_(?:rsa|ed25519)\b|\.aws[/\\]credentials\b|/etc/shadow\b)",
        "A network upload command references a sensitive local file as request data. "
        "Running it could send credentials to the command's destination.",
        "Keep this skill disabled until the destination and authorization are verified. "
        "Remove unauthorized uploads and rotate credentials if the command already ran.",
    ),
)


# These rules are matched structurally by scanner.py rather than by regex.
PYTHON_RULES = {
    "SG101": Rule(
        "SG101", "Python dynamic code execution", "MEDIUM", "unsafe-api", "",
        "eval/exec/compile converts input into code. Untrusted input reaching this call "
        "could execute with the agent's permissions; this scanner does not prove data flow.",
        "Trace the argument's origin. Prefer JSON or other structured parsing and remove "
        "the skill if it executes untrusted input without adequate isolation.",
        confidence="high",
    ),
    "SG102": Rule(
        "SG102", "Python shell command execution", "MEDIUM", "unsafe-api", "",
        "This call invokes a shell or enables shell=True. Untrusted command fragments "
        "can become shell injection; constant, reviewed commands may be legitimate.",
        "Prefer subprocess argument lists with shell=False, validate inputs, and restrict "
        "execution permissions. Reject a skill that interpolates untrusted shell commands.",
        confidence="high",
    ),
    "SG103": Rule(
        "SG103", "Unsafe Python deserialization", "HIGH", "unsafe-deserialization", "",
        "Pickle-like deserialization or an unsafe YAML loader can construct executable "
        "objects. Reading attacker-controlled serialized data may execute arbitrary code.",
        "Use JSON or yaml.safe_load for untrusted data. Remove this behavior before "
        "allowing the skill to process downloaded or user-controlled serialized objects.",
        confidence="high",
    ),
}


# These rules inspect shell command structure and block-local state, not prose.
SHELL_RULES = {
    "SG017": Rule(
        "SG017", "Security scanner failure masked by logging pipeline", "HIGH",
        "security-gate-bypass", "",
        "A recognized security scanner is piped to tee without visible pipeline-failure "
        "propagation. tee can succeed when the scanner fails, even with set -e. If CI "
        "relies on this status, policy violations or scan errors can pass the gate. "
        "A nonempty log is not evidence of a successful scan.",
        "Preserve and check the scanner's exit status. Use an explicitly supported shell "
        "with pipefail and appropriate failure handling, or capture/check the status "
        "before replaying the log in POSIX sh. Test a failing scanner in CI.",
    ),
    "SG018": Rule(
        "SG018", "Detached validation container status not propagated", "MEDIUM",
        "security-gate-bypass", "",
        "A recognized validation container runs detached and its logs are collected, "
        "but no matching container exit-status propagation was recognized. Successful "
        "docker run/logs calls do not establish successful validation. This is a "
        "release-gate risk only when the container's validation is required.",
        "Wait for this container, inspect its actual exit code, and explicitly fail "
        "on nonzero status. docker wait prints the container status; its own successful "
        "exit status is not the validation result. Review custom status handling manually.",
    ),
}


ALL_RULES = (*RULES, *PYTHON_RULES.values(), *SHELL_RULES.values())
