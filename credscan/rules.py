"""Detection rules.

Each rule has a regular expression whose first capture group is the secret
itself. `min_entropy` filters out obvious placeholders; rules for formats that
are unambiguous on their own (e.g. a PEM private-key header) set it to 0.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str  # "high" | "medium" | "low"
    pattern: re.Pattern
    min_entropy: float = 0.0


def _r(expr: str, flags: int = 0) -> re.Pattern:
    return re.compile(expr, flags)


RULES: list[Rule] = [
    Rule("aws-access-key-id", "AWS access key ID", "high",
         _r(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 3.0),
    Rule("aws-secret-access-key", "AWS secret access key", "high",
         _r(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"=:\s]+([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"), 4.0),
    Rule("github-token", "GitHub personal access / OAuth token", "high",
         _r(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), 3.5),
    Rule("github-fine-grained-token", "GitHub fine-grained token", "high",
         _r(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"), 3.5),
    Rule("slack-token", "Slack token", "high",
         _r(r"\b(xox[abposr]-[A-Za-z0-9-]{10,72})\b"), 3.0),
    Rule("stripe-secret-key", "Stripe secret key", "high",
         _r(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,99})\b"), 3.5),
    Rule("google-api-key", "Google API key", "high",
         _r(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 3.5),
    Rule("anthropic-api-key", "Anthropic API key", "high",
         _r(r"\b(sk-ant-[A-Za-z0-9_\-]{20,200})\b"), 3.5),
    Rule("openai-api-key", "OpenAI API key", "high",
         _r(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,200})\b"), 3.8),
    Rule("private-key", "Private key (PEM block)", "high",
         _r(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), 0.0),
    Rule("jwt", "JSON Web Token", "medium",
         _r(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"), 3.5),
    Rule("database-url-password", "Password inside a connection string", "high",
         _r(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:([^@\s/]{6,})@"), 3.0),
    Rule("generic-secret-assignment", "Hard-coded secret in an assignment", "medium",
         _r(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"), 3.5),
]

# Values that look like secrets syntactically but are clearly placeholders.
PLACEHOLDER_HINTS = (
    "example", "sample", "dummy", "placeholder", "changeme", "change_me",
    "your_", "your-", "<", "xxxx", "****", "${", "{{", "{", "}", "os.environ", "getenv",
)
