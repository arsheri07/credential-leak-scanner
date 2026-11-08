"""Output formats: human-readable text, JSON, and SARIF for GitHub code scanning."""

from __future__ import annotations

import json

from . import __version__
from .rules import RULES
from .scanner import Finding

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.path, f.line))


def to_text(findings: list[Finding], color: bool = False) -> str:
    if not findings:
        return "No secrets found."
    red, yel, dim, end = ("\033[31m", "\033[33m", "\033[2m", "\033[0m") if color else ("", "", "", "")
    lines = []
    for f in sort_findings(findings):
        tag = f"{red}HIGH{end}" if f.severity == "high" else f"{yel}{f.severity.upper()}{end}"
        where = f"{f.path}:{f.line}:{f.column}" + (f" (commit {f.commit})" if f.commit else "")
        lines.append(f"[{tag}] {f.description}\n    {where}\n    {dim}match: {f.redacted}  entropy: {f.entropy:.2f}{end}")
    high = sum(f.severity == "high" for f in findings)
    lines.append(f"\n{len(findings)} finding(s), {high} high severity. Rotate any real secret: deleting it is not enough.")
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in sort_findings(findings)], indent=2)


def to_sarif(findings: list[Finding]) -> str:
    used = {f.rule_id for f in findings}
    rules = [{
        "id": r.id,
        "shortDescription": {"text": r.description},
        "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
    } for r in RULES if r.id in used]
    results = [{
        "ruleId": f.rule_id,
        "level": SARIF_LEVEL.get(f.severity, "warning"),
        "message": {"text": f"{f.description} detected ({f.redacted})."},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path},
            "region": {"startLine": f.line, "startColumn": f.column},
        }}],
    } for f in sort_findings(findings)]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "credscan", "version": __version__,
                                       "informationUri": "https://github.com/arsheri07/credential-leak-scanner",
                                       "rules": rules}},
                  "results": results}],
    }
    return json.dumps(doc, indent=2)
