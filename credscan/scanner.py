"""Core scanning logic: files, directories, and git history."""

from __future__ import annotations

import fnmatch
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .entropy import shannon_entropy
from .rules import PLACEHOLDER_HINTS, RULES, Rule

INLINE_ALLOW = "credscan: ignore"
IGNORE_FILE = ".credscanignore"
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache", ".pytest_cache"}
BINARY_SNIFF_BYTES = 2048
MAX_FILE_BYTES = 2 * 1024 * 1024  # skip files over 2 MB (lockfiles, data dumps)


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    path: str
    line: int
    column: int
    secret: str = field(repr=False)
    entropy: float
    commit: str | None = None

    @property
    def redacted(self) -> str:
        """Show just enough of the secret to recognize it, never the whole thing."""
        s = self.secret
        if len(s) <= 8:
            return "*" * len(s)
        return f"{s[:4]}{'*' * min(len(s) - 8, 24)}{s[-4:]}"

    def to_dict(self) -> dict:
        d = {
            "rule": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "match": self.redacted,
            "entropy": round(self.entropy, 2),
        }
        if self.commit:
            d["commit"] = self.commit
        return d


def _looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    return any(h in low for h in PLACEHOLDER_HINTS)


def scan_text(text: str, path: str = "<input>", rules: list[Rule] = RULES, commit: str | None = None) -> list[Finding]:
    """Scan a block of text and return every finding, one per secret per line."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if INLINE_ALLOW in line:
            continue
        seen: set[str] = set()
        for rule in rules:
            for m in rule.pattern.finditer(line):
                secret = m.group(1)
                if secret in seen:
                    continue  # a more specific rule already reported this value
                ent = shannon_entropy(secret)
                if rule.min_entropy and ent < rule.min_entropy:
                    continue
                if rule.id != "private-key" and _looks_like_placeholder(secret):
                    continue
                seen.add(secret)
                findings.append(Finding(rule.id, rule.description, rule.severity, path,
                                        lineno, m.start(1) + 1, secret, ent, commit))
    return findings


def load_ignore_patterns(root: Path) -> list[str]:
    f = root / IGNORE_FILE
    if not f.is_file():
        return []
    return [ln.strip() for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def _ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(rel), p) for p in patterns)


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(BINARY_SNIFF_BYTES)
    except OSError:
        return True


def iter_files(root: Path, patterns: list[str]):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if name == IGNORE_FILE or _ignored(rel, patterns):
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            if not _is_binary(p):
                yield p


def scan_path(target: str | os.PathLike) -> list[Finding]:
    """Scan a file or every text file under a directory."""
    root = Path(target)
    base = root if root.is_dir() else root.parent
    patterns = load_ignore_patterns(base)
    findings: list[Finding] = []
    for f in iter_files(root, patterns):
        rel = f.relative_to(base).as_posix()
        text = f.read_text(encoding="utf-8", errors="ignore")
        findings.extend(scan_text(text, rel))
    return findings


def scan_git_history(repo: str | os.PathLike, max_commits: int = 500) -> list[Finding]:
    """Scan lines *added* in past commits — a deleted secret is still in history.

    Removing a key in a later commit does not remove it from the repository;
    anyone who clones can still read it. This is why secrets must be rotated,
    not just deleted.
    """
    out = subprocess.run(
        ["git", "-C", str(repo), "log", f"-n{max_commits}", "-p", "--no-color", "--unified=0",
         "--format=__COMMIT__%H"],
        capture_output=True, text=True, errors="ignore", check=True,
    ).stdout
    findings: list[Finding] = []
    commit, path, new_line = None, None, 0
    for raw in out.splitlines():
        if raw.startswith("__COMMIT__"):
            commit = raw[len("__COMMIT__"):][:12]
        elif raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
        elif raw.startswith("@@"):
            # @@ -a,b +c,d @@  -> next added line number is c
            try:
                new_line = int(raw.split("+")[1].split(",")[0].split(" ")[0])
            except (IndexError, ValueError):
                new_line = 0
        elif raw.startswith("+") and path:
            for f in scan_text(raw[1:], path, commit=commit):
                f.line = new_line
                findings.append(f)
            new_line += 1
    # The same secret often survives many commits; report each one once.
    unique: dict[tuple, Finding] = {}
    for f in findings:
        unique.setdefault((f.rule_id, f.path, f.secret), f)
    return list(unique.values())
