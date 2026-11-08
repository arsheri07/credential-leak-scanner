"""Command-line interface.

Exit codes: 0 = clean, 1 = findings at or above --fail-on, 2 = usage error.
That makes it drop straight into CI pipelines and pre-commit hooks.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

from . import __version__
from .report import SEVERITY_ORDER, to_json, to_sarif, to_text
from .scanner import scan_git_history, scan_path, scan_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="credscan",
                                description="Find leaked credentials in files, directories, or git history.")
    p.add_argument("paths", nargs="*", default=["."], help="files or directories to scan (default: .)")
    p.add_argument("--history", action="store_true", help="also scan lines added in past git commits")
    p.add_argument("--max-commits", type=int, default=500, help="how far back --history looks (default 500)")
    p.add_argument("--stdin", action="store_true", help="scan text piped on standard input")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--fail-on", choices=["high", "medium", "low"], default="medium",
                   help="lowest severity that makes the exit code 1 (default: medium)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings = []
    if args.stdin:
        findings += scan_text(sys.stdin.read(), "<stdin>")
    else:
        for path in args.paths:
            findings += scan_path(path)
        if args.history:
            for path in args.paths:
                try:
                    findings += scan_git_history(path, args.max_commits)
                except (subprocess.CalledProcessError, FileNotFoundError):
                    print(f"credscan: {path} is not a git repository; skipping --history", file=sys.stderr)

    if args.format == "json":
        print(to_json(findings))
    elif args.format == "sarif":
        print(to_sarif(findings))
    else:
        print(to_text(findings, color=sys.stdout.isatty() and not args.no_color))

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] <= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
