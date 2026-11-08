# Credential Leak Scanner

A command-line tool that finds **leaked API keys, tokens, and passwords** in source code and **git history** before they reach a public repository.

Committing a credential is one of the most common ways cloud accounts get compromised, and deleting it in a later commit does not help: the key is still in the history for anyone who clones the repo. `credscan` catches it at commit time, in CI, or after the fact.

```text
$ credscan . --history
[HIGH] GitHub personal access / OAuth token
    settings.py:2:10 (commit 26381ec1bece)
    match: ghp_************************oCLr  entropy: 4.62

1 finding(s), 1 high severity. Rotate any real secret: deleting it is not enough.
```

## Features

- **13 detection rules**: AWS, GitHub, Slack, Stripe, Google, Anthropic and OpenAI keys, PEM private keys, JWTs, passwords in database URLs, and hard-coded `password = "..."` style assignments.
- **Shannon-entropy filtering** so random-looking strings are flagged while placeholders (`changeme`, `your-api-key`, `${VAR}`, `os.environ[...]`, AWS's `...EXAMPLE` key) are not.
- **Git history scanning** (`--history`): checks every line *added* in past commits, so secrets that were "deleted" are still found, with the commit hash.
- **Redacted output**: findings show only the first and last 4 characters, so the report itself never leaks the secret.
- **Text, JSON, and SARIF output**: SARIF uploads directly to GitHub code scanning.
- **CI and pre-commit friendly**: exit code `1` when findings meet `--fail-on` severity, `0` when clean.
- **No dependencies**: pure Python standard library.

## Install

```bash
git clone https://github.com/arsheri07/credential-leak-scanner
cd credential-leak-scanner
pip install -e .
```

## Usage

```bash
credscan                      # scan the current directory
credscan src/ config.yml      # scan specific paths
credscan . --history          # also scan git history
credscan . --format sarif > results.sarif
credscan . --fail-on high     # only fail the build on high-severity findings
cat file.txt | credscan --stdin
```

### Suppressing false positives

- Add `# credscan: ignore` to a line to skip it.
- List glob patterns in a `.credscanignore` file at the scan root (e.g. `tests/fixtures/*`).

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/arsheri07/credential-leak-scanner
    rev: v1.0.0
    hooks:
      - id: credscan
```

### GitHub Actions

```yaml
- run: pip install git+https://github.com/arsheri07/credential-leak-scanner
- run: credscan . --format sarif > results.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## How it works

1. Walk the target, skipping binary files, files over 2 MB, and vendor folders (`.git`, `node_modules`, virtualenvs).
2. Run each line through regular expressions for known credential formats. The first capture group is the secret itself.
3. Compute the **Shannon entropy** of the captured value (bits per character). Real keys are random, so they score high; words and placeholders score low and are dropped.
4. Drop values that contain placeholder hints (`example`, `changeme`, `${`, `getenv`, ...).
5. With `--history`, parse `git log -p` and run the same checks on every added line, tracking file and line number per commit.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

43 tests cover every rule, false-positive cases, redaction, ignore files, git history (a secret added and then deleted is still found), and the CLI's exit codes and output formats. The test suite builds its fake keys at runtime, so this repository passes its own scan.

## Limitations

Regex and entropy rules catch common formats but not everything: a custom internal token with no recognizable prefix and a low-entropy password will be missed. Treat this as one layer of defense, alongside keeping secrets in environment variables or a secrets manager.

## License

MIT
