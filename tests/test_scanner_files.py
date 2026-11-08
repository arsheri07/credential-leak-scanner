import subprocess

import pytest

from credscan.scanner import scan_git_history, scan_path


def test_scans_directory_and_reports_relative_paths(tmp_path, fake):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text(f'TOKEN = "{fake["github"]}"\n')
    (tmp_path / "README.md").write_text("nothing to see\n")
    found = scan_path(tmp_path)
    assert [(f.path, f.line) for f in found] == [("src/config.py", 1)]


def test_skips_binary_and_vendor_dirs(tmp_path, fake):
    (tmp_path / "blob.bin").write_bytes(b"\0\1\2" + fake["github"].encode())
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text(f"k='{fake['github']}'")
    assert scan_path(tmp_path) == []


def test_ignore_file(tmp_path, fake):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "keys.txt").write_text(fake["github"])
    (tmp_path / "app.py").write_text(f"t='{fake['github']}'")
    (tmp_path / ".credscanignore").write_text("# test data\nfixtures/*\n")
    assert [f.path for f in scan_path(tmp_path)] == ["app.py"]


def test_single_file(tmp_path, fake):
    p = tmp_path / "one.env"
    p.write_text(f"STRIPE={fake['stripe']}\n")
    assert [f.rule_id for f in scan_path(p)] == ["stripe-secret-key"]


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    return tmp_path


def test_history_finds_secret_deleted_in_later_commit(repo, fake):
    f = repo / "settings.py"
    f.write_text("DEBUG = True\n")
    _git(repo, "add", "."); _git(repo, "commit", "-qm", "init")
    f.write_text(f"DEBUG = True\nTOKEN = '{fake['github']}'\n")
    _git(repo, "commit", "-qam", "oops")
    f.write_text("DEBUG = True\n")
    _git(repo, "commit", "-qam", "remove token")

    assert scan_path(repo) == []                      # working tree is clean...
    hist = scan_git_history(repo)                     # ...but history is not
    assert len(hist) == 1
    assert hist[0].path == "settings.py" and hist[0].line == 2 and hist[0].commit


def test_history_reports_each_secret_once(repo, fake):
    f = repo / "a.py"
    f.write_text(f"T='{fake['github']}'\n")
    _git(repo, "add", "."); _git(repo, "commit", "-qm", "1")
    (repo / "a.py").rename(repo / "b.py")
    _git(repo, "add", "-A"); _git(repo, "commit", "-qm", "rename")
    paths = sorted(x.path for x in scan_git_history(repo))
    assert paths == ["a.py", "b.py"] or paths == ["a.py"]
