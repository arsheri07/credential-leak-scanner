import io
import json

from credscan.cli import main


def test_clean_exit_zero(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("print('hi')\n")
    assert main([str(tmp_path)]) == 0
    assert "No secrets found" in capsys.readouterr().out


def test_findings_exit_one(tmp_path, fake, capsys):
    (tmp_path / "bad.py").write_text(f"k='{fake['aws_id']}'\n")
    assert main([str(tmp_path), "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "AWS access key ID" in out and fake["aws_id"] not in out


def test_fail_on_high_ignores_medium(tmp_path, fake):
    (tmp_path / "a.py").write_text(f"auth = '{fake['jwt']}'\n")  # jwt = medium
    assert main([str(tmp_path), "--fail-on", "high"]) == 0
    assert main([str(tmp_path), "--fail-on", "medium"]) == 1


def test_json_output(tmp_path, fake, capsys):
    (tmp_path / "a.py").write_text(f"k='{fake['github']}'\n")
    main([str(tmp_path), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["rule"] == "github-token" and data[0]["path"] == "a.py"


def test_sarif_output_is_valid_shape(tmp_path, fake, capsys):
    (tmp_path / "a.py").write_text(f"k='{fake['github']}'\n")
    main([str(tmp_path), "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "github-token"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_stdin(monkeypatch, fake, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(f"x={fake['stripe']}"))
    assert main(["--stdin"]) == 1


def test_history_on_non_repo_warns(tmp_path, capsys):
    assert main([str(tmp_path), "--history"]) == 0
    assert "not a git repository" in capsys.readouterr().err
