import pytest

from credscan.scanner import scan_text


@pytest.mark.parametrize("line", [
    'password = "changeme123"',
    'api_key = "your-api-key-here"',
    'api_key = os.environ["API_KEY"]',
    'secret = "${SECRET_FROM_VAULT}"',
    'password = "{{ db_password }}"',
    'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',  # AWS's own documentation example
    'password = "aaaaaaaaaaaa"',                     # low entropy
    'token = "xxxxxxxxxxxxxxxxxxxx"',
    "postgres://user:password@localhost/db",          # low-entropy password
    'def get_password(user): return lookup(user)',
    'url = f"postgres://app:{db_password}@db:5432/app"',  # template, not a value
])
def test_placeholders_and_low_entropy_are_ignored(line):
    assert scan_text(line) == []


def test_inline_allow_comment(fake):
    assert scan_text(f'token = "{fake["github"]}"  # credscan: ignore') == []


def test_redaction_never_leaks_full_secret(fake):
    (f,) = scan_text(f"t={fake['github']}")
    assert fake["github"] not in f.redacted
    assert f.redacted.startswith(fake["github"][:4]) and f.redacted.endswith(fake["github"][-4:])
    assert fake["github"] not in str(f.to_dict())
