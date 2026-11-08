import pytest

from credscan.scanner import scan_text


def ids(text):
    return {f.rule_id for f in scan_text(text)}


@pytest.mark.parametrize("key,template,rule", [
    ("aws_id", 'aws_access_key_id = "{}"', "aws-access-key-id"),
    ("github", "token: {}", "github-token"),
    ("slack", "SLACK={}", "slack-token"),
    ("stripe", "stripe.api_key = '{}'", "stripe-secret-key"),
    ("google", "const k = '{}';", "google-api-key"),
    ("anthropic", "ANTHROPIC_API_KEY={}", "anthropic-api-key"),
    ("jwt", "Authorization: Bearer {}", "jwt"),
    ("pem", "{}", "private-key"),
])
def test_provider_formats_detected(fake, key, template, rule):
    assert rule in ids(template.format(fake[key]))


def test_aws_secret_needs_context(fake):
    assert "aws-secret-access-key" in ids(f'aws_secret_access_key = "{fake["aws_secret"]}"')
    # A random 40-char string with no AWS context is not flagged by this rule.
    assert "aws-secret-access-key" not in ids(f'checksum = "{fake["aws_secret"]}"')


def test_password_in_database_url(fake):
    found = scan_text(f"DATABASE_URL=postgres://admin:{fake['db_pw']}@db.internal:5432/app")
    assert [f.rule_id for f in found] == ["database-url-password"]
    assert found[0].secret == fake["db_pw"]


def test_generic_assignment(fake):
    assert "generic-secret-assignment" in ids(f'client_secret = "{fake["generic"]}"')


def test_anthropic_key_not_double_reported_as_openai(fake):
    found = scan_text(f"key={fake['anthropic']}")
    assert len(found) == 1 and found[0].rule_id == "anthropic-api-key"


def test_column_and_line_numbers(fake):
    text = "first line\n    token = " + fake["github"]
    (f,) = scan_text(text)
    assert f.line == 2
    assert f.column == text.splitlines()[1].index("ghp") + 1
