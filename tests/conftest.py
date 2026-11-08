import random
import string

import pytest


def rand(n, alphabet=string.ascii_letters + string.digits, seed=None):
    rng = random.Random(seed if seed is not None else n)
    return "".join(rng.choice(alphabet) for _ in range(n))


@pytest.fixture
def fake():
    """Build realistic-looking but fake credentials at runtime."""
    up = string.ascii_uppercase + string.digits
    return {
        "aws_id": "AKIA" + rand(16, up, 1),
        "aws_secret": rand(40, string.ascii_letters + string.digits + "/+", 2),
        "github": "ghp" + "_" + rand(36, seed=3),
        "slack": "xoxb" + "-" + rand(12, string.digits, 4) + "-" + rand(24, seed=5),
        "stripe": "sk" + "_live_" + rand(24, seed=6),
        "google": "AIza" + rand(35, string.ascii_letters + string.digits + "_-", 7),
        "anthropic": "sk-ant" + "-" + rand(40, seed=8),
        "jwt": "eyJ" + rand(20, seed=9) + ".eyJ" + rand(30, seed=10) + "." + rand(43, seed=11),
        "pem": "-----BEGIN " + "RSA PRIVATE KEY-----",
        "db_pw": rand(16, seed=12),
        "generic": rand(24, seed=13),
    }
