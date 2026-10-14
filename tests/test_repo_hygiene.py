import os
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tracked():
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [f for f in out.decode().split("\0") if f and os.path.exists(os.path.join(ROOT, f))]


def test_no_key_material_or_runtime_artifacts_are_tracked():
    bad = [f for f in tracked() if re.search(r"\.(pem|key|p12|pfx|checkpoint|lock|pyc)$|(^|/)\.env$|__pycache__|network_blockchain\.json$", f)]
    assert bad == []


def test_no_private_key_blocks_or_obvious_secrets_in_tracked_files():
    pat = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}")
    hits = []
    for f in tracked():
        if f.endswith((".png", ".ico")) or f.startswith("static/vendor/"):
            continue
        try:
            text = open(os.path.join(ROOT, f), encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        if f != "tests/test_repo_hygiene.py" and pat.search(text):
            hits.append(f)
    assert hits == []


def test_env_example_contains_no_values_for_secrets():
    text = open(os.path.join(ROOT, ".env.example")).read()
    for key in ("BLOCKAUDIT_ADMIN_TOKEN", "BLOCKAUDIT_ANALYST_TOKEN", "BLOCKAUDIT_VIEWER_TOKEN", "ANTHROPIC_API_KEY"):
        assert re.search(rf"^{key}=$", text, re.M), key


def test_key_script_refuses_to_write_inside_repo(tmp_path):
    import create_device_keys as c
    with pytest.raises(SystemExit):
        c.generate_rsa_keypair(os.path.join(ROOT, "keys"))
    priv, pub = c.generate_rsa_keypair(str(tmp_path / "k"), key_size=2048)
    assert oct(os.stat(priv).st_mode & 0o777) == "0o600"
    with pytest.raises(SystemExit):
        c.generate_rsa_keypair(str(tmp_path / "k"), key_size=2048)


def test_secrets_are_redacted_from_logs():
    from blockaudit.logging_setup import redact
    assert "abcdef0123456789" not in redact("Authorization: Bearer abcdef0123456789")
    assert "sk-test-secret-value" not in redact("api_key=sk-test-secret-value")
    assert "MIIE" not in redact("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----")
