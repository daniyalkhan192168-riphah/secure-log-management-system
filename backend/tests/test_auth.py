"""
Authentication tests: passwords, session tokens, agent keys, login lockout,
and the manage.py setup command.

Run from the backend folder:  python tests/test_auth.py
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path.insert(0, BACKEND)

os.environ["SECURELOG_ENV_FILE"] = os.path.join(tempfile.mkdtemp(), "none.env")
os.environ["SECURELOG_TOKEN_SECRET"] = "ab" * 32
os.environ["SECURELOG_ADMIN_USERNAME"] = "admin"

import config                      # noqa: E402
from services import auth          # noqa: E402

FAST = 1000  # fewer PBKDF2 rounds to keep tests quick


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_password_hash_and_verify():
    h = auth.hash_password("correct horse battery", iterations=FAST)
    assert h.startswith("pbkdf2_sha256$")
    assert auth.verify_password("correct horse battery", h)
    assert not auth.verify_password("wrong password", h)
    assert h != auth.hash_password("correct horse battery", iterations=FAST)  # random salt


def test_admin_credentials():
    config.ADMIN_PASSWORD_HASH = auth.hash_password("S3cure-Passw0rd", iterations=FAST)
    assert auth.check_admin_credentials("admin", "S3cure-Passw0rd")
    assert not auth.check_admin_credentials("admin", "nope")
    assert not auth.check_admin_credentials("root", "S3cure-Passw0rd")


def test_token_roundtrip():
    token, exp = auth.issue_token("admin")
    claims = auth.verify_token(token)
    assert claims["sub"] == "admin" and claims["role"] == "admin" and claims["exp"] == exp


def test_tampered_token_rejected():
    token, _ = auth.issue_token("admin")
    h, p, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=="))
    claims["role"] = "superadmin"
    assert auth.verify_token(f"{h}.{b64(claims)}.{sig}") is None
    assert auth.verify_token(token[:-2] + ("AA" if not token.endswith("AA") else "BB")) is None


def test_alg_none_token_rejected():
    forged = b64({"alg": "none", "typ": "JWT"}) + "." + b64(
        {"sub": "admin", "role": "admin", "exp": time.time() + 999, "jti": "x"}) + "."
    assert auth.verify_token(forged) is None


def test_expired_token_rejected():
    token, _ = auth.issue_token("admin", ttl_minutes=-1)
    assert auth.verify_token(token) is None


def test_token_signed_with_other_secret_rejected():
    token, _ = auth.issue_token("admin")
    old = config.TOKEN_SECRET
    config.TOKEN_SECRET = "cd" * 32
    try:
        assert auth.verify_token(token) is None
    finally:
        config.TOKEN_SECRET = old


def test_logout_revokes_token():
    token, _ = auth.issue_token("admin")
    claims = auth.verify_token(token)
    auth.revoke_token(claims)
    assert auth.verify_token(token) is None
    assert auth.verify_token(auth.issue_token("admin")[0]) is not None  # new login works


def test_agent_keys():
    k1, k2 = auth.new_agent_key(), auth.new_agent_key()
    config.AGENT_KEYS = f"ubuntu-vm:{auth.hash_agent_key(k1)},web-01:{auth.hash_agent_key(k2)}"
    assert auth.verify_agent_key(k1) == "ubuntu-vm"
    assert auth.verify_agent_key(k2) == "web-01"
    assert auth.verify_agent_key("secure-log-secret-2026") is None   # the old hardcoded key
    assert auth.verify_agent_key("") is None and auth.verify_agent_key(None) is None
    assert k1 not in config.AGENT_KEYS                                 # only hashes stored


def test_login_lockout():
    limiter = auth.LoginLimiter(max_failures=3, window_seconds=60)
    for _ in range(3):
        assert limiter.retry_after("1.2.3.4") == 0
        limiter.record_failure("1.2.3.4")
    assert limiter.retry_after("1.2.3.4") > 0         # locked
    assert limiter.retry_after("5.6.7.8") == 0        # other IPs unaffected
    limiter.reset("1.2.3.4")
    assert limiter.retry_after("1.2.3.4") == 0


def test_lockout_expires():
    limiter = auth.LoginLimiter(max_failures=1, window_seconds=1)
    limiter.record_failure("ip")
    assert limiter.retry_after("ip") > 0
    time.sleep(1.1)
    assert limiter.retry_after("ip") == 0


def test_manage_init_creates_working_env():
    env_file = os.path.join(tempfile.mkdtemp(), ".env")
    out = subprocess.run(
        [sys.executable, os.path.join(BACKEND, "manage.py"), "--env-file", env_file,
         "init", "--username", "teacher", "--password", "Viva-Passw0rd!", "--agent", "vm1"],
        capture_output=True, text=True, check=True,
    ).stdout
    key = [l.strip() for l in out.splitlines() if l.startswith("   ") and l.strip()][0]

    values = {}
    for line in open(env_file):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            values[k] = v
    assert key not in open(env_file).read()                    # raw key never stored
    assert auth.verify_password("Viva-Passw0rd!", values["SECURELOG_ADMIN_PASSWORD_HASH"])
    assert len(values["SECURELOG_TOKEN_SECRET"]) == 64
    assert values["SECURELOG_AGENT_KEYS"] == f"vm1:{auth.hash_agent_key(key)}"

    # add-agent keeps the first agent and adds a second one
    subprocess.run([sys.executable, os.path.join(BACKEND, "manage.py"), "--env-file", env_file,
                    "add-agent", "web-01"], capture_output=True, text=True, check=True)
    agents = auth.parse_agent_keys(open(env_file).read().split("SECURELOG_AGENT_KEYS=")[1].split("\n")[0])
    assert set(agents.values()) == {"vm1", "web-01"}

    # refuses to overwrite without --force
    r = subprocess.run([sys.executable, os.path.join(BACKEND, "manage.py"), "--env-file", env_file,
                        "init", "--username", "x", "--password", "Another-Passw0rd"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "already exists" in r.stderr


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
