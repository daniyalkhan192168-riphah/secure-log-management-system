"""
Authentication primitives (standard library only, so they are easy to test
and explain).

  Admin password : PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt
                   (OWASP 2023 recommendation). Only the hash is stored.
  Session token  : JWT-compatible HS256 token  header.payload.signature
                   signed with SECURELOG_TOKEN_SECRET, expires after
                   SECURELOG_TOKEN_TTL_MINUTES, revocable on logout.
  Agent API key  : 32 random bytes. Server stores only SHA-256(key), so a
                   leaked .env does not reveal working agent keys.
  Login limiter  : after N failures from one IP, lock that IP for M minutes.
"""
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import defaultdict, deque

import config

PBKDF2_ITERATIONS = 600_000


# ------------------------------------------------------------ passwords
def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, AttributeError):
        return False


# A fixed dummy hash so a wrong USERNAME costs the same time as a wrong
# password (prevents discovering valid usernames by timing).
_DUMMY_HASH = hash_password("dummy-password-for-timing", iterations=PBKDF2_ITERATIONS)


def check_admin_credentials(username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(username.encode(), config.ADMIN_USERNAME.encode())
    stored = config.ADMIN_PASSWORD_HASH if user_ok else _DUMMY_HASH
    password_ok = verify_password(password, stored)
    return user_ok and password_ok


# ------------------------------------------------------------ tokens
def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(signing_input: bytes) -> str:
    return _b64e(hmac.new(config.TOKEN_SECRET.encode(), signing_input, hashlib.sha256).digest())


_revoked = {}           # jti -> exp
_revoked_lock = threading.Lock()


def issue_token(username: str, role: str = "admin", ttl_minutes: int = None) -> tuple:
    now = int(time.time())
    exp = now + 60 * (ttl_minutes if ttl_minutes is not None else config.TOKEN_TTL_MINUTES)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": username, "role": role, "iat": now, "exp": exp, "jti": secrets.token_hex(12)}
    signing_input = (_b64e(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     _b64e(json.dumps(payload, separators=(",", ":")).encode()))
    return signing_input + "." + _sign(signing_input.encode()), exp


def verify_token(token: str):
    """Return the claims dict if the token is valid, otherwise None."""
    if not token or not config.TOKEN_SECRET:
        return None
    try:
        header_b64, payload_b64, signature = token.split(".")
        header = json.loads(_b64d(header_b64))
        if header.get("alg") != "HS256":          # blocks the "alg: none" trick
            return None
        expected = _sign(f"{header_b64}.{payload_b64}".encode())
        if not hmac.compare_digest(expected, signature):
            return None
        claims = json.loads(_b64d(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(claims.get("exp", 0)) <= time.time():
        return None
    with _revoked_lock:
        if claims.get("jti") in _revoked:
            return None
    return claims


def revoke_token(claims: dict):
    now = time.time()
    with _revoked_lock:
        for jti, exp in list(_revoked.items()):   # forget expired entries
            if exp <= now:
                del _revoked[jti]
        _revoked[claims["jti"]] = claims["exp"]


# ------------------------------------------------------------ agent keys
def new_agent_key() -> str:
    return secrets.token_urlsafe(32)


def hash_agent_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def parse_agent_keys(raw: str) -> dict:
    """'name:hash,name2:hash2' -> {hash: name}"""
    result = {}
    for item in raw.split(","):
        if ":" in item:
            name, digest = item.strip().split(":", 1)
            if name and digest:
                result[digest.strip()] = name.strip()
    return result


def verify_agent_key(key: str):
    """Return the agent's name if the key is valid, otherwise None."""
    if not key:
        return None
    presented = hash_agent_key(key)
    found = None
    for digest, name in parse_agent_keys(config.AGENT_KEYS).items():
        if hmac.compare_digest(presented, digest):
            found = name
    return found


# ------------------------------------------------------------ login limiter
class LoginLimiter:
    def __init__(self, max_failures: int, window_seconds: int):
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, q: deque, now: float):
        while q and q[0] <= now - self.window:
            q.popleft()

    def retry_after(self, client: str) -> int:
        """Seconds until this client may try again (0 = allowed now)."""
        now = time.time()
        with self._lock:
            q = self._failures[client]
            self._prune(q, now)
            if len(q) >= self.max_failures:
                return max(1, int(q[0] + self.window - now))
            return 0

    def record_failure(self, client: str):
        with self._lock:
            self._failures[client].append(time.time())

    def reset(self, client: str):
        with self._lock:
            self._failures.pop(client, None)


login_limiter = LoginLimiter(config.LOGIN_MAX_FAILURES, config.LOGIN_LOCKOUT_MINUTES * 60)