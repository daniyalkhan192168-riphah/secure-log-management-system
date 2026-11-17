"""
Central configuration.

Secrets live in backend/.env (created by `python manage.py init`), never in
code or git. Real environment variables override values from .env.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.getenv("SECURELOG_ENV_FILE", os.path.join(BASE_DIR, ".env"))


def load_env_file(path: str):
    """Minimal .env reader: KEY=VALUE lines, # comments, no interpolation."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key.strip(), value)


load_env_file(ENV_FILE)


def _bool(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> list:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


# ---- storage ---------------------------------------------------------------
DATABASE_URL = os.getenv(
    "SECURELOG_DATABASE_URL",
    "sqlite:///" + os.path.join(BASE_DIR, "secure_logs.db"),
)
KEY_DIR = os.getenv("SECURELOG_KEY_DIR", os.path.join(BASE_DIR, "keys"))
BATCH_SIZE = int(os.getenv("SECURELOG_BATCH_SIZE", "100"))
# How often the background integrity monitor re-verifies the whole log.
INTEGRITY_CHECK_SECONDS = int(os.getenv("SECURELOG_INTEGRITY_CHECK_SECONDS", "30"))
# An agent that was online and sends no heartbeat for this long is reported as silent.
AGENT_SILENCE_SECONDS = int(os.getenv("SECURELOG_AGENT_SILENCE_SECONDS", "180"))
# The open batch is also sealed once its oldest log is this old (0 = only seal when full).
SEAL_MAX_AGE_SECONDS = int(os.getenv("SECURELOG_SEAL_MAX_AGE_SECONDS", "600"))
# ---- authentication --------------------------------------------------------
ADMIN_USERNAME = os.getenv("SECURELOG_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("SECURELOG_ADMIN_PASSWORD_HASH", "")
TOKEN_SECRET = os.getenv("SECURELOG_TOKEN_SECRET", "")
TOKEN_TTL_MINUTES = int(os.getenv("SECURELOG_TOKEN_TTL_MINUTES", "480"))
# "name:sha256(key),name2:sha256(key2)"  (only hashes are stored)
AGENT_KEYS = os.getenv("SECURELOG_AGENT_KEYS", "")

LOGIN_MAX_FAILURES = int(os.getenv("SECURELOG_LOGIN_MAX_FAILURES", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.getenv("SECURELOG_LOGIN_LOCKOUT_MINUTES", "15"))

# ---- web -------------------------------------------------------------------
CORS_ORIGINS = _list("SECURELOG_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
ENABLE_DOCS = _bool("SECURELOG_ENABLE_DOCS", "true")
# Demo attack buttons (simulate tamper / rewrite). Turn OFF for a real deployment.
DEMO_MODE = _bool("SECURELOG_DEMO_MODE", "false")


def missing_security_settings() -> list:
    missing = []
    if not ADMIN_PASSWORD_HASH:
        missing.append("SECURELOG_ADMIN_PASSWORD_HASH")
    if len(TOKEN_SECRET) < 64:
        missing.append("SECURELOG_TOKEN_SECRET (at least 32 random bytes as hex)")
    if not AGENT_KEYS:
        missing.append("SECURELOG_AGENT_KEYS")
    return missing