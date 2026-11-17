"""
Forward-secure key storage.

The server only ever holds ONE key: the key of the currently open batch.
When a batch is sealed the key is evolved one-way and the old key is
overwritten, so a later break-in cannot recover it.

Files in KEY_DIR:
  current_key.json   secret, permission 600, never sent over the API
  AUDITOR_K0.key     created once on first start. MOVE IT OFFLINE (USB /
                     auditor machine) and delete it from the server.
                     Whoever holds K0 can verify (and forge!) everything.

Honest limitations (put these in the report's threat model):
  * os.replace() does not guarantee the old key bytes are wiped from the
    disk blocks or from Python memory. Real deployments use a TPM / HSM.
  * Logs in the OPEN batch are protected only by the current key; an
    attacker who steals it can rewrite the open batch. Sealing often
    (smaller BATCH_SIZE) shrinks that window.
"""
import json
import os
import secrets
import threading
from datetime import datetime, timezone

from config import KEY_DIR
from services import crypto_core as cc

KEY_FILE = os.path.join(KEY_DIR, "current_key.json")
K0_EXPORT_FILE = os.path.join(KEY_DIR, "AUDITOR_K0.key")

_lock = threading.Lock()


class KeyStateError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _restrict(path: str):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows only partly supports chmod; fine for development


def _atomic_write(path: str, text: str):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    _restrict(tmp)
    os.replace(tmp, path)
    _restrict(path)


def _read() -> dict:
    with open(KEY_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def initialize() -> dict:
    """Create K0 on first start; otherwise load the existing state."""
    with _lock:
        os.makedirs(KEY_DIR, exist_ok=True)
        if os.path.exists(KEY_FILE):
            return _public(_read())

        k0 = secrets.token_bytes(32)
        state = {
            "key_version": 1,
            "key": k0.hex(),
            "k0_fingerprint": cc.k0_fingerprint(k0),
            "created_at": _now(),
            "updated_at": _now(),
        }
        _atomic_write(K0_EXPORT_FILE, k0.hex() + "\n")
        _atomic_write(KEY_FILE, json.dumps(state, indent=2))
        print("=" * 70)
        print(" NEW FORWARD-SECURE KEY CREATED")
        print(f" Auditor key K0 written to: {K0_EXPORT_FILE}")
        print(" Copy it to the auditor machine / USB, then DELETE it from here.")
        print("=" * 70)
        return _public(state)


def _public(state: dict) -> dict:
    """Everything except the secret key itself."""
    return {k: v for k, v in state.items() if k != "key"}


def public_state() -> dict:
    return _public(_read())


def current_key() -> tuple:
    """(key_bytes, key_version) for the currently open batch."""
    state = _read()
    return bytes.fromhex(state["key"]), state["key_version"]


def evolve_to(target_version: int) -> dict:
    """
    Move the key forward until key_version == target_version, overwriting
    the old key. Only ever moves forward.
    """
    with _lock:
        state = _read()
        if target_version < state["key_version"]:
            raise KeyStateError(
                f"Refusing to move key backwards ({state['key_version']} -> {target_version})"
            )
        key = bytes.fromhex(state["key"])
        while state["key_version"] < target_version:
            key = cc.evolve(key)
            state["key_version"] += 1
        state["key"] = key.hex()
        state["updated_at"] = _now()
        _atomic_write(KEY_FILE, json.dumps(state, indent=2))
        return _public(state)
