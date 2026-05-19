import hashlib
import json
import os
import secrets
from datetime import datetime

KEY_FILE = "key_state.json"


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def initialize_key_state():
    if not os.path.exists(KEY_FILE):
        initial_key = secrets.token_hex(32)

        state = {
            "key_version": 1,
            "current_key_hash": sha256(initial_key),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }

        with open(KEY_FILE, "w") as file:
            json.dump(state, file, indent=4)

        return state

    with open(KEY_FILE, "r") as file:
        return json.load(file)


def get_current_key_state():
    return initialize_key_state()


def evolve_key():
    state = initialize_key_state()

    old_key_hash = state["current_key_hash"]
    new_key_hash = sha256(old_key_hash)

    state["key_version"] += 1
    state["current_key_hash"] = new_key_hash
    state["updated_at"] = datetime.utcnow().isoformat()

    with open(KEY_FILE, "w") as file:
        json.dump(state, file, indent=4)

    return state


def get_key_version():
    state = initialize_key_state()
    return state["key_version"]


def get_current_key_hash():
    state = initialize_key_state()
    return state["current_key_hash"]