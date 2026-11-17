"""
All cryptographic primitives of the system, in one place, using only the
Python standard library.

Design (based on Schneier & Kelsey 1999, Bellare & Yee 2003):

  entry_hash_i = SHA256("SLv1-entry" || canonical(log_i) || entry_hash_{i-1})
      Public hash chain. Anyone can recompute it, so it detects careless edits
      but NOT an attacker who recomputes the whole chain.

  mac_i        = HMAC(K_b, "SLv1-mac" || entry_hash_i)
      Secret tag made with the key of the batch b the log belongs to.

  root_b       = Merkle root over the entry hashes of batch b
                 (leaf = H(0x00 || h), node = H(0x01 || left || right))

  seal_b       = HMAC(K_b, "SLv1-seal" || canonical(batch_b_header))
      The batch header contains root_b and seal_{b-1}, so seals form a chain.

  K_{b+1}      = SHA256("SLv1-evolve" || K_b)      then K_b is overwritten.
      One-way: K_{b+1} reveals nothing about K_b. An attacker who steals the
      key while batch v is open cannot forge MACs or seals for batches < v.

The auditor keeps K_1 (called K0 in the docs) offline and can re-derive every
batch key to verify everything.
"""
import hashlib
import hmac
import json

GENESIS_HASH = "0" * 64   # previous hash of the very first log
GENESIS_SEAL = "0" * 64   # previous seal of the very first batch

_ENTRY = b"SLv1-entry"
_MAC = b"SLv1-mac"
_SEAL = b"SLv1-seal"
_EVOLVE = b"SLv1-evolve"
_FINGERPRINT = b"SLv1-k0-fingerprint"


def canonical(data: dict) -> bytes:
    """Deterministic JSON encoding: same dict -> same bytes, always."""
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def entry_hash(log_data: dict, previous_hash: str) -> str:
    h = hashlib.sha256()
    h.update(_ENTRY)
    h.update(canonical(log_data))
    h.update(bytes.fromhex(previous_hash))
    return h.hexdigest()


def log_mac(key: bytes, entry_hash_hex: str) -> str:
    return hmac.new(key, _MAC + bytes.fromhex(entry_hash_hex), hashlib.sha256).hexdigest()


def batch_header(batch_id, first_log_id, last_log_id, total_logs,
                 root_hash, previous_seal, key_version) -> dict:
    return {
        "batch_id": batch_id,
        "first_log_id": first_log_id,
        "last_log_id": last_log_id,
        "total_logs": total_logs,
        "root_hash": root_hash,
        "previous_seal": previous_seal,
        "key_version": key_version,
    }


def batch_seal(key: bytes, header: dict) -> str:
    return hmac.new(key, _SEAL + canonical(header), hashlib.sha256).hexdigest()


def evolve(key: bytes) -> bytes:
    return hashlib.sha256(_EVOLVE + key).digest()


def derive_key(k0: bytes, version: int) -> bytes:
    """Key for batch `version` (version 1 == K0)."""
    key = k0
    for _ in range(version - 1):
        key = evolve(key)
    return key


def k0_fingerprint(k0: bytes) -> str:
    """Public commitment to K0, so the auditor can confirm they hold the right key."""
    return hashlib.sha256(_FINGERPRINT + k0).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")
