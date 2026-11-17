"""
Ledger service: every operation on the tamper-evident log lives here.
Routes only call these functions, so the logic can be tested without FastAPI.

Invariant:  key_version == open_batch_id
            open_batch_id == (last sealed batch_id) + 1
A log is always appended to the open batch and MACed with the open batch key.
Sealing batch b: build Merkle root, compute seal with K_b, COMMIT the seal,
then evolve the key to K_{b+1} (commit first, so a crash can never leave a
batch whose key is already destroyed but whose seal was never written).
"""
import threading
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from config import BATCH_SIZE
from models import Log, MerkleRoot
from services import crypto_core as cc
from services import key_manager as km
from services.merkle_service import (
    build_merkle_root, inclusion_proof, verify_inclusion, tree_for_display,
)

# One writer at a time, so two logs never grab the same previous_hash.
# NOTE: works for a single uvicorn worker (the default). Do not run with --workers > 1.
_write_lock = threading.Lock()

AUDITOR_NOTE = (
    "MACs and seals of SEALED batches can only be checked by the auditor "
    "(scripts/auditor_verify.py with K0), because the server has already "
    "destroyed those keys. That is what forward security means."
)


# ---------------------------------------------------------------- helpers
def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def ts_string(dt: datetime) -> str:
    return dt.isoformat(timespec="microseconds")


def log_payload(log: Log) -> dict:
    """Exactly the fields that are hashed. The log id is included so a log
    cannot be moved to another position in the chain."""
    return {
        "id": log.id,
        "timestamp": ts_string(log.timestamp),
        "source": log.source,
        "event_type": log.event_type,
        "username": log.username,
        "ip_address": log.ip_address,
        "message": log.message,
        "agent_id": log.agent_id,
        "event_time": ts_string(log.event_time) if log.event_time else None,
    }


def last_sealed(db: Session):
    return db.query(MerkleRoot).order_by(MerkleRoot.batch_id.desc()).first()


def open_batch_id(db: Session) -> int:
    last = last_sealed(db)
    return (last.batch_id if last else 0) + 1


def sync_key(db: Session):
    """Bring the key in line with the database before writing.
    key behind DB  -> crash happened after a seal commit; evolve forward.
    key ahead of DB -> seal rows were deleted; refuse to continue."""
    ob = open_batch_id(db)
    _, kv = km.current_key()
    if kv < ob:
        km.evolve_to(ob)
    elif kv > ob:
        raise km.KeyStateError(
            f"Key is at version {kv} but the database's open batch is {ob}. "
            "Sealed batch records are missing (possible deletion). Run the auditor."
        )


# ---------------------------------------------------------------- writing
def append_log(db: Session, data: dict, agent_id: str) -> Log:
    """data: source, event_type, username, ip_address, message.
    agent_id comes from authentication, never from the request body."""
    event_time = data.get("event_time")
    if event_time is not None and event_time.tzinfo is not None:
        data = {**data, "event_time": event_time.astimezone(timezone.utc).replace(tzinfo=None)}
    with _write_lock:
        sync_key(db)
        key, kv = km.current_key()

        latest = db.query(Log).order_by(Log.id.desc()).first()
        previous_hash = latest.current_hash if latest else cc.GENESIS_HASH

        log = Log(
            **data,
            agent_id=agent_id,
            timestamp=utcnow(),
            previous_hash=previous_hash,
            current_hash="",
            mac="",
            batch_id=kv,
        )
        db.add(log)
        db.flush()  # assigns log.id, which is part of the hashed payload

        log.current_hash = cc.entry_hash(log_payload(log), previous_hash)
        log.mac = cc.log_mac(key, log.current_hash)
        db.commit()
        db.refresh(log)

        open_count = db.query(Log).filter(Log.batch_id == kv).count()
        if open_count >= BATCH_SIZE:
            _seal_locked(db)

        return log


def _seal_locked(db: Session):
    sync_key(db)
    key, kv = km.current_key()

    logs = db.query(Log).filter(Log.batch_id == kv).order_by(Log.id.asc()).all()
    if not logs:
        return None

    prev = last_sealed(db)
    previous_seal = prev.seal if prev else cc.GENESIS_SEAL
    root = build_merkle_root([l.current_hash for l in logs])

    header = cc.batch_header(
        batch_id=kv,
        first_log_id=logs[0].id,
        last_log_id=logs[-1].id,
        total_logs=len(logs),
        root_hash=root,
        previous_seal=previous_seal,
        key_version=kv,
    )
    row = MerkleRoot(**header, seal=cc.batch_seal(key, header))
    db.add(row)
    db.commit()          # 1) seal is safely stored
    db.refresh(row)
    km.evolve_to(kv + 1)  # 2) only now destroy K_b
    return row


def seal_open_batch(db: Session):
 SERVER_AGENT = "securelog-server"


def record_server_event(db: Session, event_type: str, username: str, ip: str, message: str):
    """Write the server's own security events (logins, admin actions) into the
    same tamper-evident ledger. Never lets a logging failure break the request."""
    try:
        return append_log(db, {
            "source": "SecureLog-Server",
            "event_type": event_type,
            "username": (username or "-")[:100],
            "ip_address": (ip or "-")[:50],
            "message": message[:4000],
        }, agent_id=SERVER_AGENT)
    except Exception as e:  # noqa: BLE001
        db.rollback()
        print(f"[WARN] could not record server event {event_type}: {e}")
        return None
    """Seal the open batch now (even if it has fewer than BATCH_SIZE logs)."""
    with _write_lock:
        return _seal_locked(db)


# ---------------------------------------------------------------- verifying
class _Problems:
    LIMIT = 100

    def __init__(self):
        self.items = []
        self.count = 0

    def add(self, kind, detail, log_id=None, batch_id=None):
        self.count += 1
        if len(self.items) < self.LIMIT:
            item = {"type": kind, "detail": detail}
            if log_id is not None:
                item["log_id"] = log_id
            if batch_id is not None:
                item["batch_id"] = batch_id
            self.items.append(item)


def verify_all(db: Session) -> dict:
    """Everything the SERVER can check without old keys."""
    p = _Problems()
    logs = db.query(Log).order_by(Log.id.asc()).all()
    roots = db.query(MerkleRoot).order_by(MerkleRoot.batch_id.asc()).all()

    # 1. public hash chain + content hashes
    expected_prev = cc.GENESIS_HASH
    last_batch = 0
    by_batch = defaultdict(list)
    for log in logs:
        if log.previous_hash != expected_prev:
            p.add("chain_link", "previous_hash does not match the log before it", log_id=log.id)
        if cc.entry_hash(log_payload(log), log.previous_hash) != log.current_hash:
            p.add("content_hash", "log content does not match its stored hash", log_id=log.id)
        if log.batch_id < last_batch:
            p.add("batch_order", "batch id goes backwards in the chain", log_id=log.id)
        last_batch = max(last_batch, log.batch_id)
        by_batch[log.batch_id].append(log)
        expected_prev = log.current_hash

    # 2. sealed batches: numbering, seal chain links, ranges, Merkle roots
    expected_prev_seal = cc.GENESIS_SEAL
    for i, root in enumerate(roots, start=1):
        b = root.batch_id
        if b != i:
            p.add("missing_batch", f"expected sealed batch {i}, found {b}", batch_id=b)
        if root.previous_seal != expected_prev_seal:
            p.add("seal_link", "previous_seal does not match the batch before it", batch_id=b)
        if root.key_version != b:
            p.add("key_version", "key_version differs from batch id", batch_id=b)
        batch_logs = by_batch.get(b, [])
        ids = [l.id for l in batch_logs]
        if (len(ids) != root.total_logs or not ids
                or ids[0] != root.first_log_id or ids[-1] != root.last_log_id):
            p.add("batch_range", "logs in this batch were added or removed after sealing", batch_id=b)
        if build_merkle_root([l.current_hash for l in batch_logs]) != root.root_hash:
            p.add("merkle_root", "recomputed Merkle root differs from sealed root", batch_id=b)
        expected_prev_seal = root.seal

    # 3. open batch: key state and MACs (the server still has this key)
    ob = (roots[-1].batch_id if roots else 0) + 1
    key, kv = km.current_key()
    for b in by_batch:
        if b > ob:
            p.add("orphan_batch", f"logs claim batch {b} but the open batch is {ob}", batch_id=b)
    if kv > ob:
        p.add("seal_records_missing",
              f"key is at version {kv} but only {ob - 1} sealed batches exist")
    elif kv == ob:
        for log in by_batch.get(ob, []):
            if not cc.constant_time_equal(cc.log_mac(key, log.current_hash), log.mac):
                p.add("mac", "HMAC of an open-batch log is wrong", log_id=log.id)

    return {
        "status": "Valid" if p.count == 0 else "Tampered",
        "total_logs_verified": len(logs),
        "sealed_batches": len(roots),
        "open_batch_id": ob,
        "open_batch_logs": len(by_batch.get(ob, [])),
        "problems_found": p.count,
        "problems": p.items,
        "checks": [
            "hash chain links", "log content hashes", "sealed batch numbering",
            "seal chain links", "sealed batch log ranges", "Merkle roots",
            "key version vs sealed batches", "HMACs of open-batch logs",
        ],
        "note": AUDITOR_NOTE,
    }


def verify_batch(db: Session, batch_id: int) -> dict:
 def verify_all_consistent(db: Session) -> dict:
    """verify_all while no log is being written or sealed, so the check never
    sees half of a seal (which could cause a false "Tampered")."""
    with _write_lock:
        db.expire_all()
        return verify_all(db)
    root = db.query(MerkleRoot).filter(MerkleRoot.batch_id == batch_id).first()
    if not root:
        return {"status": "Not Found", "message": f"Batch {batch_id} is not sealed yet"}

    logs = db.query(Log).filter(Log.batch_id == batch_id).order_by(Log.id.asc()).all()
    problems = []
    ids = [l.id for l in logs]
    if (len(ids) != root.total_logs or not ids
            or ids[0] != root.first_log_id or ids[-1] != root.last_log_id):
        problems.append("logs were added to or removed from this batch after sealing")
    for log in logs:
        if cc.entry_hash(log_payload(log), log.previous_hash) != log.current_hash:
            problems.append(f"log {log.id}: content does not match its hash")
    recalculated = build_merkle_root([l.current_hash for l in logs])
    if recalculated != root.root_hash:
        problems.append("recomputed Merkle root differs from sealed root")

    prev = db.query(MerkleRoot).filter(MerkleRoot.batch_id == batch_id - 1).first()
    expected_prev_seal = prev.seal if prev else cc.GENESIS_SEAL
    if batch_id > 1 and not prev:
        problems.append(f"previous batch {batch_id - 1} is missing")
    elif root.previous_seal != expected_prev_seal:
        problems.append("seal chain broken: previous_seal does not match")

    return {
        "status": "Valid" if not problems else "Tampered",
        "batch_id": batch_id,
        "root_hash": root.root_hash,
        "recalculated_root": recalculated,
        "total_logs_verified": len(logs),
        "problems": problems,
        "note": AUDITOR_NOTE,
    }


# ---------------------------------------------------------------- Merkle extras
def merkle_proof(db: Session, log_id: int) -> dict:
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        return {"status": "Not Found", "message": f"Log {log_id} not found"}
    root = db.query(MerkleRoot).filter(MerkleRoot.batch_id == log.batch_id).first()
    if not root:
        return {"status": "Open Batch",
                "message": f"Log {log_id} is in batch {log.batch_id}, which is not sealed yet"}

    hashes = [l.current_hash for l in
              db.query(Log).filter(Log.batch_id == log.batch_id).order_by(Log.id.asc())]
    index = hashes.index(log.current_hash)
    proof = inclusion_proof(hashes, index)
    recomputed = cc.entry_hash(log_payload(log), log.previous_hash)
    return {
        "status": "Included" if verify_inclusion(recomputed, proof, root.root_hash) else "Not Included",
        "log_id": log_id,
        "batch_id": log.batch_id,
        "leaf_index": index,
        "entry_hash": recomputed,
        "proof": proof,
        "proof_length": len(proof),
        "root_hash": root.root_hash,
        "explanation": "Hashing the entry with each sibling in order must give the sealed root. "
                       "This proves one log is in the batch without reading the other logs.",
    }


def merkle_tree(db: Session, batch_id: int) -> dict:
    hashes = [l.current_hash for l in
              db.query(Log).filter(Log.batch_id == batch_id).order_by(Log.id.asc())]
    return {"batch_id": batch_id, "levels": tree_for_display(hashes)}


# ---------------------------------------------------------------- demo attacks
def simulate_tamper(db: Session, log_id: int) -> dict:
    """Careless attacker: edits a message and does nothing else."""
    log = db.query(Log).filter(Log.id == log_id).first()
    if not log:
        return {"status": "Not Found", "message": f"Log {log_id} not found"}
    old = log.message
    log.message = old + " [TAMPERED]"
    db.commit()
    return {"status": "Tampering Simulated", "attack": "edit only",
            "log_id": log_id, "old_message": old, "new_message": log.message,
            "expected_result": "Server verification detects it (content hash mismatch)."}


def simulate_rewrite(db: Session, log_id: int) -> dict:
    """
    Smart attacker with database access but WITHOUT the secret key:
    edits a log, recomputes every public hash after it and every affected
    Merkle root. MACs and seals cannot be recomputed without the key.
    """
    with _write_lock:
        target = db.query(Log).filter(Log.id == log_id).first()
        if not target:
            return {"status": "Not Found", "message": f"Log {log_id} not found"}
        old = target.message
        target.message = "Nothing suspicious happened here"

        logs = db.query(Log).filter(Log.id >= log_id).order_by(Log.id.asc()).all()
        prev = target.previous_hash
        for log in logs:
            log.previous_hash = prev
            log.current_hash = cc.entry_hash(log_payload(log), prev)
            prev = log.current_hash

        affected = sorted({l.batch_id for l in logs})
        for root in db.query(MerkleRoot).filter(MerkleRoot.batch_id.in_(affected)):
            hashes = [l.current_hash for l in db.query(Log)
                      .filter(Log.batch_id == root.batch_id).order_by(Log.id.asc())]
            root.root_hash = build_merkle_root(hashes)
        db.commit()

    return {
        "status": "Rewrite Simulated",
        "attack": "edit + recompute all public hashes and Merkle roots",
        "log_id": log_id,
        "old_message": old,
        "logs_rewritten": len(logs),
        "expected_result": (
            "If the open batch has logs, the server detects it (their HMACs break). "
            "If every affected log is sealed, the server check passes, but the auditor "
            "detects it because the seals no longer match."
        ),
    }


# ---------------------------------------------------------------- stats
def stats(db: Session) -> dict:
    result = verify_all(db)
    last = last_sealed(db)
    latest_log = db.query(Log).order_by(Log.id.desc()).first()
    key_state = km.public_state()
    return {
        "total_logs": db.query(Log).count(),
        "total_merkle_roots": db.query(MerkleRoot).count(),
        "latest_batch_id": last.batch_id if last else None,   # last SEALED batch
        "latest_merkle_root": last.root_hash if last else None,
        "open_batch_id": result["open_batch_id"],
        "open_batch_logs": result["open_batch_logs"],
        "batch_size": BATCH_SIZE,
        "latest_log_id": latest_log.id if latest_log else None,
        "key_version": key_state["key_version"],
        "integrity_status": result["status"],
        "problems_found": result["problems_found"],
    }

def verify_all_consistent(db: Session) -> dict:
    """verify_all while no log is being written or sealed, so the check never
    sees half of a seal (which could cause a false "Tampered")."""
    with _write_lock:
        db.expire_all()
        return verify_all(db)

def seal_if_older_than(db: Session, max_age_seconds: int):
    """Time-based sealing: seal the open batch once its OLDEST log has waited
    max_age_seconds, even if the batch is not full. This limits how long any
    log stays in the open batch, where only the current key protects it."""
    if max_age_seconds <= 0:
        return None
    with _write_lock:
        sync_key(db)
        _, kv = km.current_key()
        oldest = db.query(Log).filter(Log.batch_id == kv).order_by(Log.id.asc()).first()
        if oldest is None:
            return None
        if (utcnow() - oldest.timestamp).total_seconds() < max_age_seconds:
            return None
        return _seal_locked(db)

SERVER_AGENT = "securelog-server"

def seal_open_batch(db: Session):
    """Seal the open batch now (even if it has fewer than BATCH_SIZE logs)."""
    with _write_lock:
        return _seal_locked(db)