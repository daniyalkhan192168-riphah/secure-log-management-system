"""
Security tests for the tamper-evident log. Each test is one attack scenario
(good material for the Results chapter).

Run from the backend folder:
    python -m pytest tests -v        (if pytest is installed)
    python tests/test_security.py    (plain Python, no extra packages)
"""
import contextlib
import io
import os
import shutil
import sqlite3
import sys
import tempfile

# Isolated database + key folder; must be set BEFORE importing the backend.
TMP = tempfile.mkdtemp(prefix="securelog_test_")
os.environ["SECURELOG_DATABASE_URL"] = "sqlite:///" + os.path.join(TMP, "test.db")
os.environ["SECURELOG_KEY_DIR"] = os.path.join(TMP, "keys")
os.environ["SECURELOG_BATCH_SIZE"] = "10"

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))                                   # backend/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts"))

from database import Base, engine, SessionLocal          # noqa: E402
from models import Log, MerkleRoot                        # noqa: E402
from services import ledger, key_manager as km            # noqa: E402
from services import crypto_core as cc                    # noqa: E402
from services.merkle_service import (                     # noqa: E402
    build_merkle_root, inclusion_proof, verify_inclusion,
)
import auditor_verify                                     # noqa: E402

DB_FILE = os.path.join(TMP, "test.db")


# ------------------------------------------------------------ helpers
def reset():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    shutil.rmtree(os.environ["SECURELOG_KEY_DIR"], ignore_errors=True)
    with contextlib.redirect_stdout(io.StringIO()):
        km.initialize()


def k0():
    with open(km.K0_EXPORT_FILE) as f:
        return bytes.fromhex(f.read().strip())


def add_logs(db, n, start=0):
    for i in range(start, start + n):
        ledger.append_log(db, {
            "source": "Ubuntu-test", "event_type": "AUTH_FAILED",
            "username": f"user{i}", "ip_address": "10.0.0.1",
            "message": f"Failed password for user{i}",
        }, agent_id="test-agent")


def server(db):
    return ledger.verify_all(db)


def auditor():
    return auditor_verify.audit(DB_FILE, k0())


def types(report):
    return {p["type"] for p in report["problems"]}


def raw_sql(sql, *params):
    con = sqlite3.connect(DB_FILE)
    con.execute(sql, params)
    con.commit()
    con.close()


# ------------------------------------------------------------ normal operation
def test_clean_log_is_valid_everywhere():
    reset()
    db = SessionLocal()
    add_logs(db, 25)                       # batch size 10 -> 2 sealed + 5 open
    assert db.query(MerkleRoot).count() == 2
    assert ledger.open_batch_id(db) == 3
    assert km.current_key()[1] == 3
    assert server(db)["status"] == "Valid"
    assert auditor()["status"] == "VALID"
    db.close()


def test_secret_key_never_in_public_state():
    reset()
    state = km.public_state()
    assert "key" not in state and "k0_fingerprint" in state
    assert state["k0_fingerprint"] == cc.k0_fingerprint(k0())


def test_key_evolution_is_forward_only():
    reset()
    db = SessionLocal()
    add_logs(db, 10)                       # seals batch 1 -> key 2
    key2, v = km.current_key()
    assert v == 2 and key2 == cc.derive_key(k0(), 2) and key2 != k0()
    try:
        km.evolve_to(1)
        assert False, "key moved backwards"
    except km.KeyStateError:
        pass
    db.close()


# ------------------------------------------------------------ attacks
def test_careless_edit_detected():
    reset()
    db = SessionLocal()
    add_logs(db, 15)
    ledger.simulate_tamper(db, 3)
    assert "content_hash" in types(server(db))
    assert auditor()["status"] == "TAMPERED"
    db.close()


def test_rewrite_attack_detected_by_server_when_open_batch_has_logs():
    reset()
    db = SessionLocal()
    add_logs(db, 15)                       # batch 1 sealed, 5 logs open
    ledger.simulate_rewrite(db, 3)
    assert "mac" in types(server(db))      # open-batch HMACs break
    assert auditor()["status"] == "TAMPERED"
    db.close()


def test_rewrite_attack_on_sealed_data_only_caught_by_auditor():
    """THE attack the old design missed: recompute every public hash + root."""
    reset()
    db = SessionLocal()
    add_logs(db, 20)                       # 2 sealed batches, open batch empty
    ledger.simulate_rewrite(db, 3)
    assert server(db)["status"] == "Valid"          # server cannot tell
    report = auditor()
    assert report["status"] == "TAMPERED"
    assert {"mac", "seal"} <= types(report)
    db.close()


def test_deleting_log_from_sealed_batch_detected():
    reset()
    db = SessionLocal()
    add_logs(db, 15)
    db.close()
    raw_sql("DELETE FROM logs WHERE id = 5")
    db = SessionLocal()
    t = types(server(db))
    assert "chain_link" in t and "batch_range" in t
    db.close()


def test_deleting_whole_last_sealed_batch_detected():
    reset()
    db = SessionLocal()
    add_logs(db, 20)                       # batches 1, 2 sealed; key at 3
    db.close()
    raw_sql("DELETE FROM logs WHERE batch_id = 2")
    raw_sql("DELETE FROM merkle_roots WHERE batch_id = 2")
    db = SessionLocal()
    assert "seal_records_missing" in types(server(db))
    try:                                   # server refuses to keep writing
        add_logs(db, 1)
        assert False, "append should be refused"
    except km.KeyStateError:
        pass
    db.close()


def test_forged_merkle_root_detected():
    reset()
    db = SessionLocal()
    add_logs(db, 10)
    db.close()
    raw_sql("UPDATE merkle_roots SET root_hash = ? WHERE batch_id = 1", "ab" * 32)
    db = SessionLocal()
    assert "merkle_root" in types(server(db))
    assert "seal" in types(auditor())
    db.close()


def test_stolen_current_key_cannot_forge_old_batches():
    """Attacker steals the key while batch 3 is open and rewrites batch 1."""
    reset()
    db = SessionLocal()
    add_logs(db, 25)
    stolen_key, v = km.current_key()
    assert v == 3

    log = db.query(Log).filter(Log.id == 2).first()
    log.message = "harmless"
    # recompute everything, re-MAC every log and re-seal every batch with the stolen key
    prev = cc.GENESIS_HASH
    for l in db.query(Log).order_by(Log.id):
        l.previous_hash = prev
        l.current_hash = cc.entry_hash(ledger.log_payload(l), prev)
        l.mac = cc.log_mac(stolen_key, l.current_hash)
        prev = l.current_hash
    prev_seal = cc.GENESIS_SEAL
    for r in db.query(MerkleRoot).order_by(MerkleRoot.batch_id):
        hashes = [l.current_hash for l in db.query(Log).filter(Log.batch_id == r.batch_id).order_by(Log.id)]
        r.root_hash = build_merkle_root(hashes)
        r.previous_seal = prev_seal
        header = cc.batch_header(r.batch_id, r.first_log_id, r.last_log_id, r.total_logs,
                                 r.root_hash, prev_seal, r.key_version)
        r.seal = cc.batch_seal(stolen_key, header)
        prev_seal = r.seal
    db.commit()

    report = auditor()
    assert report["status"] == "TAMPERED"
    bad_batches = {p.get("batch_id") for p in report["problems"] if p["type"] in ("mac", "seal")}
    assert 1 in bad_batches and 2 in bad_batches     # pre-compromise batches exposed
    db.close()


def test_known_limitation_open_batch_tail_truncation():
    """Documented limitation: dropping the newest UNSEALED logs is not
    detectable without an external anchor. Sealing often limits the damage."""
    reset()
    db = SessionLocal()
    add_logs(db, 15)
    db.close()
    raw_sql("DELETE FROM logs WHERE id > 12")
    db = SessionLocal()
    assert server(db)["status"] == "Valid"
    assert auditor()["status"] == "VALID"
    db.close()


# ------------------------------------------------------------ robustness
def test_crash_between_seal_commit_and_key_evolution_recovers():
    reset()
    db = SessionLocal()
    add_logs(db, 5)
    original = km.evolve_to
    km.evolve_to = lambda v: None          # simulate crash right after commit
    try:
        ledger.seal_open_batch(db)
    finally:
        km.evolve_to = original
    assert km.current_key()[1] == 1        # key not yet evolved
    add_logs(db, 3, start=5)               # sync_key catches up automatically
    assert km.current_key()[1] == 2
    assert server(db)["status"] == "Valid"
    assert auditor()["status"] == "VALID"
    db.close()


def test_merkle_proofs_all_sizes():
    for n in range(1, 18):
        hashes = [cc.entry_hash({"i": i}, cc.GENESIS_HASH) for i in range(n)]
        root = build_merkle_root(hashes)
        for i in range(n):
            proof = inclusion_proof(hashes, i)
            assert verify_inclusion(hashes[i], proof, root)
            assert not verify_inclusion(hashes[(i + 1) % n], proof, root) or n == 1


def test_merkle_no_duplicate_leaf_ambiguity():
    h = [cc.entry_hash({"i": i}, cc.GENESIS_HASH) for i in range(3)]
    assert build_merkle_root(h) != build_merkle_root(h + [h[-1]])


def test_agent_identity_is_protected():
    """Changing WHO sent a log (agent_id) is tampering too."""
    reset()
    db = SessionLocal()
    add_logs(db, 15)
    db.close()
    raw_sql("UPDATE logs SET agent_id = 'other-agent' WHERE id = 12")
    db = SessionLocal()
    assert "content_hash" in types(server(db))
    assert auditor()["status"] == "TAMPERED"
    db.close()


def test_event_time_is_protected_and_normalised_to_utc():
    from datetime import datetime, timedelta, timezone
    reset()
    db = SessionLocal()
    pk = timezone(timedelta(hours=5))                     # a source in UTC+5
    log = ledger.append_log(db, {"source": "s", "event_type": "E", "username": "u",
                                 "ip_address": "1.1.1.1", "message": "m",
                                 "event_time": datetime(2026, 10, 19, 10, 0, tzinfo=pk)},
                            agent_id="a")
    assert log.event_time == datetime(2026, 10, 19, 5, 0)   # stored as UTC
    assert server(db)["status"] == "Valid" and auditor()["status"] == "VALID"
    db.close()
    raw_sql("UPDATE logs SET event_time = '2026-01-01 00:00:00.000000' WHERE id = ?", log.id)
    db = SessionLocal()
    assert "content_hash" in types(server(db))
    assert auditor()["status"] == "TAMPERED"
    db.close()


def test_time_based_sealing():
    reset()
    db = SessionLocal()
    add_logs(db, 3)                                        # open batch, not full
    assert ledger.seal_if_older_than(db, 3600) is None     # too young: stays open
    assert ledger.seal_if_older_than(db, 0) is None        # 0 = feature switched off
    row = ledger.seal_if_older_than(db, 1e-6)              # old enough: sealed
    assert row.batch_id == 1 and row.total_logs == 3
    assert km.current_key()[1] == 2                        # key evolved
    assert ledger.seal_if_older_than(db, 1e-6) is None     # nothing left to seal
    add_logs(db, 2, start=3)
    assert server(db)["status"] == "Valid" and auditor()["status"] == "VALID"
    db.close()


def test_time_based_sealing_with_waiting_logs_is_race_free():
    """Writers and the time-based sealer run at the same time: no log may be
    lost, duplicated, or left in an inconsistent batch."""
    import threading
    reset()
    done = threading.Event()

    def writer():
        d = SessionLocal()
        add_logs(d, 120)
        d.close()
        done.set()

    t = threading.Thread(target=writer)
    t.start()
    sealer = SessionLocal()
    while not done.is_set():
        ledger.seal_if_older_than(sealer, 1e-6)
    t.join()
    sealer.close()
    db = SessionLocal()
    assert db.query(Log).count() == 120
    assert server(db)["status"] == "Valid" and auditor()["status"] == "VALID"
    db.close()


def test_server_events_go_into_the_ledger():
    reset()
    db = SessionLocal()
    log = ledger.record_server_event(db, "DASHBOARD_LOGIN_FAILED", "admin", "1.2.3.4", "bad password")
    assert log.agent_id == ledger.SERVER_AGENT and log.event_type == "DASHBOARD_LOGIN_FAILED"
    assert server(db)["status"] == "Valid"
    db.close()


def test_proof_endpoint_logic():
    reset()
    db = SessionLocal()
    add_logs(db, 13)
    assert ledger.merkle_proof(db, 7)["status"] == "Included"
    assert ledger.merkle_proof(db, 12)["status"] == "Open Batch"
    ledger.simulate_tamper(db, 7)
    assert ledger.merkle_proof(db, 7)["status"] == "Not Included"
    db.close()


def test_verify_single_batch():
    """The dashboard's per-batch Verify button (GET /merkle/verify/{id})."""
    reset()
    db = SessionLocal()
    add_logs(db, 23)                       # batches 1 and 2 sealed, 3 open
    assert ledger.verify_batch(db, 1)["status"] == "Valid"
    assert ledger.verify_batch(db, 2)["status"] == "Valid"
    assert ledger.verify_batch(db, 3)["status"] == "Not Found"
    ledger.simulate_tamper(db, 15)
    assert ledger.verify_batch(db, 2)["status"] == "Tampered"
    assert ledger.verify_batch(db, 1)["status"] == "Valid"
    db.close()


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
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if failed else 0)
