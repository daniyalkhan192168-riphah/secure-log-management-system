#!/usr/bin/env python3
"""
Attack lab: runs every attack scenario against a fresh, temporary ledger and
prints a DETECTION MATRIX (attack -> detected by server? by auditor?).

It never touches your real database or keys.

    cd backend
    python ../scripts/attack_lab.py              # prints the table
    python ../scripts/attack_lab.py --out attack_results.md

Each attack is done the way a real attacker would: by editing the SQLite file
directly with SQL, bypassing the application.
"""
import argparse
import contextlib
import io
import os
import shutil
import sqlite3
import sys
import tempfile
import time

# Windows consoles/pipes default to a legacy encoding that cannot print ✅.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TMP = tempfile.mkdtemp(prefix="securelog_attacklab_")
os.environ["SECURELOG_DATABASE_URL"] = "sqlite:///" + os.path.join(TMP, "lab.db")
os.environ["SECURELOG_KEY_DIR"] = os.path.join(TMP, "keys")
os.environ["SECURELOG_BATCH_SIZE"] = "10"
os.environ["SECURELOG_ENV_FILE"] = os.path.join(TMP, "none.env")

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(os.path.dirname(HERE), "backend")
sys.path.insert(0, BACKEND)
sys.path.insert(0, HERE)

from database import Base, engine, SessionLocal          # noqa: E402
from models import Log, MerkleRoot                        # noqa: E402
from services import ledger, key_manager as km            # noqa: E402
from services import crypto_core as cc                    # noqa: E402
from services.merkle_service import build_merkle_root     # noqa: E402
import auditor_verify                                     # noqa: E402

DB_FILE = os.path.join(TMP, "lab.db")


def fresh_ledger(n_logs: int):
    engine.dispose()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    shutil.rmtree(os.environ["SECURELOG_KEY_DIR"], ignore_errors=True)
    with contextlib.redirect_stdout(io.StringIO()):
        km.initialize()
    db = SessionLocal()
    for i in range(n_logs):
        ledger.append_log(db, {
            "source": "securelog:sshd", "event_type": "AUTH_FAILED",
            "username": f"user{i}", "ip_address": f"10.0.0.{i % 250}",
            "message": f"Failed password for user{i} from 10.0.0.{i % 250} port 22 ssh2",
        }, agent_id="ubuntu-vm")
    db.close()


def sql(statement: str, *params):
    con = sqlite3.connect(DB_FILE)
    con.execute(statement, params)
    con.commit()
    con.close()


def k0() -> bytes:
    with open(km.K0_EXPORT_FILE) as f:
        return bytes.fromhex(f.read().strip())


def check():
    db = SessionLocal()
    server = ledger.verify_all(db)
    db.close()
    audit = auditor_verify.audit(DB_FILE, k0())
    return server, audit


def recompute_public_hashes(db, from_id=1):
    """What an attacker WITHOUT the key can do."""
    target = db.query(Log).filter(Log.id >= from_id).order_by(Log.id).all()
    prev = cc.GENESIS_HASH
    before = db.query(Log).filter(Log.id < from_id).order_by(Log.id.desc()).first()
    if before:
        prev = before.current_hash
    for l in target:
        l.previous_hash = prev
        l.current_hash = cc.entry_hash(ledger.log_payload(l), prev)
        prev = l.current_hash
    for r in db.query(MerkleRoot):
        hashes = [l.current_hash for l in
                  db.query(Log).filter(Log.batch_id == r.batch_id).order_by(Log.id)]
        r.root_hash = build_merkle_root(hashes)
    db.commit()

def resign_everything(db, key: bytes):
    """What an attacker WITH a stolen key can do."""
    for l in db.query(Log).order_by(Log.id):
        l.mac = cc.log_mac(key, l.current_hash)
    prev_seal = cc.GENESIS_SEAL
    for r in db.query(MerkleRoot).order_by(MerkleRoot.batch_id):
        r.previous_seal = prev_seal
        header = cc.batch_header(r.batch_id, r.first_log_id, r.last_log_id, r.total_logs,
                                 r.root_hash, prev_seal, r.key_version)
        r.seal = cc.batch_seal(key, header)
        prev_seal = r.seal
    db.commit()


def a_edit_message():
    fresh_ledger(25)
    sql("UPDATE logs SET message = 'nothing happened' WHERE id = 5")
    return "Edit one log's message directly in the database"


def a_change_ip():
    fresh_ledger(25)
    sql("UPDATE logs SET ip_address = '127.0.0.1' WHERE id = 7")
    return "Change the attacker's IP address in a log"


def a_change_agent():
    fresh_ledger(25)
    sql("UPDATE logs SET agent_id = 'other-server' WHERE id = 8")
    return "Change which machine a log came from (agent_id)"


def a_change_time():
    fresh_ledger(25)
    sql("UPDATE logs SET timestamp = '2020-01-01 00:00:00.000000' WHERE id = 9")
    return "Back-date a log's timestamp"


def a_delete_middle():
    fresh_ledger(25)
    sql("DELETE FROM logs WHERE id = 6")
    return "Delete one log from a sealed batch"


def a_insert_fake():
    fresh_ledger(25)
    sql("""INSERT INTO logs (id, timestamp, source, event_type, username, ip_address, message,
           agent_id, previous_hash, current_hash, mac, batch_id)
           SELECT 1000, timestamp, source, 'AUTH_SUCCESS', 'admin', ip_address, 'login ok',
                  agent_id, current_hash, current_hash, mac, 1 FROM logs WHERE id = 5""")
    return "Insert a fake log into a sealed batch"


def a_swap_order():
    fresh_ledger(25)
    con = sqlite3.connect(DB_FILE)
    a = con.execute("SELECT message FROM logs WHERE id=3").fetchone()[0]
    b = con.execute("SELECT message FROM logs WHERE id=4").fetchone()[0]
    con.execute("UPDATE logs SET message=? WHERE id=3", (b,))
    con.execute("UPDATE logs SET message=? WHERE id=4", (a,))
    con.commit()
    con.close()
    return "Swap the contents of two logs (reorder events)"


def a_forge_root():
    fresh_ledger(25)
    sql("UPDATE merkle_roots SET root_hash = ? WHERE batch_id = 1", "ab" * 32)
    return "Replace a sealed Merkle root"


def a_delete_batch():
    fresh_ledger(25)
    sql("DELETE FROM logs WHERE batch_id = 2")
    sql("DELETE FROM merkle_roots WHERE batch_id = 2")
    return "Delete the newest sealed batch (logs + root)"


def a_rewrite_open():
    fresh_ledger(25)
    db = SessionLocal()
    db.query(Log).filter(Log.id == 3).one().message = "nothing happened"
    recompute_public_hashes(db, 3)
    db.close()
    return "Edit a log and recompute all public hashes and roots (no key)"


def a_rewrite_sealed_only():
    fresh_ledger(20)
    db = SessionLocal()
    db.query(Log).filter(Log.id == 3).one().message = "nothing happened"
    recompute_public_hashes(db, 3)
    db.close()
    return "Same rewrite, when every log is already sealed (no key)"


def a_stolen_key_old():
    fresh_ledger(25)
    stolen, _ = km.current_key()
    db = SessionLocal()
    db.query(Log).filter(Log.id == 2).one().message = "nothing happened"
    recompute_public_hashes(db, 2)
    resign_everything(db, stolen)
    db.close()
    return "Steal the CURRENT key, rewrite an OLD batch and re-sign everything"


def a_stolen_key_open():
    fresh_ledger(25)
    stolen, _ = km.current_key()
    db = SessionLocal()
    db.query(Log).filter(Log.id == 23).one().message = "nothing happened"
    recompute_public_hashes(db, 23)
    for l in db.query(Log).filter(Log.batch_id == 3):
        l.mac = cc.log_mac(stolen, l.current_hash)
    db.commit()
    db.close()
    return "Steal the current key and rewrite the OPEN (unsealed) batch"


def a_truncate_open():
    fresh_ledger(25)
    sql("DELETE FROM logs WHERE id > 22")
    return "Delete the newest logs of the open batch"


ATTACKS = [
    (a_edit_message, True, True, ""),
    (a_change_ip, True, True, ""),
    (a_change_agent, True, True, ""),
    (a_change_time, True, True, ""),
    (a_swap_order, True, True, ""),
    (a_delete_middle, True, True, ""),
    (a_insert_fake, True, True, ""),
    (a_forge_root, True, True, ""),
    (a_delete_batch, True, True, "server refuses new writes"),
    (a_rewrite_open, True, True, "open-batch HMACs break"),
    (a_rewrite_sealed_only, False, True, "only the auditor's seals catch it"),
    (a_stolen_key_old, False, True, "forward security: old keys are gone"),
    (a_stolen_key_open, False, False, "limitation: open batch (time sealing limits it to 10 min)"),
    (a_truncate_open, False, False, "limitation: open batch (time sealing limits it to 10 min)"),
]


def main():
    ap = argparse.ArgumentParser(description="Run all attacks and print a detection matrix")
    ap.add_argument("--out", help="also write the table to this Markdown file")
    args = ap.parse_args()

    rows, unexpected = [], 0
    started = time.time()
    for fn, exp_server, exp_auditor, note in ATTACKS:
        description = fn()
        server, audit = check()
        s_det = server["status"] != "Valid"
        a_det = audit["status"] != "VALID"
        types = sorted({p["type"] for p in server["problems"]} | {p["type"] for p in audit["problems"]})
        ok = (s_det, a_det) == (exp_server, exp_auditor)
        unexpected += not ok
        rows.append((description, s_det, a_det, ", ".join(types) or "-", note, ok))
        print(f"{'OK ' if ok else 'UNEXPECTED'} {description}")

    yes = lambda b: "✅ Detected" if b else "❌ Not detected"
    lines = [
        "| # | Attack | Server check | Auditor (K0) | Evidence | Note |",
        "|---|---|---|---|---|---|",
    ]
    for i, (d, s, a, t, n, _) in enumerate(rows, 1):
        lines.append(f"| {i} | {d} | {yes(s)} | {yes(a)} | {t} | {n} |")
    detected = sum(1 for r in rows if r[1] or r[2])
    summary = (f"\n{detected} of {len(rows)} attacks detected. The {len(rows) - detected} "
               "undetected ones are the documented limitations of the open (unsealed) batch.\n"
               f"Ran in {time.time() - started:.1f} s. "
               f"{'All results as expected.' if not unexpected else f'{unexpected} UNEXPECTED result(s)!'}")
    table = "\n".join(lines) + "\n" + summary

    print("\n" + table)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("# Attack detection matrix\n\n" + table + "\n")
        print(f"\nSaved to {args.out}")

    engine.dispose()
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if unexpected else 0)


if __name__ == "__main__":
    main()
