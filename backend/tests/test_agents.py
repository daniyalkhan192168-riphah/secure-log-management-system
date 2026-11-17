"""
Agent heartbeat, silence detection and rollback-witness tests.

Run from the backend folder:  python tests/test_agents.py
"""
import contextlib
import io
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import timedelta

TMP = tempfile.mkdtemp(prefix="securelog_agents_")
os.environ["SECURELOG_DATABASE_URL"] = "sqlite:///" + os.path.join(TMP, "test.db")
os.environ["SECURELOG_KEY_DIR"] = os.path.join(TMP, "keys")
os.environ["SECURELOG_BATCH_SIZE"] = "10"
os.environ["SECURELOG_ENV_FILE"] = os.path.join(TMP, "none.env")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import config                                             # noqa: E402
from database import Base, engine, SessionLocal          # noqa: E402
from models import Alert, AgentStatus, Log                # noqa: E402
from services import agents, ledger, key_manager as km    # noqa: E402
from services.auth import hash_agent_key                  # noqa: E402

DB_FILE = os.path.join(TMP, "test.db")


def reset():
    engine.dispose()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    shutil.rmtree(os.environ["SECURELOG_KEY_DIR"], ignore_errors=True)
    with contextlib.redirect_stdout(io.StringIO()):
        km.initialize()


def add_logs(db, n):
    for i in range(n):
        ledger.append_log(db, {"source": "s", "event_type": "E", "username": "u",
                               "ip_address": "1.1.1.1", "message": f"m{i}"}, agent_id="vm1")


def beat(db, **kw):
    data = {"hostname": "securelog", "version": "2.1", "spool_size": 0,
            "uptime_seconds": 1, "witness": None, "stopping": False}
    data.update(kw)
    with contextlib.redirect_stdout(io.StringIO()):
        return agents.heartbeat(db, "vm1", "192.168.56.101", data)


def events(db, event_type):
    return db.query(Log).filter(Log.event_type == event_type).count()


def alerts(db, alert_type):
    return db.query(Alert).filter(Alert.alert_type == alert_type).count()


def test_first_heartbeat_registers_agent():
    reset()
    db = SessionLocal()
    reply = beat(db)
    row = db.query(AgentStatus).one()
    assert row.status == "online" and row.hostname == "securelog"
    assert events(db, "AGENT_ONLINE") == 1
    assert reply["latest_seal"] is None
    beat(db)
    assert events(db, "AGENT_ONLINE") == 1              # no event for routine heartbeats
    assert ledger.verify_all(db)["status"] == "Valid"
    db.close()


def test_stop_and_return():
    reset()
    db = SessionLocal()
    beat(db)
    beat(db, stopping=True)
    assert db.query(AgentStatus).one().status == "stopped"
    assert alerts(db, "AGENT_STOPPED") == 1 and events(db, "AGENT_STOPPED") == 1
    beat(db)
    assert db.query(AgentStatus).one().status == "online"
    assert events(db, "AGENT_ONLINE") == 2              # first contact + back online
    recovery = db.query(Alert).filter(Alert.alert_type == "AGENT_ONLINE").one()
    assert recovery.severity == "info" and "back online" in recovery.description
    db.close()


def test_silent_agent_alerts_once():
    reset()
    db = SessionLocal()
    beat(db)
    row = db.query(AgentStatus).one()
    row.last_seen = ledger.utcnow() - timedelta(minutes=10)
    db.commit()
    with contextlib.redirect_stdout(io.StringIO()):
        assert agents.check_silent(db, 180) == ["vm1"]
        assert agents.check_silent(db, 180) == []         # already silent: no second alert
    assert alerts(db, "AGENT_SILENT") == 1 and events(db, "AGENT_SILENT") == 1
    beat(db)                                              # comes back
    assert db.query(AgentStatus).one().status == "online"
    db.close()


def test_recent_heartbeat_is_not_silent():
    reset()
    db = SessionLocal()
    beat(db)
    with contextlib.redirect_stdout(io.StringIO()):
        assert agents.check_silent(db, 180) == []
    db.close()


def test_rollback_of_database_and_key_detected_once():
    """The realistic insider attack: restore an old backup of BOTH files."""
    reset()
    db = SessionLocal()
    add_logs(db, 15)                                      # batch 1 sealed
    db.close()
    engine.dispose()
    shutil.copy(DB_FILE, DB_FILE + ".bak")                # the insider's backup
    shutil.copy(km.KEY_FILE, km.KEY_FILE + ".bak")

    db = SessionLocal()
    add_logs(db, 20)                                      # batches 2, 3 sealed later
    witness = beat(db)["latest_seal"]
    assert witness["batch_id"] == 3
    db.close()
    engine.dispose()

    shutil.copy(DB_FILE + ".bak", DB_FILE)                # restore both: hides batches 2-3
    shutil.copy(km.KEY_FILE + ".bak", km.KEY_FILE)
    db = SessionLocal()
    assert ledger.verify_all(db)["status"] == "Valid"     # the server alone is fooled
    reply = beat(db, witness=witness)
    assert reply["latest_seal"]["batch_id"] == 1
    assert alerts(db, "ROLLBACK_DETECTED") == 1
    assert events(db, "ROLLBACK_DETECTED") == 1           # also recorded in the ledger
    beat(db, witness=witness)                             # still rolled back: no duplicate
    assert alerts(db, "ROLLBACK_DETECTED") == 1
    db.close()


def test_rollback_of_database_only_detected():
    reset()
    db = SessionLocal()
    add_logs(db, 25)                                      # batches 1, 2 sealed
    witness = beat(db)["latest_seal"]
    db.close()
    con = sqlite3.connect(DB_FILE)
    con.execute("DELETE FROM logs WHERE batch_id >= 2")
    con.execute("DELETE FROM merkle_roots WHERE batch_id = 2")
    con.commit()
    con.close()
    db = SessionLocal()
    beat(db, witness=witness)
    assert alerts(db, "ROLLBACK_DETECTED") == 1
    assert "seal_records_missing" in {p["type"] for p in ledger.verify_all(db)["problems"]}
    db.close()


def test_forged_seal_detected():
    reset()
    db = SessionLocal()
    add_logs(db, 15)                                      # batch 1 sealed
    witness = beat(db)["latest_seal"]
    db.close()
    con = sqlite3.connect(DB_FILE)
    con.execute("UPDATE merkle_roots SET seal = ? WHERE batch_id = 1", ("cd" * 32,))
    con.commit()
    con.close()
    db = SessionLocal()
    beat(db, witness=witness)
    assert alerts(db, "SEAL_MISMATCH") == 1
    db.close()


def test_honest_server_never_alerts():
    reset()
    db = SessionLocal()
    witness = None
    for _ in range(4):
        add_logs(db, 10)
        witness = beat(db, witness=witness)["latest_seal"]
    assert witness["batch_id"] == 4
    assert db.query(Alert).count() == 0
    db.close()


def test_list_includes_registered_but_never_seen():
    reset()
    db = SessionLocal()
    old = config.AGENT_KEYS
    config.AGENT_KEYS = f"vm1:{hash_agent_key('a')},web-01:{hash_agent_key('b')}"
    try:
        beat(db)
        listed = {a["agent_id"]: a["status"] for a in agents.list_agents(db)}
        assert listed == {"vm1": "online", "web-01": "never seen"}
    finally:
        config.AGENT_KEYS = old
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
    engine.dispose()
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if failed else 0)
