"""
Dashboard tests: severity rule, statistics over all logs, search/filter,
and the integrity monitor's automatic alerts.

Run from the backend folder:  python tests/test_dashboard.py
"""
import contextlib
import io
import os
import shutil
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="securelog_dash_")
os.environ["SECURELOG_DATABASE_URL"] = "sqlite:///" + os.path.join(TMP, "test.db")
os.environ["SECURELOG_KEY_DIR"] = os.path.join(TMP, "keys")
os.environ["SECURELOG_BATCH_SIZE"] = "10"
os.environ["SECURELOG_ENV_FILE"] = os.path.join(TMP, "none.env")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from database import Base, engine, SessionLocal          # noqa: E402
from models import Alert, Log                             # noqa: E402
from services import ledger, key_manager as km            # noqa: E402
from services import dashboard_service as ds              # noqa: E402
from services.monitor import IntegrityMonitor             # noqa: E402
from services.severity import severity                    # noqa: E402


def reset():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    shutil.rmtree(os.environ["SECURELOG_KEY_DIR"], ignore_errors=True)
    with contextlib.redirect_stdout(io.StringIO()):
        km.initialize()


def add(db, event_type, ip="10.0.0.1", user="alice", message="test"):
    return ledger.append_log(db, {"source": "Ubuntu-test", "event_type": event_type,
                                  "username": user, "ip_address": ip, "message": message},
                             agent_id="ubuntu-vm")


def test_severity_rule_covers_all_event_types():
    expected = {
        # agent events
        "AUTH_FAILED": "high", "AUTH_INVALID_USER": "high", "SUDO_AUTH_FAILED": "high",
        "FIREWALL_BLOCKED": "high", "SERVICE_FAILED": "high", "SYSTEM_ERROR": "high",
        "AUTH_SUCCESS": "medium", "SUDO_COMMAND": "medium", "SSH_EVENT": "medium",
        "SSH_DISCONNECT": "medium", "ACCOUNT_CHANGE": "medium", "PRIVILEGE_SWITCH": "medium",
        "SESSION_OPENED": "low", "SYSTEM_EVENT": "low", "SYSTEM_WARNING": "low",
        # server events
        "INTEGRITY_ALERT": "critical", "DEMO_ATTACK": "critical",
        "DASHBOARD_LOGIN_FAILED": "high", "DASHBOARD_LOGIN_SUCCESS": "medium",
        # agent monitoring
        "ROLLBACK_DETECTED": "critical", "SEAL_MISMATCH": "critical",
        "AGENT_SILENT": "high", "AGENT_STOPPED": "high", "AGENT_ONLINE": "low",
        # detection rules
        "BRUTE_FORCE_SUCCESS": "critical", "ADMIN_RIGHTS_GRANTED": "critical",
        "LOG_WIPING_DETECTED": "critical", "BRUTE_FORCE_DETECTED": "high",
        "SUDO_PASSWORD_GUESSING": "high", "PORT_SCAN_DETECTED": "high",
    }
    wrong = {k: severity(k) for k, v in expected.items() if severity(k) != v}
    assert not wrong, wrong
    assert severity(None) == "low"


def test_stats_count_all_logs_not_just_loaded_ones():
    reset()
    db = SessionLocal()
    for i in range(30):
        add(db, "AUTH_FAILED", ip=f"10.0.0.{i % 3}")
    for _ in range(25):
        add(db, "SYSTEM_EVENT", ip="10.0.0.9")
    add(db, "SUDO_COMMAND")
    stats = ds.build_stats(db, {"status": "Valid"})
    assert stats["total_logs"] == 56
    assert stats["severity_counts"] == {"critical": 0, "high": 30, "medium": 1, "low": 25}
    assert stats["top_ips"][0] == {"ip": "10.0.0.9", "count": 25}
    assert len(stats["recent_threats"]) == 5
    assert all(t["severity"] in ("critical", "high") for t in stats["recent_threats"])
    assert stats["total_merkle_roots"] == 5 and stats["open_batch_logs"] == 6
    assert stats["recent_batches"][0]["batch_id"] == 5
    assert "key" not in stats and len(stats["k0_fingerprint"]) == 64
    db.close()


def test_search_and_filter_logic():
    reset()
    db = SessionLocal()
    add(db, "AUTH_FAILED", ip="203.0.113.5", user="mallory", message="Failed password")
    add(db, "SESSION_OPENED", user="bob", message="session opened")
    add(db, "SUDO_COMMAND", user="alice", message="sudo ls")
    assert ds.event_types_with(db, {"high"}) == ["AUTH_FAILED"]
    rows = db.query(Log).filter(Log.ip_address.ilike("%203.0.113%")).all()
    assert [r.username for r in rows] == ["mallory"]
    assert ds.serialize_log(rows[0])["severity"] == "high"
    db.close()


def test_monitor_raises_one_alert_per_incident():
    reset()
    db = SessionLocal()
    for _ in range(12):
        add(db, "AUTH_FAILED")
    mon = IntegrityMonitor(interval_seconds=30)
    with contextlib.redirect_stdout(io.StringIO()):
        assert mon.check_now("test", db=db)["status"] == "Valid"
        assert db.query(Alert).count() == 0
        ledger.simulate_tamper(db, 3)
        assert mon.check_now("test", db=db)["status"] == "Tampered"
        assert db.query(Alert).count() == 1
        assert mon.check_now("test", db=db)["status"] == "Tampered"
        assert db.query(Alert).count() == 1          # no duplicate alert
    alert = db.query(Alert).first()
    assert alert.severity == "critical" and alert.log_id == 3
    assert "content_hash" in alert.description
    event = db.query(Log).filter(Log.event_type == "INTEGRITY_ALERT").one()
    assert event.agent_id == ledger.SERVER_AGENT
    latest = mon.latest()
    assert latest["status"] == "Tampered" and "content_hash" in latest["problem_types"]
    db.close()


def test_monitor_caches_its_result():
    reset()
    db = SessionLocal()
    add(db, "SYSTEM_EVENT")
    mon = IntegrityMonitor(interval_seconds=30)
    first = mon.latest()                               # runs a check on first use
    assert first["status"] == "Valid" and first["reason"] == "first request"
    assert mon.latest()["checked_at"] == first["checked_at"]   # cached, not re-run
    db.close()


def test_monitor_check_is_race_free_while_logs_arrive():
    """Without the write lock, checks during a seal gave false 'Tampered'."""
    import threading
    reset()
    done = threading.Event()

    def writer():
        d = SessionLocal()
        for _ in range(150):
            add(d, "SYSTEM_EVENT")
        d.close()
        done.set()

    t = threading.Thread(target=writer)
    t.start()
    false_alarms = 0
    while not done.is_set():
        d = SessionLocal()
        if ledger.verify_all_consistent(d)["status"] != "Valid":
            false_alarms += 1
        d.close()
    t.join()
    assert false_alarms == 0


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
