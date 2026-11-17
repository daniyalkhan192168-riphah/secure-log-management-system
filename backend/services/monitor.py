"""
Background integrity monitor.

Every SECURELOG_INTEGRITY_CHECK_SECONDS the full server-side verification runs
once and the result is cached, so the dashboard can poll every few seconds
without re-verifying every log each time.

When the status changes to "Tampered", an alert is raised automatically:
  * a row in the `alerts` table (shown on the dashboard), and
  * an INTEGRITY_ALERT event in the tamper-evident ledger itself.
"""
import threading
import time
from datetime import datetime, timezone

import config
from database import SessionLocal
from models import Alert
from services import agents, ledger
from services.detection import detector

class IntegrityMonitor:
    def __init__(self, interval_seconds: int):
        self.interval = interval_seconds
        self._result = None
        self._last_status = None
        self._state_lock = threading.Lock()   # protects _result / _last_status
        self._check_lock = threading.Lock()   # one check at a time
        self._stop = threading.Event()
        self._thread = None

    # -------------------------------------------------------------- checks
    def check_now(self, reason: str = "manual", db=None) -> dict:
        """Run a full verification now, cache it, alert on a new failure.
        Returns the full verification report."""
        own_session = db is None
        db = db or SessionLocal()
        try:
            with self._check_lock:
                started = time.perf_counter()
                report = ledger.verify_all_consistent(db)
                summary = {
                    "status": report["status"],
                    "problems_found": report["problems_found"],
                    "problem_types": sorted({p["type"] for p in report["problems"]}),
                    "total_logs_verified": report["total_logs_verified"],
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "reason": reason,
                    "interval_seconds": self.interval,
                }
                with self._state_lock:
                    previous = self._last_status
                    self._last_status = report["status"]
                    self._result = summary

            if report["status"] == "Tampered" and previous != "Tampered":
                self._raise_alert(db, report)
            return report
        finally:
            if own_session:
                db.close()

    def latest(self) -> dict:
        with self._state_lock:
            result = self._result
        if result is None:
            self.check_now("first request")
            with self._state_lock:
                result = self._result
        return dict(result)

    def _raise_alert(self, db, report: dict):
        types = sorted({p["type"] for p in report["problems"]})
        first_log = next((p["log_id"] for p in report["problems"] if "log_id" in p), None)
        description = (f"Integrity check failed: {report['problems_found']} problem(s) "
                       f"[{', '.join(types)}]")
        if first_log is not None:
            description += f", first at log {first_log}"
        try:
            db.add(Alert(alert_type="INTEGRITY_FAILURE", severity="critical",
                         description=description[:2000], log_id=first_log))
            db.commit()
        except Exception as e:  # noqa: BLE001
            db.rollback()
            print(f"[WARN] could not store alert: {e}")
        ledger.record_server_event(db, "INTEGRITY_ALERT", "system", "-", description)
        print(f"[ALERT] {description}")

    # -------------------------------------------------------------- thread
    def _loop(self):
        while not self._stop.is_set():
            try:
                self.check_now("scheduled")
            except Exception as e:  # noqa: BLE001
                print(f"[WARN] integrity check failed to run: {e}")
            try:
                db = SessionLocal()
                try:
                    agents.check_silent(db)
                finally:
                    db.close()
            except Exception as e:  # noqa: BLE001
                print(f"[WARN] agent silence check failed to run: {e}")
            try:
                db = SessionLocal()
                try:
                    row = ledger.seal_if_older_than(db, config.SEAL_MAX_AGE_SECONDS)
                    if row:
                        print(f"[SEAL] batch {row.batch_id} sealed by time "
                              f"({row.total_logs} logs); key evolved to {row.batch_id + 1}")
                finally:
                    db.close()
            except Exception as e:  # noqa: BLE001
                print(f"[WARN] time-based sealing failed to run: {e}")
            self._stop.wait(self.interval)
            try:
                db = SessionLocal()
                try:
                    detector.run(db)
                finally:
                    db.close()
            except Exception as e:  # noqa: BLE001
                print(f"[WARN] attack detection failed to run: {e}")
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="integrity-monitor", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()


monitor = IntegrityMonitor(config.INTEGRITY_CHECK_SECONDS)