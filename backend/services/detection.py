"""
Attack detection rules (a small SIEM correlation engine).

The integrity monitor calls detector.run() every 30 seconds. It looks at the
logs that arrived since the last run (agents' logs only, never the server's
own events) and applies these rules:

  BRUTE_FORCE_DETECTED    5+ failed SSH password attempts from one IP
                          within 5 min                                       high
  BRUTE_FORCE_SUCCESS     successful login from an IP with 5+ recent
                          failures: the attacker may have got in             critical
  SUDO_PASSWORD_GUESSING  3+ failed sudo passwords by one user in 10 min     high
  ADMIN_RIGHTS_GRANTED    an account added to sudo/admin/wheel group         critical
  LOG_WIPING_DETECTED     journal vacuum, deleting /var/log, stopping a
                          logging service, clearing shell history            critical
  PORT_SCAN_DETECTED      one IP hits 5+ different blocked ports in 2 min    high

Windows use the ORIGINAL event time, so logs delivered late from an agent's
queue are still correlated correctly. The same rule for the same attacker
(IP / user) is not repeated within 10 minutes.
"""
import re
import threading
import time
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from models import Alert, Log
from services import ledger

FAILED_LOGINS = ("AUTH_FAILED", "AUTH_INVALID_USER")
BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW = 5, 300
BRUTE_SUCCESS_WINDOW = 600
SUDO_GUESS_THRESHOLD, SUDO_GUESS_WINDOW = 3, 600
PORT_SCAN_PORTS, PORT_SCAN_WINDOW = 5, 120
COOLDOWN_SECONDS = 600
PRIVILEGED_GROUPS = {"sudo", "admin", "wheel", "root"}

ADD_TO_GROUP = re.compile(r"\badd '([^']+)' to (?:shadow )?group '([^']+)'")
DEST_PORT = re.compile(r"\bDPT=(\d+)")
SUDO_SUMMARY = re.compile(r"\b(\d+) incorrect password attempts?")
LOG_WIPING = [
    (re.compile(r"\bjournalctl\b.*--vacuum"), "deleted the system journal"),
    (re.compile(r"\b(?:rm|shred|truncate|unlink)\b.*?/var/log"), "deleted or emptied files in /var/log"),
    (re.compile(r"\bsystemctl\s+(?:stop|disable|mask|kill)\s+.*?"
                r"(?:securelog-agent|systemd-journald|rsyslog|auditd)"),
     "stopped a logging service"),
    (re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\.bash_history"), "cleared shell history"),
]


def _when(log: Log):
    return log.event_time or log.timestamp


def _host(log: Log) -> str:
    return (log.source or "unknown").split(":")[0]


def _usable_ip(ip: str) -> bool:
    return bool(ip) and ip not in ("-", "127.0.0.1")


def _is_attempt(log: Log) -> bool:
    """One SSH password attempt produces several lines (connection, PAM
    failure, 'Failed password', disconnect). Only 'Failed ...' is the attempt
    itself, so only those are counted."""
    return (log.message or "").startswith("Failed ")


class Detector:
    def __init__(self):
        self.last_id = None
        self.recent = {}                 # (rule, key) -> time of last alert
        self.lock = threading.Lock()

    def reset(self, last_id=0):
        self.last_id = last_id
        self.recent = {}

    # ------------------------------------------------------------ driver
    def run(self, db: Session) -> list:
        """Check logs that arrived since the last run. Returns raised alert types."""
        with self.lock:
            if self.last_id is None:
                # First run after start: only watch logs from now on.
                self.last_id = db.query(func.max(Log.id)).scalar() or 0
                return []
            new = (db.query(Log)
                   .filter(Log.id > self.last_id, Log.agent_id != ledger.SERVER_AGENT)
                   .order_by(Log.id.asc()).limit(5000).all())
            raised = []
            for log in new:
                self.last_id = log.id
                raised += self._check(db, log)
            return raised

    def _window(self, db: Session, log: Log, types, seconds: int, **match):
        when = _when(log)
        t = func.coalesce(Log.event_time, Log.timestamp)
        q = (db.query(Log)
             .filter(Log.event_type.in_(types), Log.id <= log.id,
                     Log.agent_id != ledger.SERVER_AGENT,
                     t >= when - timedelta(seconds=seconds), t <= when))
        for column, value in match.items():
            q = q.filter(getattr(Log, column) == value)
        return q.order_by(Log.id.asc()).all()

    def _alert(self, db: Session, rule: str, severity: str, key: str,
               description: str, log: Log) -> list:
        now = time.time()
        if now - self.recent.get((rule, key), 0) < COOLDOWN_SECONDS:
            return []
        self.recent[(rule, key)] = now
        try:
            db.add(Alert(alert_type=rule, severity=severity,
                         description=description[:2000], log_id=log.id))
            db.commit()
        except Exception as e:  # noqa: BLE001
            db.rollback()
            print(f"[WARN] could not store alert: {e}")
        ledger.record_server_event(db, rule, log.username, log.ip_address, description)
        print(f"[ALERT] {rule}: {description}")
        return [rule]

    # ------------------------------------------------------------ rules
    def _check(self, db: Session, log: Log) -> list:
        et, ip, user, host = log.event_type, log.ip_address, log.username, _host(log)
        raised = []

        if et in FAILED_LOGINS and _usable_ip(ip) and _is_attempt(log):
            rows = [r for r in self._window(db, log, FAILED_LOGINS, BRUTE_FORCE_WINDOW,
                                            ip_address=ip) if _is_attempt(r)]
            if len(rows) >= BRUTE_FORCE_THRESHOLD:
                users = sorted({r.username for r in rows})
                raised += self._alert(
                    db, "BRUTE_FORCE_DETECTED", "high", ip,
                    f"{len(rows)} failed SSH logins from {ip} on {host} within "
                    f"{BRUTE_FORCE_WINDOW // 60} min, trying user(s): {', '.join(users[:10])}. "
                    f"Evidence: logs #{rows[0].id} to #{rows[-1].id}.", log)

        if et == "AUTH_SUCCESS" and _usable_ip(ip):
            rows = [r for r in self._window(db, log, FAILED_LOGINS, BRUTE_SUCCESS_WINDOW,
                                            ip_address=ip) if _is_attempt(r)]
            if len(rows) >= BRUTE_FORCE_THRESHOLD:
                raised += self._alert(
                    db, "BRUTE_FORCE_SUCCESS", "critical", f"{ip}:{user}",
                    f"Successful login as '{user}' on {host} from {ip}, after {len(rows)} failed "
                    f"attempts from the same IP in {BRUTE_SUCCESS_WINDOW // 60} min. The brute "
                    f"force may have succeeded. Evidence: log #{log.id}.", log)

        if et == "SUDO_AUTH_FAILED":
            # sudo itself reports "N incorrect password attempts" when it gives up;
            # otherwise count failures in the window.
            summary = SUDO_SUMMARY.search(log.message or "")
            rows = self._window(db, log, ("SUDO_AUTH_FAILED",), SUDO_GUESS_WINDOW, username=user)
            attempts = max(int(summary.group(1)) if summary else 0, len(rows))
            if attempts >= SUDO_GUESS_THRESHOLD:
                raised += self._alert(
                    db, "SUDO_PASSWORD_GUESSING", "high", user,
                    f"User '{user}' failed sudo authentication {attempts} times on {host} within "
                    f"{SUDO_GUESS_WINDOW // 60} min (someone guessing the password to gain root). "
                    f"Evidence: logs #{rows[0].id} to #{rows[-1].id}.", log)

        if et == "ACCOUNT_CHANGE":
            m = ADD_TO_GROUP.search(log.message or "")
            if m and m.group(2) in PRIVILEGED_GROUPS:
                account, group = m.group(1), m.group(2)
                raised += self._alert(
                    db, "ADMIN_RIGHTS_GRANTED", "critical", f"{host}:{account}:{group}",
                    f"Account '{account}' was added to the privileged group '{group}' on {host}. "
                    f"A new admin account is a common way for attackers to keep access. "
                    f"Evidence: log #{log.id}.", log)

        if et == "SUDO_COMMAND" and "COMMAND=" in (log.message or ""):
            command = log.message.split("COMMAND=", 1)[1]
            for pattern, what in LOG_WIPING:
                if pattern.search(command):
                    raised += self._alert(
                        db, "LOG_WIPING_DETECTED", "critical", f"{host}:{user}:{what}",
                        f"User '{user}' {what} on {host}: {command[:200]}. Logs already "
                        f"collected by SecureLog are not affected. Evidence: log #{log.id}.", log)
                    break

        if et == "FIREWALL_BLOCKED" and _usable_ip(ip):
            rows = self._window(db, log, ("FIREWALL_BLOCKED",), PORT_SCAN_WINDOW, ip_address=ip)
            ports = sorted({int(p.group(1)) for r in rows if (p := DEST_PORT.search(r.message or ""))})
            if len(ports) >= PORT_SCAN_PORTS:
                raised += self._alert(
                    db, "PORT_SCAN_DETECTED", "high", ip,
                    f"{ip} probed {len(ports)} different blocked ports on {host} within "
                    f"{PORT_SCAN_WINDOW // 60} min: {', '.join(map(str, ports[:15]))}. "
                    f"Evidence: logs #{rows[0].id} to #{rows[-1].id}.", log)

        return raised


detector = Detector()