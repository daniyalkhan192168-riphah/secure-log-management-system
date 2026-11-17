"""
Attack detection rule tests. Each test replays a real attack pattern
(the same log lines Ubuntu produced in the live tests) and checks that the
right alert is raised, and that normal activity raises nothing.

Run from the backend folder:  python tests/test_detection.py
"""
import contextlib
import io
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone

TMP = tempfile.mkdtemp(prefix="securelog_detect_")
os.environ["SECURELOG_DATABASE_URL"] = "sqlite:///" + os.path.join(TMP, "test.db")
os.environ["SECURELOG_KEY_DIR"] = os.path.join(TMP, "keys")
os.environ["SECURELOG_ENV_FILE"] = os.path.join(TMP, "none.env")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from database import Base, engine, SessionLocal          # noqa: E402
from models import Alert, Log                             # noqa: E402
from services import ledger, key_manager as km            # noqa: E402
from services.detection import Detector                   # noqa: E402

BASE = datetime(2026, 10, 20, 11, 25, 0, tzinfo=timezone.utc)


def reset():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    shutil.rmtree(os.environ["SECURELOG_KEY_DIR"], ignore_errors=True)
    with contextlib.redirect_stdout(io.StringIO()):
        km.initialize()
    d = Detector()
    d.reset(0)
    return d, SessionLocal()


def log(db, event_type, message, user="-", ip="-", seconds=0, source="securelog:sshd"):
    ledger.append_log(db, {"source": source, "event_type": event_type, "username": user,
                           "ip_address": ip, "message": message,
                           "event_time": BASE + timedelta(seconds=seconds)}, agent_id="ubuntu-vm")


def run(d, db):
    with contextlib.redirect_stdout(io.StringIO()):
        return d.run(db)


def alert_types(db):
    return sorted(a.alert_type for a in db.query(Alert))


def real_ssh_connection(db, start, attempts=3, port=50166, user="hacker", ip="192.168.56.1"):
    """Exactly what Ubuntu logged for one 'ssh hacker@...' with 3 wrong passwords
    (live test, logs #9069-#9078), as classified by the fixed agent."""
    t = start
    log(db, "AUTH_INVALID_USER", f"Invalid user {user} from {ip} port {port}", user=user, ip=ip, seconds=t)
    log(db, "SSH_EVENT", "pam_unix(sshd:auth): check pass; user unknown", seconds=t + 2)
    log(db, "AUTH_FAILED", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
        f"tty=ssh ruser= rhost={ip}", ip=ip, seconds=t + 2)
    for i in range(attempts):
        log(db, "AUTH_INVALID_USER", f"Failed password for invalid user {user} from {ip} port {port} ssh2",
            user=user, ip=ip, seconds=t + 4 + i * 6)
    log(db, "AUTH_FAILED", f"PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh "
        f"ruser= rhost={ip}", ip=ip, seconds=t + 20)
    log(db, "SSH_DISCONNECT", f"Connection reset by invalid user {user} {ip} port {port} [preauth]",
        user=user, ip=ip, seconds=t + 20)


def test_real_ubuntu_ssh_one_connection_is_not_brute_force():
    d, db = reset()
    real_ssh_connection(db, 0)                    # 3 real attempts, 7 lines
    assert run(d, db) == []
    db.close()


def test_real_ubuntu_ssh_two_connections_is_brute_force():
    d, db = reset()
    real_ssh_connection(db, 0)
    real_ssh_connection(db, 22, port=63099)       # 6 real attempts
    assert run(d, db) == ["BRUTE_FORCE_DETECTED"]
    a = db.query(Alert).one()
    assert "trying user(s): hacker." in a.description   # not "hacker, root"
    assert a.description.startswith("5 failed")         # counts attempts, not lines
    db.close()


def test_real_ubuntu_sudo_three_wrong_passwords():
    """Ubuntu 24: one PAM failure, unix_chkpwd lines, then sudo's summary."""
    d, db = reset()
    log(db, "SUDO_AUTH_FAILED", "pam_unix(sudo:auth): authentication failure; logname=securelog "
        "uid=1000 euid=0 tty=/dev/pts/0 ruser=securelog rhost=  user=securelog",
        user="securelog", source="securelog:sudo")
    log(db, "AUTH_FAILED", "password check failed for user (securelog)", user="securelog",
        seconds=3, source="securelog:unix_chkpwd")
    log(db, "AUTH_FAILED", "password check failed for user (securelog)", user="securelog",
        seconds=6, source="securelog:unix_chkpwd")
    log(db, "SUDO_AUTH_FAILED", "securelog : 3 incorrect password attempts ; TTY=/dev/pts/0 ; "
        "PWD=/home/securelog ; USER=root ; COMMAND=/usr/bin/ls", user="securelog",
        seconds=8, source="securelog:sudo")
    assert run(d, db) == ["SUDO_PASSWORD_GUESSING"]
    assert "3 times" in db.query(Alert).one().description
    db.close()


def test_one_wrong_sudo_password_is_not_an_alert():
    d, db = reset()
    log(db, "SUDO_AUTH_FAILED", "pam_unix(sudo:auth): authentication failure; logname=securelog "
        "uid=1000 euid=0 tty=/dev/pts/0 ruser=securelog rhost=  user=securelog",
        user="securelog", source="securelog:sudo")
    assert run(d, db) == []
    db.close()


def failed_ssh(db, n, ip="192.168.56.1", start=0, step=6, user="hacker"):
    for i in range(n):
        log(db, "AUTH_INVALID_USER",
            f"Failed password for invalid user {user} from {ip} port {50000 + i} ssh2",
            user=user, ip=ip, seconds=start + i * step)


def test_ssh_brute_force():
    d, db = reset()
    failed_ssh(db, 4)
    assert run(d, db) == []                                  # 4 attempts: not yet
    failed_ssh(db, 3, start=30)
    assert run(d, db) == ["BRUTE_FORCE_DETECTED"]
    a = db.query(Alert).one()
    assert a.severity == "high" and "192.168.56.1" in a.description and "hacker" in a.description
    failed_ssh(db, 5, start=60)
    assert run(d, db) == []                                  # same attacker: suppressed
    assert db.query(Log).filter(Log.event_type == "BRUTE_FORCE_DETECTED").count() == 1
    assert ledger.verify_all(db)["status"] == "Valid"
    db.close()


def test_slow_failures_are_not_brute_force():
    d, db = reset()
    failed_ssh(db, 6, step=120)                              # one try every 2 min
    assert run(d, db) == []
    db.close()


def test_different_ips_are_separate():
    d, db = reset()
    for i in range(6):
        failed_ssh(db, 1, ip=f"10.0.0.{i}", start=i)
    assert run(d, db) == []
    db.close()


def test_brute_force_then_success_is_critical():
    d, db = reset()
    failed_ssh(db, 6, user="securelog")
    log(db, "AUTH_SUCCESS", "Accepted password for securelog from 192.168.56.1 port 51000 ssh2",
        user="securelog", ip="192.168.56.1", seconds=60)
    assert run(d, db) == ["BRUTE_FORCE_DETECTED", "BRUTE_FORCE_SUCCESS"]
    assert db.query(Alert).filter(Alert.alert_type == "BRUTE_FORCE_SUCCESS").one().severity == "critical"
    db.close()


def test_normal_login_is_not_an_alert():
    d, db = reset()
    failed_ssh(db, 1, user="securelog")                      # one typo, then success
    log(db, "AUTH_SUCCESS", "Accepted password for securelog from 192.168.56.1 port 51000 ssh2",
        user="securelog", ip="192.168.56.1", seconds=10)
    assert run(d, db) == []
    db.close()


def test_sudo_password_guessing():
    d, db = reset()
    for i in range(3):
        log(db, "SUDO_AUTH_FAILED",
            "pam_unix(sudo:auth): authentication failure; logname=securelog uid=1000 euid=0 "
            "tty=/dev/pts/0 ruser=securelog rhost=  user=securelog",
            user="securelog", seconds=i * 5, source="securelog:sudo")
    assert run(d, db) == ["SUDO_PASSWORD_GUESSING"]
    db.close()


def test_backdoor_admin_account():
    d, db = reset()
    log(db, "ACCOUNT_CHANGE", "new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor",
        user="backdoor", source="securelog:useradd")
    log(db, "ACCOUNT_CHANGE", "add 'backdoor' to group 'sudo'", user="backdoor",
        seconds=5, source="securelog:usermod")
    log(db, "ACCOUNT_CHANGE", "add 'backdoor' to shadow group 'sudo'", user="backdoor",
        seconds=5, source="securelog:usermod")
    assert run(d, db) == ["ADMIN_RIGHTS_GRANTED"]           # shadow-group line not repeated
    assert "backdoor" in db.query(Alert).one().description
    db.close()


def test_normal_group_change_is_not_an_alert():
    d, db = reset()
    log(db, "ACCOUNT_CHANGE", "add 'alice' to group 'docker'", user="alice", source="securelog:usermod")
    assert run(d, db) == []
    db.close()


def test_log_wiping_commands():
    commands = [
        "/usr/bin/journalctl --vacuum-time=1s",
        "/usr/bin/rm -rf /var/log/auth.log",
        "/usr/bin/truncate -s 0 /var/log/syslog",
        "/usr/bin/systemctl stop securelog-agent",
    ]
    for cmd in commands:
        d, db = reset()
        log(db, "SUDO_COMMAND", f"securelog : TTY=pts/0 ; PWD=/home/securelog ; USER=root ; COMMAND={cmd}",
            user="securelog", source="securelog:sudo")
        assert run(d, db) == ["LOG_WIPING_DETECTED"], cmd
        assert db.query(Alert).one().severity == "critical"
        db.close()


def test_normal_sudo_is_not_an_alert():
    d, db = reset()
    for cmd in ["/usr/bin/cat /etc/shadow", "/usr/bin/journalctl -u securelog-agent -f",
                "/usr/bin/systemctl status securelog-agent", "/usr/bin/ls /var/log"]:
        log(db, "SUDO_COMMAND", f"securelog : TTY=pts/0 ; PWD=/home/securelog ; USER=root ; COMMAND={cmd}",
            user="securelog", source="securelog:sudo")
    assert run(d, db) == []
    db.close()


def test_port_scan():
    d, db = reset()
    for i, port in enumerate([23, 3389, 8080, 445, 21]):
        log(db, "FIREWALL_BLOCKED",
            f"[UFW BLOCK] IN=enp0s8 OUT= SRC=192.168.56.1 DST=192.168.56.101 PROTO=TCP SPT=5{i}000 DPT={port}",
            ip="192.168.56.1", seconds=i * 3, source="securelog:kernel")
    assert run(d, db) == ["PORT_SCAN_DETECTED"]
    db.close()


def test_repeated_hits_on_one_port_are_not_a_scan():
    d, db = reset()
    for i in range(8):
        log(db, "FIREWALL_BLOCKED",
            "[UFW BLOCK] IN=enp0s8 OUT= SRC=192.168.56.1 DST=192.168.56.101 PROTO=TCP DPT=23",
            ip="192.168.56.1", seconds=i, source="securelog:kernel")
    assert run(d, db) == []
    db.close()


def test_late_delivery_uses_original_event_time():
    """Logs queued by the agent during an outage arrive late but together;
    correlation must use when they HAPPENED, not when they arrived."""
    d, db = reset()
    failed_ssh(db, 6, step=120)            # happened 2 min apart, arrives all at once
    assert run(d, db) == []
    db.close()


def test_server_events_are_ignored_and_detector_starts_at_now():
    d, db = reset()
    failed_ssh(db, 10)
    fresh = Detector()                     # e.g. backend restart
    with contextlib.redirect_stdout(io.StringIO()):
        assert fresh.run(db) == []         # first run: remember position only
        assert fresh.run(db) == []         # old attack not re-alerted
    assert run(d, db) == ["BRUTE_FORCE_DETECTED"]
    before = db.query(Log).count()
    assert run(d, db) == []                # its own alert event is not re-checked
    assert db.query(Log).count() == before
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
            import traceback; traceback.print_exc()
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    engine.dispose()
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if failed else 0)
