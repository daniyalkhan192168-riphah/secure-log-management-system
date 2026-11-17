#!/usr/bin/env python3
"""
Agent tests (run on Linux / the Ubuntu server):

    python3 test_agent.py

1. Real Ubuntu log lines (sshd, sudo, PAM, unix_chkpwd, UFW, useradd,
   usermod, userdel, su, systemd) are classified correctly, with the right
   username and IP. Includes the exact lines from the live attack tests.
2. Journal JSON details: binary messages, original timestamps, own output skipped.
3. No log is lost or reordered when the backend fails; the queue survives restarts.
4. Rollback witness logic and heartbeat address.
"""
import importlib.util
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("agent", os.path.join(HERE, "ubuntu_log_agent.py"))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

# (program, message, priority, expected event, expected user, expected IP)
CASES = [
    # --- SSH (live test A1)
    ("sshd-session", "Invalid user hacker from 192.168.56.1 port 50166", 6,
     "AUTH_INVALID_USER", "hacker", "192.168.56.1"),
    ("sshd-session", "Failed password for invalid user hacker from 192.168.56.1 port 50166 ssh2", 6,
     "AUTH_INVALID_USER", "hacker", "192.168.56.1"),
    ("sshd-session", "pam_unix(sshd:auth): check pass; user unknown", 6,
     "SSH_EVENT", "-", "-"),
    ("sshd-session", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
                     "ruser= rhost=192.168.56.1", 5,
     "AUTH_FAILED", "-", "192.168.56.1"),
    ("sshd-session", "PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= "
                     "rhost=192.168.56.1", 5,
     "AUTH_FAILED", "-", "192.168.56.1"),
    ("sshd-session", "Connection reset by invalid user hacker 192.168.56.1 port 50166 [preauth]", 6,
     "SSH_DISCONNECT", "hacker", "192.168.56.1"),
    ("sshd", "Failed password for securelog from 192.168.56.1 port 51234 ssh2", 6,
     "AUTH_FAILED", "securelog", "192.168.56.1"),
    ("sshd", "Accepted password for securelog from 192.168.56.1 port 50510 ssh2", 6,
     "AUTH_SUCCESS", "securelog", "192.168.56.1"),
    ("sshd", "pam_unix(sshd:session): session opened for user securelog(uid=1000) by securelog(uid=0)", 6,
     "SESSION_OPENED", "securelog", "-"),
    ("sshd-session", "Disconnected from user securelog 192.168.56.1 port 50510", 6,
     "SSH_DISCONNECT", "securelog", "192.168.56.1"),
    # --- sudo (live test A2)
    ("sudo", "securelog : TTY=pts/0 ; PWD=/home/securelog ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", 5,
     "SUDO_COMMAND", "securelog", "-"),
    ("sudo", "pam_unix(sudo:auth): authentication failure; logname=securelog uid=1000 euid=0 "
             "tty=/dev/pts/0 ruser=securelog rhost=  user=securelog", 5,
     "SUDO_AUTH_FAILED", "securelog", "-"),
    ("unix_chkpwd", "password check failed for user (securelog)", 5,
     "AUTH_FAILED", "securelog", "-"),
    ("sudo", "securelog : 3 incorrect password attempts ; TTY=/dev/pts/0 ; PWD=/home/securelog ; "
             "USER=root ; COMMAND=/usr/bin/ls", 3,
     "SUDO_AUTH_FAILED", "securelog", "-"),
    ("sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by securelog(uid=1000)", 6,
     "SESSION_OPENED", "root", "-"),
    # --- backdoor account (live test A3)
    ("useradd", "new user: name=backdoor3, UID=1001, GID=1001, home=/home/backdoor3, shell=/bin/sh, "
                "from=/dev/pts/1", 6, "ACCOUNT_CHANGE", "backdoor3", "-"),
    ("useradd", "new group: name=backdoor3, GID=1001", 6, "ACCOUNT_CHANGE", "backdoor3", "-"),
    ("usermod", "add 'backdoor3' to group 'sudo'", 6, "ACCOUNT_CHANGE", "backdoor3", "-"),
    ("usermod", "add 'backdoor3' to shadow group 'sudo'", 6, "ACCOUNT_CHANGE", "backdoor3", "-"),
    ("userdel", "delete user 'backdoor3'", 6, "ACCOUNT_CHANGE", "backdoor3", "-"),
    ("userdel", "delete 'backdoor3' from group 'sudo'", 6, "ACCOUNT_CHANGE", "backdoor3", "-"),
    ("userdel", "removed group 'backdoor3' owned by 'backdoor3'", 6, "ACCOUNT_CHANGE", "backdoor3", "-"),
    ("userdel", "removed shadow group 'backdoor3' owned by 'backdoor3'", 6,
     "ACCOUNT_CHANGE", "backdoor3", "-"),
    ("passwd", "pam_unix(passwd:chauthtok): password changed for eve", 5, "ACCOUNT_CHANGE", "eve", "-"),
    # --- firewall (live test A4)
    ("kernel", "[UFW BLOCK] IN=enp0s3 OUT= MAC=00 SRC=45.33.32.156 DST=10.0.2.15 LEN=44 PROTO=TCP DPT=22", 4,
     "FIREWALL_BLOCKED", "-", "45.33.32.156"),
    # --- other
    ("su", "FAILED SU (to root) securelog on pts/0", 4, "AUTH_FAILED", "securelog", "-"),
    ("systemd", "Started ssh.service - OpenBSD Secure Shell server.", 6, "SERVICE_EVENT", "-", "-"),
    ("systemd", "nginx.service: Failed with result 'exit-code'.", 3, "SERVICE_FAILED", "-", "-"),
    ("root", "SecureLog test message", 5, "SYSTEM_EVENT", "-", "-"),
    ("kernel", "Out of memory: Killed process 1234", 2, "SYSTEM_ERROR", "-", "-"),
]


def test_real_ubuntu_log_lines():
    failures = []
    for ident, msg, prio, ev, user, ip in CASES:
        got = (agent.classify(ident, msg, prio), agent.extract_user(msg, None), agent.extract_ip(msg))
        if got != (ev, user, ip):
            failures.append(f"{ident}: got {got}, expected {(ev, user, ip)}")
    assert not failures, "\n".join(failures)


def test_sshd_never_reports_its_own_root_account():
    """sshd runs as root; lines without a username must not say 'root'."""
    entry = {"MESSAGE": "pam_unix(sshd:auth): check pass; user unknown",
             "SYSLOG_IDENTIFIER": "sshd-session", "_UID": "0", "PRIORITY": "6"}
    assert agent.build_payload(entry)["username"] == "-"
    entry = {"MESSAGE": "Started something", "SYSLOG_IDENTIFIER": "systemd",
             "_UID": "0", "PRIORITY": "6"}
    assert agent.build_payload(entry)["username"] == "root"      # other programs: real uid


def test_journal_json_details():
    entry = {
        "MESSAGE": list("hello \u2713".encode("utf-8")),        # binary-encoded message
        "SYSLOG_IDENTIFIER": "root", "_HOSTNAME": "securelog", "PRIORITY": "5",
        "_UID": "0", "__REALTIME_TIMESTAMP": "1792064216940123", "__CURSOR": "s=abc",
    }
    p = agent.build_payload(entry)
    assert p["message"] == "hello \u2713"
    assert p["source"] == "securelog:root"
    assert p["username"] == "root"                              # from _UID
    assert p["ip_address"] == "-"                               # never invented
    assert p["event_time"] == "2026-10-15T11:36:56.940123+00:00"
    assert agent.build_payload({"MESSAGE": "   "}) is None
    assert agent.is_own_entry({"SYSLOG_IDENTIFIER": "securelog-agent"}, {"securelog-agent"})
    assert agent.is_own_entry({"_SYSTEMD_UNIT": "securelog-agent.service"}, set())
    assert not agent.is_own_entry({"SYSLOG_IDENTIFIER": "sshd"}, {"securelog-agent"})


def _make_agent(state_dir):
    conf = os.path.join(state_dir, "agent.conf")
    with open(conf, "w") as f:
        f.write(f"[agent]\napi_url = http://127.0.0.1:1/logs/add\napi_key = k\n"
                f"state_dir = {state_dir}\nverbose = false\n")
    os.chmod(conf, 0o600)
    return agent.Agent(agent.Config(conf))


def test_no_loss_and_order_during_outage():
    tmp = tempfile.mkdtemp()
    try:
        received, backend_up = [], {"up": True}

        def fake_backend(payload):
            if not backend_up["up"]:
                return "retry"
            received.append(payload["message"])
            return "ok"

        a = _make_agent(tmp)
        a.send = fake_backend
        a.deliver({"message": "1"})
        backend_up["up"] = False                     # backend goes down
        for m in ("2", "3", "4"):
            a.deliver({"message": m})
        assert received == ["1"] and a.state.spooled == 3

        b = _make_agent(tmp)                         # agent restarts, still down
        b.send = fake_backend
        assert b.state.spooled == 3
        b.deliver({"message": "5"})                  # must queue behind 2,3,4
        backend_up["up"] = True                      # backend comes back
        b.next_retry = 0
        b.try_flush()
        assert received == ["1", "2", "3", "4", "5"], received
        assert b.state.spooled == 0
    finally:
        shutil.rmtree(tmp)


def test_invalid_logs_are_dropped_not_retried_forever():
    tmp = tempfile.mkdtemp()
    try:
        a = _make_agent(tmp)
        a.state.spool({"message": "bad"})
        a.state.spool({"message": "good"})
        seen = []
        a.state.flush(lambda p: seen.append(p["message"]) or ("drop" if p["message"] == "bad" else "ok"))
        assert seen == ["bad", "good"] and a.state.spooled == 0
    finally:
        shutil.rmtree(tmp)


def test_cursor_is_saved_and_restored():
    tmp = tempfile.mkdtemp()
    try:
        s = agent.State(tmp, 100)
        assert s.load_cursor() is None
        s.save_cursor("s=123;i=4")
        assert agent.State(tmp, 100).load_cursor() == "s=123;i=4"
        s.clear_cursor()
        assert s.load_cursor() is None
    finally:
        shutil.rmtree(tmp)


def test_witness_logic():
    s1 = {"batch_id": 5, "seal": "a" * 64}
    assert agent.check_witness(None, None) == ("ok", None)
    assert agent.check_witness(None, s1) == ("ok", s1)                      # first seal seen
    newer = {"batch_id": 6, "seal": "b" * 64}
    assert agent.check_witness(s1, newer) == ("ok", newer)                  # server moved on
    assert agent.check_witness(s1, s1) == ("ok", s1)                        # unchanged
    assert agent.check_witness(s1, {"batch_id": 4, "seal": "c" * 64})[0] == "rollback"
    assert agent.check_witness(s1, None)[0] == "rollback"                   # all seals gone
    assert agent.check_witness(s1, {"batch_id": 5, "seal": "d" * 64})[0] == "mismatch"
    assert agent.check_witness(s1, {"batch_id": 4, "seal": "c" * 64})[1] == s1   # keep newest


def test_heartbeat_url_and_witness_storage():
    assert agent.Config._heartbeat_url("http://10.0.2.2:8000/logs/add") == \
        "http://10.0.2.2:8000/agents/heartbeat"
    tmp = tempfile.mkdtemp()
    try:
        s = agent.State(tmp, 100)
        assert s.load_witness() is None
        s.save_witness({"batch_id": 3, "seal": "e" * 64})
        assert agent.State(tmp, 100).load_witness() == {"batch_id": 3, "seal": "e" * 64}
    finally:
        shutil.rmtree(tmp)


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
    print(f"\n{len(tests) - failed}/{len(tests)} passed  ({len(CASES)} real log formats checked)")
    sys.exit(1 if failed else 0)
