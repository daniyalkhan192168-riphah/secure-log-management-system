#!/usr/bin/env python3
"""
SecureLog Ubuntu agent (v2). Standard library only.

What it does
  * Reads the systemd journal as JSON (journalctl -f -o json), so every log
    has its real program (sshd, sudo...), host, user id and ORIGINAL time.
  * Extracts the real username and IP from the message; never invents them.
  * Never loses a log:
      - if the backend is down, logs are queued in a spool file on disk and
        sent in the original order when it comes back;
      - the journal position (cursor) is saved, so after a restart or reboot
        the agent continues exactly where it stopped.
  * Ignores its own output, so running it as a service cannot create a loop.
  * Sends a heartbeat every 60 s and keeps a witness of the server's latest
    seal, so a silent agent or a rolled-back log database is detected.

Config (agent.conf):
    [agent]
    api_url   = http://10.0.2.2:8000/logs/add
    api_key   = <key from: python manage.py add-agent NAME>
    # optional:
    state_dir = /var/lib/securelog-agent
    max_spool = 50000
    verbose   = true
    heartbeat_seconds = 60

Run by hand:   sudo python3 ubuntu_log_agent.py --config agent.conf
As a service:  see install.sh and securelog-agent.service
"""
import argparse
import configparser
import grp
import json
import os
import pwd
import re
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

AGENT_NAME = "securelog-agent"
AGENT_VERSION = "2.1"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIGS = ["/etc/securelog-agent/agent.conf", os.path.join(HERE, "agent.conf")]

MESSAGE_LIMIT = 2000
RETRY_MIN, RETRY_MAX = 5, 60          # seconds between attempts while the backend is down


def log(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ====================================================================== config
class Config:
    def __init__(self, path: str):
        cp = configparser.ConfigParser()
        if not cp.read(path) or "agent" not in cp:
            sys.exit(f"Cannot read [agent] section from {path}")
        a = cp["agent"]
        self.path = path
        self.api_url = a.get("api_url", "").strip()
        self.api_key = a.get("api_key", "").strip()
        if not self.api_url or not self.api_key:
            sys.exit(f"{path} needs both api_url and api_key")
        self.state_dir = a.get("state_dir", "").strip() or self._default_state_dir()
        self.max_spool = a.getint("max_spool", 50000)
        self.verbose = a.getboolean("verbose", True)
        self.heartbeat_seconds = a.getint("heartbeat_seconds", 60)
        self.heartbeat_url = a.get("heartbeat_url", "").strip() or self._heartbeat_url(self.api_url)
        self.ca_file = a.get("ca_file", "").strip() or None
        self.ssl_context = None
        if self.api_url.lower().startswith("https://"):
            if self.ca_file and not os.path.exists(self.ca_file):
                sys.exit(f"ca_file {self.ca_file} not found")
            # With ca_file, ONLY the SecureLog CA is trusted (certificate pinning).
            self.ssl_context = ssl.create_default_context(cafile=self.ca_file)
        else:
            log("[WARN] api_url uses plain HTTP: the API key and logs travel unencrypted. "
                "Use https:// and ca_file (see backend/make_certs.py).")
        self.ignore = {AGENT_NAME} | {
            s.strip() for s in a.get("ignore_identifiers", "").split(",") if s.strip()
        }
        os.makedirs(self.state_dir, exist_ok=True)
        if os.name == "posix" and os.stat(path).st_mode & 0o007:
            log(f"[WARN] {path} is readable by everyone. Run: chmod 600 {path}")

    @staticmethod
    def _heartbeat_url(api_url: str) -> str:
        # http://host:8000/logs/add -> http://host:8000/agents/heartbeat
        base = api_url.split("/logs/", 1)[0].rstrip("/")
        return base + "/agents/heartbeat"

    @staticmethod
    def _default_state_dir() -> str:
        # systemd's StateDirectory= sets $STATE_DIRECTORY
        if os.environ.get("STATE_DIRECTORY"):
            return os.environ["STATE_DIRECTORY"].split(":")[0]
        if os.geteuid() == 0:
            return "/var/lib/securelog-agent"
        return os.path.join(HERE, ".securelog-agent-state")


def find_config(explicit):
    if explicit:
        return explicit
    for path in DEFAULT_CONFIGS:
        if os.path.exists(path):
            return path
    sys.exit("No agent.conf found. Looked in: " + ", ".join(DEFAULT_CONFIGS))


# ====================================================================== parsing
IPV4 = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
IP_PATTERNS = [
    re.compile(rf"\bfrom\s+({IPV4})\b"),
    re.compile(rf"\brhost=({IPV4})\b"),
    re.compile(rf"\bSRC=({IPV4})\b"),
    re.compile(rf"\b({IPV4})\b"),
]
USER_PATTERNS = [
    re.compile(r"\b[Ii]nvalid user (\S+)"),
    re.compile(r"\b(?:Failed|Accepted) \S+ for (\S+) from"),
    re.compile(r"\bsession (?:opened|closed) for user ([^\s(]+)"),
    re.compile(r"^\s*(\S+) : (?:\d+ incorrect password attempts? ; )?TTY="),   # sudo
    re.compile(r"\bnew user: name=([^,\s]+)"),                                  # useradd
    re.compile(r"\bdelete user '([^']+)'"),                                     # userdel
    re.compile(r"\bdelete '([^']+)' from (?:shadow )?group"),                   # userdel
    re.compile(r"\badd '([^']+)' to (?:shadow )?group"),                        # usermod
    re.compile(r"\bnew group: name=([^,\s]+)"),                                 # useradd
    re.compile(r"\bgroup added to /etc/\S+: name=([^,\s]+)"),                  # useradd
    re.compile(r"\b(?:removed|removed shadow) group '[^']+' owned by '([^']+)'"),  # userdel
    re.compile(r"\bpassword changed for (\S+)"),                                # passwd
    re.compile(r"\bpassword check failed for user \(([^)]+)\)"),                # unix_chkpwd    
    re.compile(r"\bDisconnected from user (\S+)"),                              # sshd
    re.compile(r"\bSU \(to \S+\) (\S+) on"),                                  # su
    re.compile(r"\bruser=(\S+)"),
    re.compile(r"\buser=(\S+)"),
]
ACCOUNT_TOOLS = {"useradd", "userdel", "usermod", "groupadd", "groupdel",
                 "groupmod", "passwd", "chpasswd", "chage", "gpasswd"}


def journal_field(entry: dict, name: str, default=None):
    """journalctl -o json encodes binary values as lists of byte values and
    repeated fields as lists of strings."""
    value = entry.get(name, default)
    if isinstance(value, list):
        if value and all(isinstance(x, int) for x in value):
            return bytes(value).decode("utf-8", "replace")
        return value[0] if value else default
    return value


def extract_ip(message: str) -> str:
    for pattern in IP_PATTERNS:
        m = pattern.search(message)
        if m:
            return m.group(1)
    return "-"


def extract_user(message: str, uid) -> str:
    for pattern in USER_PATTERNS:
        m = pattern.search(message)
        if m and m.group(1) not in ("", "-"):
            return m.group(1).rstrip(",;")
    if uid not in (None, ""):
        try:
            return pwd.getpwuid(int(uid)).pw_name
        except (KeyError, ValueError):
            return f"uid:{uid}"
    return "-"


def classify(identifier: str, message: str, priority: int) -> str:
    ident = (identifier or "").lower()
    m = message.lower()

    if "session opened" in m:
        return "SESSION_OPENED"
    if "session closed" in m:
        return "SESSION_CLOSED"

    if ident.startswith("sshd"):
        if "connection reset" in m or "connection closed" in m or "disconnected from" in m:
            return "SSH_DISCONNECT"
        if "invalid user" in m:
            return "AUTH_INVALID_USER"
        if m.startswith("failed ") or "authentication failure" in m:
            return "AUTH_FAILED"
        if m.startswith("accepted "):
            return "AUTH_SUCCESS"
        return "SSH_EVENT"

    if ident == "sudo":
        if "incorrect password" in m or "authentication failure" in m:
            return "SUDO_AUTH_FAILED"
        if "command=" in m:
            return "SUDO_COMMAND"
        return "SUDO_EVENT"

    if ident == "su":
        if "failed" in m or "authentication failure" in m:
            return "AUTH_FAILED"
        return "PRIVILEGE_SWITCH"

    if ident == "unix_chkpwd" and "password check failed" in m:
        return "AUTH_FAILED"
    if "authentication failure" in m:
        return "AUTH_FAILED"
    if "[ufw block]" in m:
        return "FIREWALL_BLOCKED"
    if "[ufw allow]" in m:
        return "FIREWALL_ALLOWED"
    if ident in ACCOUNT_TOOLS:
        return "ACCOUNT_CHANGE"

    if ident == "systemd":
        if "failed" in m:
            return "SERVICE_FAILED"
        if m.startswith(("started", "stopped", "starting", "stopping", "reloaded")):
            return "SERVICE_EVENT"

    if priority <= 3:
        return "SYSTEM_ERROR"
    if priority == 4:
        return "SYSTEM_WARNING"
    return "SYSTEM_EVENT"

def event_time(entry: dict):
    raw = journal_field(entry, "__REALTIME_TIMESTAMP")
    try:
        micros = int(raw)
    except (TypeError, ValueError):
        return None
    t = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
    return t.isoformat()


def build_payload(entry: dict):
    """Journal entry -> payload for /logs/add, or None to skip it."""
    message = journal_field(entry, "MESSAGE")
    if not isinstance(message, str) or not message.strip():
        return None
    identifier = (journal_field(entry, "SYSLOG_IDENTIFIER")
                  or journal_field(entry, "_COMM") or "unknown")
    host = journal_field(entry, "_HOSTNAME") or socket.gethostname()
    try:
        priority = int(journal_field(entry, "PRIORITY", 6))
    except (TypeError, ValueError):
        priority = 6
    message = message.strip()
    return {
        "source": f"{host}:{identifier}"[:100],
        "event_type": classify(identifier, message, priority),
        # sshd runs as root, so its user id says nothing about who is logging in
        "username": extract_user(message, None if identifier.lower().startswith("sshd")
                                 else journal_field(entry, "_UID"))[:100],
        "ip_address": extract_ip(message)[:50],
        "message": message[:MESSAGE_LIMIT],
        "event_time": event_time(entry),
    }


def is_own_entry(entry: dict, ignore: set) -> bool:
    """Skip the agent's own output (prevents a feedback loop under systemd)."""
    ident = journal_field(entry, "SYSLOG_IDENTIFIER") or ""
    unit = journal_field(entry, "_SYSTEMD_UNIT") or ""
    pid = journal_field(entry, "_PID") or ""
    return (ident in ignore or unit == f"{AGENT_NAME}.service"
            or str(pid) == str(os.getpid()))


# ====================================================================== witness
def check_witness(stored, latest):
    """Compare the newest seal this agent has seen (stored) with what the
    server reports now (latest). Returns (result, witness_to_store):
      "ok"       - server is consistent; store the newest seal
      "rollback" - server is BEHIND what we already saw (old backup restored)
      "mismatch" - same batch, different seal (sealed batch replaced)"""
    if not latest:
        return ("rollback", stored) if stored else ("ok", None)
    if stored:
        if latest["batch_id"] < stored["batch_id"]:
            return "rollback", stored
        if latest["batch_id"] == stored["batch_id"] and latest["seal"] != stored["seal"]:
            return "mismatch", stored
    return "ok", {"batch_id": latest["batch_id"], "seal": latest["seal"]}


# ====================================================================== state
class State:
    """Journal cursor, rollback witness and spool of unsent logs, all on disk."""

    def __init__(self, directory: str, max_spool: int):
        self.cursor_file = os.path.join(directory, "cursor")
        self.witness_file = os.path.join(directory, "witness.json")
        self.spool_file = os.path.join(directory, "spool.jsonl")
        self.max_spool = max_spool
        self.dropped = 0
        self.spooled = self._count()

    def _count(self) -> int:
        if not os.path.exists(self.spool_file):
            return 0
        with open(self.spool_file, encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    @staticmethod
    def _atomic_write(path: str, text: str):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def load_cursor(self):
        try:
            with open(self.cursor_file, encoding="utf-8") as f:
                return f.read().strip() or None
        except FileNotFoundError:
            return None

    def save_cursor(self, cursor: str):
        if cursor:
            self._atomic_write(self.cursor_file, cursor)

    def load_witness(self):
        try:
            with open(self.witness_file, encoding="utf-8") as f:
                data = json.load(f)
            return {"batch_id": int(data["batch_id"]), "seal": str(data["seal"])}
        except (FileNotFoundError, ValueError, KeyError, TypeError):
            return None

    def save_witness(self, witness):
        if witness:
            self._atomic_write(self.witness_file, json.dumps(witness))

    def clear_cursor(self):
        try:
            os.remove(self.cursor_file)
        except FileNotFoundError:
            pass

    def spool(self, payload: dict):
        if self.spooled >= self.max_spool:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                log(f"[WARN] spool full ({self.max_spool}); {self.dropped} log(s) dropped")
            return
        with open(self.spool_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.spooled += 1

    def flush(self, sender) -> bool:
        """Send spooled logs in order. Stops at the first failure.
        Returns True when the spool is empty afterwards."""
        if not self.spooled:
            return True
        with open(self.spool_file, encoding="utf-8") as f:
            pending = [line for line in f if line.strip()]
        sent = 0
        for line in pending:
            result = sender(json.loads(line))
            if result == "retry":
                break
            sent += 1                      # "ok" or "drop" both leave the queue
        remaining = pending[sent:]
        if remaining:
            self._atomic_write(self.spool_file, "".join(remaining))
        elif os.path.exists(self.spool_file):
            os.remove(self.spool_file)
        self.spooled = len(remaining)
        if sent:
            log(f"[SPOOL] delivered {sent} queued log(s), {self.spooled} still waiting")
        return self.spooled == 0


# ====================================================================== sending
class Sender:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.last_error = None

    def __call__(self, payload: dict) -> str:
        """'ok' = stored, 'retry' = keep it and try later, 'drop' = invalid, discard."""
        req = urllib.request.Request(
            self.cfg.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-API-KEY": self.cfg.api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5, context=self.cfg.ssl_context):
                pass
            if self.last_error:
                log("[OK] backend reachable again")
                self.last_error = None
            if self.cfg.verbose:
                log(f"[SENT] {payload['event_type']:<18} {payload['source']}")
            return "ok"
        except urllib.error.HTTPError as e:
            body = e.read()[:200].decode("utf-8", "replace")
            if e.code in (400, 422):
                log(f"[DROP] backend rejected a log as invalid ({e.code}): {body}")
                return "drop"
            if e.code == 401:
                self._error("401: backend rejected the API key. Check api_key in agent.conf.")
            else:
                self._error(f"HTTP {e.code}: {body}")
            return "retry"
        except (urllib.error.URLError, OSError) as e:
            self._error(f"backend unreachable ({getattr(e, 'reason', e)}); queueing logs")
            return "retry"

    def _error(self, text: str):
        if text != self.last_error:          # do not repeat the same error forever
            log(f"[ERROR] {text}")
            self.last_error = text


# ====================================================================== main loop
class Agent:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = State(cfg.state_dir, cfg.max_spool)
        self.send = Sender(cfg)
        self.next_retry = 0.0
        self.retry_delay = RETRY_MIN
        self.proc = None
        self.started = time.time()
        self.next_heartbeat = 0.0
        self.witness_problem = None

    def deliver(self, payload: dict):
        # Keep the original order: if anything is queued, queue this too.
        if self.state.spooled:
            self.state.spool(payload)
            self.try_flush()
            return
        result = self.send(payload)
        if result == "retry":
            self.state.spool(payload)
            self.schedule_retry()

    def try_flush(self):
        if not self.state.spooled or time.time() < self.next_retry:
            return
        if self.state.flush(self.send):
            self.retry_delay = RETRY_MIN
            self.next_retry = 0.0
        else:
            self.schedule_retry()

    def schedule_retry(self):
        self.next_retry = time.time() + self.retry_delay
        self.retry_delay = min(RETRY_MAX, self.retry_delay * 2)

    def heartbeat(self, stopping: bool = False):
        """Tell the backend we are alive; check its latest seal against our witness."""
        self.next_heartbeat = time.time() + self.cfg.heartbeat_seconds
        stored = self.state.load_witness()
        payload = {
            "hostname": socket.gethostname(),
            "version": AGENT_VERSION,
            "spool_size": self.state.spooled,
            "uptime_seconds": int(time.time() - self.started),
            "witness": stored,
            "stopping": stopping,
        }
        req = urllib.request.Request(
            self.cfg.heartbeat_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-API-KEY": self.cfg.api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3 if stopping else 5,
                                        context=self.cfg.ssl_context) as resp:
                reply = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            self.send._error(f"heartbeat rejected: HTTP {e.code}")
            return
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.send._error(f"heartbeat failed ({getattr(e, 'reason', e)})")
            return
        if stopping:
            return

        result, witness = check_witness(stored, reply.get("latest_seal"))
        if result == "ok":
            self.witness_problem = None
            if witness != stored:
                self.state.save_witness(witness)
            return
        latest = reply.get("latest_seal") or {}
        problem = (result, stored["batch_id"], latest.get("batch_id"))
        if problem != self.witness_problem:          # report each problem once
            self.witness_problem = problem
            if result == "rollback":
                log(f"[ALERT] ROLLBACK DETECTED: this agent already saw sealed batch "
                    f"{stored['batch_id']}, but the server now reports "
                    f"{latest.get('batch_id', 'no sealed batch')}. The log database was "
                    f"rolled back or truncated.")
            else:
                log(f"[ALERT] SEAL MISMATCH: the server's seal for batch {stored['batch_id']} "
                    f"differs from the one this agent saw. The sealed batch was replaced.")

    def handle_line(self, line: bytes):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return
        if not is_own_entry(entry, self.cfg.ignore):
            payload = build_payload(entry)
            if payload:
                self.deliver(payload)
        # Saved after the log is sent OR safely spooled, never before.
        self.state.save_cursor(journal_field(entry, "__CURSOR"))

    def journal_command(self):
        cmd = ["journalctl", "-f", "-o", "json", "--no-pager"]
        cursor = self.state.load_cursor()
        if cursor:
            cmd.append(f"--after-cursor={cursor}")
        else:
            cmd += ["-n", "0"]
        return cmd, bool(cursor)

    def run_once(self):
        cmd, resumed = self.journal_command()
        log("Resuming from saved journal position" if resumed
            else "Starting at the end of the journal (first run)")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sel = selectors.DefaultSelector()
        sel.register(self.proc.stdout, selectors.EVENT_READ)
        buffer = b""
        fd = self.proc.stdout.fileno()
        while True:
            if sel.select(timeout=2):
                chunk = os.read(fd, 65536)
                if not chunk:
                    break                                   # journalctl exited
                buffer += chunk
                *lines, buffer = buffer.split(b"\n")
                for line in lines:
                    if line.strip():
                        self.handle_line(line)
            self.try_flush()                                # retry queued logs
            if time.time() >= self.next_heartbeat:
                self.heartbeat()
        code = self.proc.wait()
        error = self.proc.stderr.read().decode("utf-8", "replace").strip()
        log(f"[WARN] journalctl stopped (exit {code}) {error[:200]}")
        if resumed and code != 0:
            log("[WARN] saved journal position is no longer valid; starting at the end")
            self.state.clear_cursor()

    def run(self):
        log(f"SecureLog agent {AGENT_VERSION} started. Sending to {self.cfg.api_url}, "
            f"heartbeat every {self.cfg.heartbeat_seconds} s")
        log(f"State directory: {self.cfg.state_dir}"
            + (f" ({self.state.spooled} queued log(s) from last run)" if self.state.spooled else ""))
        check_journal_access()
        while True:
            self.run_once()
            time.sleep(5)

    def stop(self, *_):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        self.heartbeat(stopping=True)          # tell the backend this is a deliberate stop
        log("Agent stopped")
        sys.exit(0)


def check_journal_access():
    if os.geteuid() == 0:
        return
    groups = set()
    for gid in os.getgroups():
        try:
            groups.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    if not groups & {"systemd-journal", "adm", "wheel"}:
        log("[WARN] not root and not in the systemd-journal/adm group: "
            "only this user's own logs are visible. Run with sudo or as the service.")


def main():
    ap = argparse.ArgumentParser(description="SecureLog Ubuntu log agent")
    ap.add_argument("--config", help="path to agent.conf")
    args = ap.parse_args()
    agent = Agent(Config(find_config(args.config)))
    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()


if __name__ == "__main__":
    main()