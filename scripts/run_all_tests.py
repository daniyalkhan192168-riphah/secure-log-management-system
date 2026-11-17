#!/usr/bin/env python3
"""
Runs every test suite plus the attack lab and writes TEST_REPORT.md in the
project folder. Run it from anywhere (with the backend venv active):

    python scripts/run_all_tests.py

Agent tests need Linux; on Windows they are skipped (run agents/test_agent.py
on the Ubuntu server instead).
"""
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime

# Windows consoles/pipes default to a legacy encoding that cannot print ✅.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BACKEND = os.path.join(ROOT, "backend")

SUITES = [
    ("Ledger security (hash chain, HMAC, Merkle, seals, forward security, time sealing)",
     [sys.executable, os.path.join("tests", "test_security.py")], BACKEND),
    ("Authentication (passwords, tokens, agent keys, lockout)",
     [sys.executable, os.path.join("tests", "test_auth.py")], BACKEND),
    ("Agent heartbeats, silence and rollback detection",
     [sys.executable, os.path.join("tests", "test_agents.py")], BACKEND),
    ("Attack detection rules (brute force, sudo, backdoor, log wiping, port scan)",
     [sys.executable, os.path.join("tests", "test_detection.py")], BACKEND),
    ("Dashboard statistics and integrity monitor",
     [sys.executable, os.path.join("tests", "test_dashboard.py")], BACKEND),
    ("Ubuntu agent (log parsing, no-loss queue, witness)",
     [sys.executable, os.path.join(ROOT, "agents", "test_agent.py")], os.path.join(ROOT, "agents")),
]


def run(cmd, cwd):
    started = time.time()
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env)
    return proc.returncode, proc.stdout + proc.stderr, time.time() - started


def main():
    report = [
        "# SecureLog test report",
        "",
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} on "
        f"{platform.system()} {platform.release()}, Python {platform.python_version()}.",
        "",
        "## Test suites",
        "",
        "| Suite | Result | Time |",
        "|---|---|---|",
    ]
    details, all_ok, total_pass, total = [], True, 0, 0

    for name, cmd, cwd in SUITES:
        if "agent (" in name.lower() and os.name != "posix":
            report.append(f"| {name} | skipped on Windows (run on Ubuntu) | - |")
            print(f"SKIP  {name} (run agents/test_agent.py on Ubuntu)")
            continue
        script = cmd[1] if os.path.isabs(cmd[1]) else os.path.join(cwd, cmd[1])
        if not os.path.exists(script):
            report.append(f"| {name} | not installed ({os.path.basename(script)} missing) | - |")
            print(f"SKIP  {name} (file not found)")
            continue
        code, output, secs = run(cmd, cwd)
        m = re.search(r"(\d+)/(\d+) passed", output)
        passed, count = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
        total_pass += passed
        total += count
        ok = code == 0 and m is not None
        all_ok &= ok
        report.append(f"| {name} | {'✅' if ok else '❌'} {passed}/{count} passed | {secs:.1f} s |")
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {passed}/{count}")
        details.append((name, output))

    print("\nRunning attack lab...")
    code, output, secs = run([sys.executable, os.path.join(HERE, "attack_lab.py")], BACKEND)
    all_ok &= code == 0
    table = output[output.find("| # |"):].strip() if "| # |" in output else output
    report += [
        "",
        f"**Total: {total_pass}/{total} tests passed.**",
        "",
        "## Attack detection matrix",
        "",
        "Each attack edits the SQLite database directly, the way a real attacker would.",
        "",
        table,
        "",
        "## Full test output",
        "",
    ]
    for name, output in details:
        report += [f"### {name}", "", "```", output.strip(), "```", ""]

    path = os.path.join(ROOT, "TEST_REPORT.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(report))
    print(f"\n{'ALL PASSED' if all_ok else 'SOME FAILURES'}: {total_pass}/{total} tests, "
          f"attack lab {'as expected' if code == 0 else 'UNEXPECTED'}")
    print(f"Report written to {path}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
