# SecureLog: Secure Log Management System Using Merkle Tree and Hash Chaining

Final Year Project, BS Cyber Security, Faculty of Computing, Riphah International University, Islamabad (Fall 2026).
Team: Daniyal Ali (27670), Ahsan Saleem (23238). Supervisor: Sir Osama Raza.

SecureLog is a tamper-evident log management system. A lightweight agent collects real systemd-journald events from an Ubuntu Server and sends them over HTTPS to a FastAPI + SQLite backend that protects every log with:

- a SHA-256 hash chain and a per-log HMAC-SHA256 tag
- Merkle trees per batch (100 logs or 10 minutes), sealed into an HMAC seal chain
- forward-secure key evolution (old keys are overwritten after every seal)
- an offline auditor that re-verifies everything from the initial key K0
- an integrity monitor (every 30 s), agent heartbeat / silence alerts (180 s) and rollback detection
- six attack-detection rules: SSH brute force, brute-force success, sudo password guessing, admin rights granted, port scan, log wiping
- a React dashboard with login, statistics, logs, alerts and verification

## Project structure

| Folder | Contents |
|---|---|
| `backend/` | FastAPI server, ledger, crypto, detection, monitor, tests |
| `agents/` | Ubuntu log agent, systemd service, installer, agent tests |
| `frontend/` | React + Vite dashboard |

The offline auditor (`auditor_verify.py`) is not part of this repository. It is kept with the auditor key K0 on the auditor's machine, away from the server.

## Requirements

- Windows 11 (backend and dashboard) with Python 3.11 and Node.js 22
- Ubuntu Server 26.04 VM (VirtualBox) for the agent

## Setup (first time)

Backend (PowerShell):

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python manage.py init            # creates .env and the initial key K0
# python manage.py add-agent NAME  # only for an extra agent (init already created 'ubuntu-vm')
python make_certs.py             # creates the private CA and HTTPS certificate
```

Dashboard:

```powershell
cd frontend
npm install
"VITE_API_URL=https://127.0.0.1:8000" | Set-Content .env.local
```

Agent (Ubuntu): copy the `agents/` folder and `backend/tls/ca.crt` to the VM, run `sudo bash install.sh`, then copy the CA next to the agent configuration and pin it:

```bash
sudo cp ca.crt /etc/securelog-agent/ca.crt
# in /etc/securelog-agent/agent.conf:
#   api_url = https://10.0.2.2:8000/logs/add
#   api_key = <key from manage.py add-agent>
#   ca_file = /etc/securelog-agent/ca.crt   (the agent trusts ONLY this CA)
sudo systemctl restart securelog-agent
```
## Running

```powershell
# 1. Backend
cd backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile tls\server.key --ssl-certfile tls\server.crt

# 2. Dashboard (new window)
cd frontend
npm run dev                       # open http://localhost:5173
```

```bash
# 3. Agent (Ubuntu VM)
sudo systemctl restart securelog-agent
```

## Testing

Each scenario is run by hand; the alert appears on the dashboard within 30 seconds.

| Scenario | Where | Action | Expected alert |
|---|---|---|---|
| SSH brute force | Windows | 5 wrong passwords: `ssh hacker@<VM IP>` (twice) | BRUTE_FORCE_DETECTED (T1110) |
| Login after brute force | Windows | Correct SSH login right after | BRUTE_FORCE_SUCCESS (T1078) |
| Sudo guessing | VM | `sudo -k`, then `sudo ls` with 3 wrong passwords | SUDO_PASSWORD_GUESSING (T1548.003) |
| New admin account | VM | `sudo useradd demo1`, `sudo usermod -aG sudo demo1` | ADMIN_RIGHTS_GRANTED (T1098) |
| Log wiping | VM | `sudo touch /var/log/demo.log`, `sudo rm /var/log/demo.log` | LOG_WIPING_DETECTED (T1070.002) |
| Port scan | Windows | Scan 5+ blocked ports on the VM (UFW on) | PORT_SCAN_DETECTED (T1046) |
| Agent stopped | VM | `sudo systemctl stop securelog-agent` | AGENT_STOPPED |
| Database tampering | DB Browser for SQLite | Edit a stored log and write changes | INTEGRITY_FAILURE (T1565.001), status Tampered |

The same rule for the same attacker is not repeated within 10 minutes.

Offline audit (run on the auditor's machine, where K0 is kept):

```powershell
python "$env:USERPROFILE\Documents\SecureLog_Auditor\auditor_verify.py" --db backend\secure_logs.db --k0 "$env:USERPROFILE\Documents\SecureLog_Auditor\AUDITOR_K0.key"
```

Results recorded during development are in `TEST_REPORT.md`: 12 of 14 direct database attacks detected (the 2 misses are the documented open-batch limitation).

## Security notes

Secrets are never committed: `backend/.env`, `backend/keys/`, `backend/tls/`, `*.db` and `agent.conf` are in `.gitignore`. See `SECURITY_DESIGN.md` for the design and `TEST_REPORT.md` for test results.


