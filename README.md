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
| `scripts/` | Test runner, attack lab, offline auditor, log generator |

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
python manage.py add-agent       # creates an API key for the Ubuntu agent
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

```powershell
python scripts\run_all_tests.py                                   # 65 automated tests + attack lab
python scripts\attack_lab.py                                      # 14 database attacks
python scripts\auditor_verify.py --db backend\secure_logs.db --k0 <path-to-offline>\AUDITOR_K0.key   # K0 is kept off the server
```

Results: 65/65 tests pass; 12 of 14 database attacks detected (the 2 misses are the documented open-batch limitation); full offline audit of about 14,000 logs in 0.58 s.

## Security notes

Secrets are never committed: `backend/.env`, `backend/keys/`, `backend/tls/`, `*.db` and `agent.conf` are in `.gitignore`. See `SECURITY_DESIGN.md` for the design and `TEST_REPORT.md` for test results.


