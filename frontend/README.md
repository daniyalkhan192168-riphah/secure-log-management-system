# SecureLog dashboard (React + Vite)

The SOC-style dashboard for SecureLog. Full setup, running and testing
instructions for the whole project are in the main [README](../README.md).

## Run

```powershell
cd frontend
npm install                                              # first time only
"VITE_API_URL=https://127.0.0.1:8000" | Set-Content .env.local   # first time only
npm run dev                                              # open http://localhost:5173
```

The backend must be running over HTTPS first (see the main README). If the
browser has never visited the backend, open https://127.0.0.1:8000 once and
accept the SecureLog certificate, or trust `backend/tls/ca.crt` in Windows.

## Pages

- **Security Overview**: posture score, KPI cards, event timeline, severity
  distribution, MITRE ATT&CK tactics, detection rules, top IPs/users/event
  types, live event stream, latest alerts, endpoints.
- **Security Alerts**: every alert with severity, rule, MITRE technique and an
  evidence link to the log that raised it.
- **Threat Hunting**: search all logs by IP, user, event type or log ID, filter
  by severity, expand a log to see its hashes and HMAC tag.
- **Integrity & Ledger**: full verification, forward-secure key state, sealed
  Merkle batches with per-batch Verify, and manual sealing.
- **Agents**: registered agents, heartbeat status and rollback witness.

## Files

- `src/App.jsx`, `src/App.css`: the dashboard
- `src/Login.jsx`, `src/AuthGate.jsx`: login page and session handling
- `src/api.js`: API client (adds the login token, logs out on 401)
