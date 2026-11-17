import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorMessage } from "./api";
import {
  ShieldCheck,
  FileText,
  Database,
  Link2,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Plus,
  Server,
  GitBranch,
  KeyRound,
  Copy,
  Loader2,
  LogOut,
  UserCircle,
  Bell,
  Search,
} from "lucide-react";
import "./App.css";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  LogarithmicScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";
import { Bar } from "react-chartjs-2";

ChartJS.register(CategoryScale, LinearScale, LogarithmicScale, BarElement, Title, Tooltip, Legend);

const POLL_MS = 5000;
const LEVELS = ["critical", "high", "medium", "low"];
const LEVEL_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const GOOD_STATUSES = ["Valid", "Sealed", "Included", "Refreshed", "Logged out"];
const BAD_STATUSES = ["Tampered", "Error", "Not Included", "Backend Error", "Rewrite Simulated", "Tampering Simulated"];

const shortenHash = (hash, start = 12, end = 8) => {
  if (!hash) return "-";
  if (hash.length <= start + end) return hash;
  return `${hash.slice(0, start)}...${hash.slice(-end)}`;
};

// The backend sends UTC times; add "Z" when the time has no timezone so the
// browser converts it to local time instead of treating it as local already.
const formatTime = (iso) => {
  if (!iso) return "-";
  const utc = /([zZ]|[+-]\d\d:\d\d)$/.test(iso) ? iso : `${iso}Z`;
  return new Date(utc).toLocaleString();
};

const cleanSourceName = (source) => {
  const toDate = (iso) =>
  iso ? new Date(/([zZ]|[+-]\d\d:\d\d)$/.test(iso) ? iso : `${iso}Z`) : null;

const timeAgo = (iso) => {
  const d = toDate(iso);
  if (!d) return "never";
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
};
  if (!source) return "-";
  return source.replace("Ubuntu-", "Ubuntu ");
};

function App({ user, onLogout }) {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [logsTotal, setLogsTotal] = useState(0);
  const [alerts, setAlerts] = useState([]);
  const [result, setResult] = useState(null);
  const [lastUpdated, setLastUpdated] = useState("");
  const [copied, setCopied] = useState("");
  const [activeNav, setActiveNav] = useState("dashboard");
  const [busy, setBusy] = useState("");
  const [backendOnline, setBackendOnline] = useState(false);

  const [logLimit, setLogLimit] = useState(50);
  const [searchInput, setSearchInput] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");

  const [tamperLogId, setTamperLogId] = useState("");
  const [proofLogId, setProofLogId] = useState("");
  const [proof, setProof] = useState(null);

  const [form, setForm] = useState({
    source: "Server-01",
    event_type: "LOGIN_FAILED",
    username: "admin",
    ip_address: "192.168.1.10",
    message: "Invalid password attempt",
  });

  const inFlight = useRef(false);

  // ---------------------------------------------------------------- data
  const refreshData = useCallback(
    async (showMessage = false) => {
      if (inFlight.current) return;
      inFlight.current = true;
      try {
        const params = new URLSearchParams({ limit: String(logLimit) });
        if (searchTerm) params.set("q", searchTerm);
        if (severityFilter) params.set("severity", severityFilter);

        const [statsRes, logsRes, alertsRes] = await Promise.all([
          api.get("/dashboard/stats"),
          api.get(`/logs/?${params.toString()}`),
          api.get("/dashboard/alerts?limit=5"),
        ]);
        setStats(statsRes.data);
        setLogs(logsRes.data.items);
        setLogsTotal(logsRes.data.total);
        setAlerts(alertsRes.data);
        setBackendOnline(true);
        setLastUpdated(new Date().toLocaleTimeString());
        if (showMessage) {
          setResult({ status: "Refreshed", message: "Dashboard data updated." });
        }
      } catch (err) {
        if (err?.response?.status === 401) return; // AuthGate shows the login page
        setBackendOnline(Boolean(err?.response));
        setResult({
          status: "Backend Error",
          message: errorMessage(err, "The backend returned an error."),
        });
      } finally {
        inFlight.current = false;
      }
    },
    [logLimit, searchTerm, severityFilter]
  );

  // Poll every 5 s, but not while the browser tab is hidden.
  useEffect(() => {
    refreshData(false);
    const interval = setInterval(() => {
      if (!document.hidden) refreshData(false);
    }, POLL_MS);
    return () => clearInterval(interval);
  }, [refreshData]);

  // Search runs on the server, 400 ms after the user stops typing.
  useEffect(() => {
    const t = setTimeout(() => setSearchTerm(searchInput.trim()), 400);
    return () => clearTimeout(t);
  }, [searchInput]);

  // Run one button's action: show its spinner, show the result, refresh.
  const runAction = async (name, request, fallback) => {
    setBusy(name);
    try {
      const res = await request();
      setResult(res.data);
      await refreshData(false);
      return res.data;
    } catch (err) {
      setResult({ status: "Error", message: errorMessage(err, fallback) });
      return null;
    } finally {
      setBusy("");
    }
  };

  // ---------------------------------------------------------------- actions
  const addLog = (e) => {
    e.preventDefault();
    runAction("add", () => api.post("/logs/manual", form), "Failed to add log.");
  };

  const verifyHashChain = () =>
    runAction("verify", () => api.get("/verify/hash-chain"), "Failed to verify the log.");

  const sealBatch = () =>
    runAction("seal", () => api.post("/merkle/seal"), "Failed to seal the open batch.");

  const verifyBatch = (batchId) => {
    if (!batchId) {
      setResult({ status: "Nothing to verify", message: "No batch has been sealed yet." });
      return;
    }
    runAction(`batch-${batchId}`, () => api.get(`/merkle/verify/${batchId}`),
      "Failed to verify the batch.");
  };

  const getProof = async () => {
    if (!proofLogId) {
      setResult({ status: "Error", message: "Enter a log ID to prove." });
      return;
    }
    const data = await runAction("proof", () => api.get(`/merkle/proof/${proofLogId}`),
      "Failed to build the Merkle proof.");
    setProof(data);
  };

  const simulate = (kind) => {
    if (!tamperLogId) {
      setResult({ status: "Error", message: "Enter a log ID first." });
      return;
    }
    runAction(kind, () => api.put(`/verify/simulate-${kind}/${tamperLogId}`),
      `Failed to simulate ${kind}.`);
  };

  const copyToClipboard = async (value, label) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      setTimeout(() => setCopied(""), 1400);
    } catch {
      setCopied("");
    }
  };

  const goTo = (id) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
    setActiveNav(id);
  };

  // ---------------------------------------------------------------- derived
  const integrity = stats?.integrity;
  const isValid = stats?.integrity_status === "Valid";
  const counts = stats?.severity_counts || { critical: 0, high: 0, medium: 0, low: 0 };
  const maxCount = Math.max(1, ...LEVELS.map((l) => counts[l]));
  const openPercent = stats
    ? Math.min(100, Math.round((stats.open_batch_logs / stats.batch_size) * 100))
    : 0;

  const agentList = stats?.agents || [];
  const agentsOnline = agentList.filter((a) => a.status === "online").length;
  // Serious alerts from the last hour get a banner at the top.
  // An agent alert is resolved once that agent is online again.
  const agentAlertResolved = (a) =>
    (a.alert_type === "AGENT_STOPPED" || a.alert_type === "AGENT_SILENT") &&
    agentList.some(
      (ag) => ag.status === "online" && (a.description || "").includes(`'${ag.agent_id}'`)
    );
  const recentAlert = alerts.find(
    (a) =>
      (a.severity === "critical" || a.severity === "high") &&
      !agentAlertResolved(a) &&
      Date.now() - (toDate(a.created_at)?.getTime() ?? 0) < 60 * 60 * 1000
  );

  const resultTone = !result
    ? ""
    : GOOD_STATUSES.includes(result.status)
    ? "good"
    : BAD_STATUSES.includes(result.status)
    ? "bad"
    : "neutral";
  const threatChartData = {
    labels: LEVELS.map((l) => LEVEL_LABEL[l]),
    datasets: [
      {
        label: "Events (all logs)",
        data: LEVELS.map((l) => counts[l]),
        backgroundColor: ["#ef4444", "#f97316", "#facc15", "#22c55e"],
        borderRadius: 8,
      },
    ],
  };

  const threatChartOptions = {
    responsive: true,
    plugins: { legend: { labels: { color: "#e5eefc" } } },
    scales: {
       y: {
        type: "logarithmic",
        title: { display: true, text: "Events (log scale)", color: "#94a3b8" },
        ticks: { color: "#cbd5e1" },
        grid: { color: "rgba(255,255,255,0.08)" },
      },
      x: { ticks: { color: "#cbd5e1" }, grid: { color: "rgba(255,255,255,0.05)" } },
    },
  };

  const spinnerOr = (name, icon) =>
    busy === name ? <Loader2 size={16} className="spin" /> : icon;

  // ---------------------------------------------------------------- view
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brandIcon">
            <ShieldCheck size={26} />
          </div>
          <div>
            <h2>SecureLog</h2>
            <p>Cyber Integrity Console</p>
          </div>
        </div>

        <nav className="menu">
          {[
            ["dashboard", <Database size={18} />, "Dashboard"],
            ["logs", <FileText size={18} />, "Logs"],
            ["hash-chain", <Link2 size={18} />, "Hash Chain"],
            ["merkle-tree", <GitBranch size={18} />, "Merkle Tree"],
            ["key-section", <KeyRound size={18} />, "Forward Key"],
          ].map(([id, icon, label]) => (
            <button
              key={id}
              type="button"
              className={activeNav === id ? "active" : ""}
              onClick={() => goTo(id)}
            >
              {icon} {label}
            </button>
          ))}
        </nav>

        <div className="integrityBox">
          <p>System Integrity</p>
          <div className={isValid ? "integrity valid" : "integrity tampered"}>
            {isValid ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
            {stats?.integrity_status || "Checking..."}
          </div>
          {integrity?.checked_at && (
            <p className="integrityMeta">
              Checked {new Date(integrity.checked_at).toLocaleTimeString()} ·{" "}
              every {integrity.interval_seconds}s
            </p>
          )}
        </div>
      </aside>

      <main className="main" id="dashboard">
        <header className="header">
          <div>
            <span className="label">FINAL YEAR PROJECT — BS CYBERSECURITY</span>
            <h1>Secure Log Management System</h1>
            <p>
              Tamper-evident log storage using SHA-256, Hash Chaining, Merkle Tree
              verification, and Forward-Secure Key Evolution.
            </p>
          </div>

          <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
            <div className={`liveStatus ${backendOnline ? "online" : "offline"}`}>
              {backendOnline ? "🟢 BACKEND CONNECTED" : "🔴 BACKEND DISCONNECTED"}
            </div>
            <div className="lastUpdated">Last Updated: {lastUpdated || "--:--:--"}</div>
            <div className="userBadge" title={`Session expires ${user?.expires_at ?? ""}`}>
              <UserCircle size={16} /> {user?.username}
            </div>
            <button className="refreshBtn" onClick={onLogout}>
              <LogOut size={16} /> Logout
            </button>
            <button className="refreshBtn" onClick={() => refreshData(true)}>
              <RefreshCw size={16} /> Refresh
            </button>
          </div>
        </header>

        {stats && !isValid && (
          <div className="attackAlert">
            🚨 INTEGRITY ALERT: {integrity?.problems_found} problem(s) found
            {integrity?.problem_types?.length > 0 && ` (${integrity.problem_types.join(", ")})`}.
            Click “Verify Hash Chain” for details.
          </div>
        )}

        <section className="stats">
          <div className="alertSummary">
            {LEVELS.map((level) => (
              <div
                key={level}
                className={`alertCard ${level} clickableCard`}
                onClick={() => {
                  setSeverityFilter(level);
                  goTo("logs");
                }}
                title={`Show ${LEVEL_LABEL[level].toLowerCase()} events`}
              >
                <h3>{counts[level]}</h3>
                <p>{level === "critical" ? "Critical Events" : `${LEVEL_LABEL[level]} Severity`}</p>
              </div>
            ))}
          </div>

          <div className="statCard clickableCard" onClick={() => goTo("logs")}>
            <div>
              <p>Total Logs</p>
              <h2>{stats?.total_logs ?? 0}</h2>
            </div>
            <Database size={28} />
          </div>
          <div className="statCard clickableCard" onClick={() => goTo("merkle-tree")}>
            <div>
              <p>Sealed Batches</p>
              <h2>{stats?.total_merkle_roots ?? 0}</h2>
            </div>
            <GitBranch size={28} />
          </div>
          <div className="statCard clickableCard" onClick={() => goTo("hash-chain")}>
            <div>
              <p>Integrity Status</p>
              <h2 className={isValid ? "greenText" : "redText"}>
                {stats?.integrity_status || "Checking..."}
              </h2>
            </div>
            {isValid ? <CheckCircle size={28} /> : <AlertTriangle size={28} />}
          </div>
          <div className="statCard clickableCard" onClick={() => goTo("key-section")}>
            <div>
              <p>Key Version</p>
              <h2>{stats?.key_version ?? "-"}</h2>
            </div>
            <KeyRound size={28} />
          </div>
        </section>

        <section className="gridTwo" id="hash-chain">
          <div className="panel">
            <div className="panelHeader">
              <h3>Add Security Log</h3>
              <span>Recorded as dashboard:{user?.username}</span>
            </div>
            <form className="logForm" onSubmit={addLog}>
              {[
                ["source", "Source"],
                ["event_type", "Event Type"],
                ["username", "Username"],
                ["ip_address", "IP Address"],
              ].map(([key, label]) => (
                <div className="field" key={key}>
                  <label>{label}</label>
                  <input
                    value={form[key]}
                    onChange={(e) => setForm({ ...form, [key]: e.target.value })}
                  />
                </div>
              ))}
              <div className="field full">
                <label>Message</label>
                <input
                  value={form.message}
                  onChange={(e) => setForm({ ...form, message: e.target.value })}
                />
              </div>
              <button className="primaryBtn" type="submit" disabled={Boolean(busy)}>
                {spinnerOr("add", <Plus size={16} />)}
                Add Log
              </button>
            </form>
          </div>

          <div className="panel">
            <div className="panelHeader">
              <h3>Security Actions</h3>
              <span>Verification controls</span>
            </div>
            <div className="actions">
              <button onClick={verifyHashChain} disabled={Boolean(busy)}>
                {spinnerOr("verify", <Link2 size={16} />)}
                Verify Hash Chain
              </button>
              <button onClick={sealBatch} disabled={Boolean(busy)}>
                {spinnerOr("seal", <GitBranch size={16} />)}
                Seal Batch Now
              </button>
              <button
                onClick={() => verifyBatch(stats?.latest_batch_id)}
                disabled={Boolean(busy)}
              >
                {spinnerOr(`batch-${stats?.latest_batch_id}`, <ShieldCheck size={16} />)}
                Verify Latest Batch
              </button>

              {user?.demo_mode && (
                <div className="tamperRow">
                  <input
                    type="number"
                    placeholder="Log ID to attack..."
                    value={tamperLogId}
                    onChange={(e) => setTamperLogId(e.target.value)}
                    className="tamperInput"
                  />
                  <button className="danger" onClick={() => simulate("tamper")} disabled={Boolean(busy)}>
                    {spinnerOr("tamper", <AlertTriangle size={16} />)}
                    Simulate Tamper
                  </button>
                  <button className="danger" onClick={() => simulate("rewrite")} disabled={Boolean(busy)}>
                    {spinnerOr("rewrite", <AlertTriangle size={16} />)}
                    Simulate Rewrite
                  </button>
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="gridTwo">
          <div className="panel">
            <div className="panelHeader">
              <h3>Latest Result</h3>
              <span>System response</span>
            </div>
            {result ? (
              <>
                <div className={`resultBadge ${resultTone}`}>
                  {result.status || "Done"}
                </div>
                {(result.message || result.expected_result || result.note) && (
                  <p className="resultMessage">
                    {result.message || result.expected_result || result.note}
                  </p>
                )}
                {Array.isArray(result.problems) && result.problems.length > 0 && (
                  <ul className="problemList">
                    {result.problems.slice(0, 8).map((p, i) => (
                      <li key={i}>
                        {typeof p === "string" ? p : (
                          <>
                            <strong>{p.type}</strong> {p.detail}
                            {p.log_id !== undefined && ` (log ${p.log_id})`}
                            {p.batch_id !== undefined && ` (batch ${p.batch_id})`}
                          </>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                <details className="rawJson">
                  <summary>Show full response</summary>
                  <pre>{JSON.stringify(result, null, 2)}</pre>
                </details>
              </>
            ) : (
              <pre>No action yet</pre>
            )}
          </div>

          <div className="panel">
            <div className="panelHeader">
              <h3>System Health</h3>
              <span>Live status</span>
            </div>
            <div className="healthGrid">
              <div className="healthItem">
                {backendOnline ? "🟢 Backend online" : "🔴 Backend offline"}
              </div>
              <div className="healthItem">
                {isValid ? "🟢" : "🔴"} Log integrity: {stats?.integrity_status || "-"}
                {integrity && (
                  <small> · {integrity.total_logs_verified} logs in {integrity.duration_ms} ms</small>
                )}
              </div>
              <div className="healthItem">
                {stats?.total_merkle_roots > 0 ? "🟢" : "⚪"} Merkle: {stats?.total_merkle_roots ?? 0}{" "}
                batches sealed
              </div>
              <div className="healthItem">
                🟢 Forward key: version {stats?.key_version ?? "-"}
              </div>
              <div className="healthItem">
                {stats?.total_alerts > 0 ? "🟠" : "🟢"} Alerts raised: {stats?.total_alerts ?? 0}
              </div>
            </div>

            <div className="panelHeader" style={{ marginTop: "18px" }}>
              <h3>Severity Distribution</h3>
              <span>All {stats?.total_logs ?? 0} logs</span>
            </div>
            <div className="severityChart">
              {LEVELS.map((level) => (
                <div className="chartRow" key={level}>
                  <span>{LEVEL_LABEL[level]}</span>
                  <div
                    className={`chartBar ${level}Bar`}
                    style={{ width: `${(counts[level] / maxCount) * 100}%`, maxWidth: "60%" }}
                  />
                  <strong>{counts[level]}</strong>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="gridTwo" id="merkle-tree">
          <div className="panel">
            <div className="panelHeader">
              <h3>Merkle Batches</h3>
              <span>Sealed with HMAC, append-only</span>
            </div>

            <p className="keyNote">
              Open batch {stats?.open_batch_id ?? "-"}: {stats?.open_batch_logs ?? 0}/
              {stats?.batch_size ?? 100} logs (seals when full or after {Math.round((stats?.seal_max_age_seconds ?? 600) / 60)} min)
            </p>
            <div className="progressTrack">
              <div className="progressFill" style={{ width: `${openPercent}%` }} />
            </div>

            {stats?.recent_batches?.length ? (
              <div className="tableWrapper">
                <table className="batchTable">
                  <thead>
                    <tr>
                      <th>Batch</th>
                      <th>Logs</th>
                      <th>Merkle Root</th>
                      <th>Sealed</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recent_batches.map((b) => (
                      <tr key={b.batch_id}>
                        <td><span className="batchPill">{b.batch_id}</span></td>
                        <td>
                          {b.total_logs} <small>(#{b.first_log_id}–{b.last_log_id})</small>
                        </td>
                        <td className="hash" title={b.root_hash}>{shortenHash(b.root_hash, 10, 6)}</td>
                        <td style={{ whiteSpace: "nowrap" }}>{formatTime(b.created_at)}</td>
                        <td>
                          <button
                            className="smallBtn"
                            onClick={() => verifyBatch(b.batch_id)}
                            disabled={Boolean(busy)}
                          >
                            {busy === `batch-${b.batch_id}` ? <Loader2 size={13} className="spin" /> : "Verify"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="hashBox">No batch sealed yet</div>
            )}
          </div>

          <div className="panel">
            <div className="panelHeader">
              <h3>Merkle Inclusion Proof</h3>
              <span>Prove one log is in its sealed batch</span>
            </div>
            <div className="tamperRow">
              <input
                type="number"
                placeholder="Log ID..."
                value={proofLogId}
                onChange={(e) => setProofLogId(e.target.value)}
                className="tamperInput"
              />
              <button className="primaryBtn" onClick={getProof} disabled={Boolean(busy)}>
                {spinnerOr("proof", <ShieldCheck size={16} />)}
                Get Proof
              </button>
            </div>
            {proof && proof.proof && (
              <div className="proofBox">
                <div className={`resultBadge ${proof.status === "Included" ? "good" : "bad"}`}>
                  {proof.status}
                </div>
                <p className="keyNote">
                  Log {proof.log_id} is leaf {proof.leaf_index} of batch {proof.batch_id}. Only{" "}
                  <strong>{proof.proof_length}</strong> sibling hashes are needed to reach the root,
                  instead of reading every log in the batch.
                </p>
                <ol className="proofPath">
                  <li className="hash">leaf: {shortenHash(proof.entry_hash, 10, 6)}</li>
                  {proof.proof.map((step, i) => (
                    <li key={i} className="hash">
                      + {step.position} sibling {shortenHash(step.sibling, 10, 6)}
                    </li>
                  ))}
                  <li className="hash">= root: {shortenHash(proof.root_hash, 10, 6)}</li>
                </ol>
              </div>
            )}
            {proof && !proof.proof && <p className="keyNote">{proof.message}</p>}
          </div>
        </section>

        <section className="gridTwo">
          <div className="panel">
            <div className="panelHeader">
              <h3>Threat Activity Overview</h3>
              <span>All logs by severity</span>
            </div>
            <Bar data={threatChartData} options={threatChartOptions} />
          </div>

          <div className="panel">
            <div className="panelHeader">
              <h3>Recent Threat Feed</h3>
              <span>Latest critical and high events</span>
            </div>
            <div className="threatFeed">
              {!stats?.recent_threats?.length ? (
                <p>No threats detected.</p>
              ) : (
                stats.recent_threats.map((log) => (
                  <div key={log.id} className="threatItem">
                    <div>
                      <strong>
                        <div className={`eventPill event-${log.severity}`} style={{ display: "inline-block" }}>
                          {log.event_type}
                        </div>
                      </strong>
                      <p>
                        #{log.id} · {log.username} · {log.ip_address} · {log.agent_id}
                      </p>
                    </div>
                    <span>{formatTime(log.event_time || log.timestamp)}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>

        <section className="gridTwo">
          <div className="panel">
            <div className="panelHeader">
              <h3>
                <Bell size={16} style={{ verticalAlign: "-2px" }} /> Integrity Alerts
              </h3>
              <span>Raised automatically by the monitor</span>
            </div>
            <div className="threatFeed">
              {alerts.length === 0 ? (
                <p>No integrity alerts. The log has never failed a check.</p>
              ) : (
                alerts.map((a) => (
                  <div key={a.id} className="threatItem alertItem">
                    <div>
                      <strong>{a.alert_type}</strong>
                      <p>{a.description}</p>
                    </div>
                    <span>{formatTime(a.created_at)}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panelHeader">
              <h3>Top Active IP Addresses</h3>
              <span>Across all logs</span>
            </div>
            <div className="topIpList">
              {!stats?.top_ips?.length ? (
                <p>No data yet.</p>
              ) : (
                stats.top_ips.map(({ ip, count }) => (
                  <div
                    key={ip}
                    className="ipRow clickableCard"
                    onClick={() => {
                      setSearchInput(ip);
                      setSeverityFilter("");
                      goTo("logs");
                    }}
                    title="Show logs from this IP"
                  >
                    <span>{ip}</span>
                    <strong>{count} events</strong>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>

        <section className="gridTwo" id="key-section">
          <div className="panel keyPanel">
            <div className="panelHeader">
              <h3>Forward-Secure Key State</h3>
              <span>HMAC-SHA256 key evolution</span>
            </div>
            <div className="keyGrid">
              <div className="keyMetric">
                <p>Current Key Version</p>
                <h2>{stats?.key_version ?? "-"}</h2>
              </div>
              <div className="keyMetric">
                <p>Protection Mode</p>
                <h2>Forward Secure</h2>
              </div>
            </div>
            <div className="keyHashBlock">
              <div>
                <p>K0 Fingerprint (public commitment)</p>
                <strong>{shortenHash(stats?.k0_fingerprint, 18, 12)}</strong>
              </div>
              <button type="button" onClick={() => copyToClipboard(stats?.k0_fingerprint, "key")}>
                <Copy size={15} />
                {copied === "key" ? "Copied" : "Copy"}
              </button>
            </div>
            <p className="keyNote">
              Each log is MACed with the key of its batch. When a batch is sealed, the key
              evolves one-way (K<sub>b+1</sub> = SHA-256(K<sub>b</sub>)) and the old key is
              destroyed, so a later compromise cannot forge earlier batches. The secret key is
              never sent to this dashboard; only the auditor holding K0 can check old seals.
            </p>
          </div>

          <div className="panel">
            <div className="panelHeader">
              <h3>Cryptographic Flow</h3>
              <span>Integrity pipeline</span>
            </div>
            <div className="flowSteps">
              <div>Ubuntu Logs</div>
              <span>→</span>
              <div>Hash Chain</div>
              <span>→</span>
              <div>HMAC (K<sub>b</sub>)</div>
              <span>→</span>
              <div>Merkle Root</div>
              <span>→</span>
              <div>Seal + Evolve Key</div>
            </div>
          </div>
        </section>

        <section className="panel" id="logs">
          <div className="panelHeader">
            <h3>Security Logs</h3>
            <span>
              Showing {logs.length} of {logsTotal}
              {searchTerm || severityFilter ? " matching" : ""} logs
            </span>
          </div>

          <div className="filterRow">
            <div className="searchWrap">
              <Search size={16} />
              <input
                type="text"
                placeholder="Search all logs: user, IP, event, message, agent, or log ID..."
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                className="searchInput"
              />
            </div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="limitSelect"
            >
              <option value="">All severities</option>
              {LEVELS.map((l) => (
                <option key={l} value={l}>{LEVEL_LABEL[l]}</option>
              ))}
            </select>
            <select
              value={logLimit}
              onChange={(e) => setLogLimit(Number(e.target.value))}
              className="limitSelect"
            >
              {[50, 100, 250, 500].map((n) => (
                <option key={n} value={n}>Last {n}</option>
              ))}
            </select>
            {(searchInput || severityFilter) && (
              <button
                className="smallBtn"
                onClick={() => {
                  setSearchInput("");
                  setSeverityFilter("");
                }}
              >
                Clear
              </button>
            )}
          </div>

          <div className="tableWrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Source</th>
                  <th>Agent</th>
                  <th>Event Type</th>
                  <th>User</th>
                  <th>IP Address</th>
                  <th>Message</th>
                  <th>Previous Hash</th>
                  <th>Current Hash</th>
                  <th>Batch</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 && (
                  <tr>
                    <td colSpan={11} style={{ textAlign: "center", color: "#94a3b8" }}>
                      No logs found.
                    </td>
                  </tr>
                )}
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td>{log.id}</td>
                                        <td
                      style={{ whiteSpace: "nowrap", color: "#94a3b8", fontSize: "13px" }}
                      title={`Happened: ${formatTime(log.event_time)}\nReceived: ${formatTime(log.timestamp)}`}
                    >
                      {formatTime(log.event_time || log.timestamp)}
                    </td>
                    <td>
                      <span className="source sourcePill" title={log.source}>
                        <Server size={14} />
                        {cleanSourceName(log.source)}
                      </span>
                    </td>
                    <td style={{ whiteSpace: "nowrap", fontSize: "13px" }}>{log.agent_id}</td>
                    <td>
                      <span className={`eventPill event-${log.severity}`}>{log.event_type}</span>
                    </td>
                    <td>{log.username || "-"}</td>
                    <td>{log.ip_address || "-"}</td>
                    <td className="messageCell" title={log.message}>{log.message}</td>
                    <td className="hash hashCell" title={log.previous_hash}>
                      <span>{shortenHash(log.previous_hash)}</span>
                      <button type="button" onClick={() => copyToClipboard(log.previous_hash, `prev-${log.id}`)}>
                        <Copy size={13} />
                      </button>
                    </td>
                    <td className="hash hashCell" title={log.current_hash}>
                      <span>{shortenHash(log.current_hash)}</span>
                      <button type="button" onClick={() => copyToClipboard(log.current_hash, `curr-${log.id}`)}>
                        <Copy size={13} />
                      </button>
                    </td>
                    <td><span className="batchPill">{log.batch_id}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {copied && copied !== "key" && <div className="copyToast">Hash copied to clipboard</div>}
        </section>

        <div className="footerBar">
          Secure Log Management System | BS Cybersecurity FYP | SHA-256 • Hash Chain •
          Merkle Tree • Forward Secure Keys
        </div>
      </main>
    </div>
  );
}

export default App;
function toDate(iso) {
  if (!iso) return null;
  return new Date(/([zZ]|[+-]\d\d:\d\d)$/.test(iso) ? iso : `${iso}Z`);
}

function timeAgo(iso) {
  const d = toDate(iso);
  if (!d) return "never";
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}