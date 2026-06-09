import { useEffect, useState } from "react";
import axios from "axios";
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
} from "lucide-react";
import "./App.css";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";

import { Bar } from "react-chartjs-2";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
const getSeverity = (eventType) => {
  if (!eventType) return "low";

  const event = eventType.toUpperCase();

  if (
    event.includes("FAILED") ||
    event.includes("ERROR") ||
    event.includes("DENIED") ||
    event.includes("TAMPER")
  ) {
    return "high";
  }

  if (
    event.includes("LOGIN") ||
    event.includes("AUTH") ||
    event.includes("ACCESS")
  ) {
    return "medium";
  }

  return "low";
};

function App() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [keyInfo, setKeyInfo] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [lastUpdated, setLastUpdated] = useState("");
  const [copied, setCopied] = useState("");
  const [activeNav, setActiveNav] = useState("dashboard");
  const [loading, setLoading] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);
  const [logLimit, setLogLimit] = useState(50);
  const [tamperLogId, setTamperLogId] = useState("");

  const [form, setForm] = useState({
    source: "Server-01",
    event_type: "LOGIN_FAILED",
    username: "admin",
    ip_address: "192.168.1.10",
    message: "Invalid password attempt",
  });

  const scrollToSection = (id) => {
    document.getElementById(id)?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  };

  const shortenHash = (hash, start = 12, end = 8) => {
    if (!hash) return "-";
    if (hash.length <= start + end) return hash;
    return `${hash.slice(0, start)}...${hash.slice(-end)}`;
  };

  const cleanSourceName = (source) => {
   
    if (!source) return "-";
    return source
      .replace("Ubuntu-Ubuntu-SecureLog-Server1", "Ubuntu Server")
      .replace("Ubuntu-SecureLog-Server1", "Ubuntu Server")
      .replace("Ubuntu-", "Ubuntu ");
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

  const refreshData = async (showMessage = true) => {
    try {
      const statsRes = await axios.get(`${API_URL}/dashboard/stats`);
      const logsRes = await axios.get(`${API_URL}/logs/?limit=${logLimit}`);
      const keyRes = await axios.get(`${API_URL}/keys/current`);
      setBackendOnline(true);

      setStats(statsRes.data);
      setLogs(logsRes.data);
      setKeyInfo(keyRes.data);
      setLastUpdated(new Date().toLocaleTimeString());
      setLastUpdated(new Date().toLocaleTimeString());
setBackendOnline(true);

      if (showMessage) {
        setResult({
          status: "Refreshed",
          message: "Dashboard data updated successfully",
          time: new Date().toLocaleTimeString(),
        });
      }
    } catch {
      setBackendOnline(false);
      setResult({
        
        status: "Backend Error",
        message: "Backend server is not responding. Make sure FastAPI is running.",
      });
    }
  };

 useEffect(() => {
  refreshData(false);

  const interval = setInterval(() => {
    refreshData(false);
  }, 5000);

  return () => clearInterval(interval);
}, [logLimit]);

  const addLog = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/logs/add`, form);
      setResult(res.data);
      await refreshData(false);
    } catch {
      setResult({ status: "Error", message: "Failed to add log." });
    } finally {
      setLoading(false);
    }
  };

  const verifyHashChain = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/verify/hash-chain`);
      setResult(res.data);
      await refreshData(false);
    } catch {
      setResult({ status: "Error", message: "Failed to verify hash chain." });
    } finally {
      setLoading(false);
    }
  };

  const generateMerkleRoot = async () => {
    setLoading(true);
    try {
      const batchId = stats?.latest_batch_id || 1;
      const res = await axios.post(`${API_URL}/merkle/generate/${batchId}`);
      setResult(res.data);
      await refreshData(false);
    } catch {
      setResult({ status: "Error", message: "Failed to generate Merkle Root." });
    } finally {
      setLoading(false);
    }
  };

  const verifyMerkleRoot = async () => {
    setLoading(true);
    try {
      const batchId = stats?.latest_batch_id || 1;
      const res = await axios.get(`${API_URL}/merkle/verify/${batchId}`);
      setResult(res.data);
      await refreshData(false);
    } catch {
      setResult({ status: "Error", message: "Failed to verify Merkle Root." });
    } finally {
      setLoading(false);
    }
  };

  const evolveKey = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/keys/evolve`);
      setResult(res.data);
      await refreshData(false);
    } catch {
      setResult({ status: "Error", message: "Failed to evolve forward-secure key." });
    } finally {
      setLoading(false);
    }
  };

  const simulateTampering = async () => {
    if (!tamperLogId) {
      setResult({ status: "Error", message: "Please enter a Log ID to tamper." });
      return;
    }
    setLoading(true);
    try {
      const res = await axios.put(`${API_URL}/verify/simulate-tamper/${tamperLogId}`);
      setResult(res.data);
      await refreshData(false);
    } catch {
      setResult({ status: "Error", message: "Failed to simulate tampering." });
    } finally {
      setLoading(false);
    }
  };

  const isValid = stats?.integrity_status === "Valid";
  const latestKeyHash =
    result?.forward_secure_key_hash ||
    result?.current_key_hash ||
    keyInfo?.current_key_hash;
  const latestKeyVersion = result?.key_version || keyInfo?.key_version || "-";
const filteredLogs = logs.filter((log) =>
  JSON.stringify(log)
    .toLowerCase()
    .includes(searchTerm.toLowerCase())
);
  const criticalCount = logs.filter(
    log => log.event_type?.includes("TAMPER")
  ).length;

  const highCount = logs.filter(
    log =>
      log.event_type === "AUTH_FAILED" ||
      log.event_type === "APP_LOGIN_FAILED" ||
      log.event_type === "SYSTEM_ERROR"
  ).length;

  const mediumCount = logs.filter(
    log =>
      log.event_type === "DATABASE_ACCESS" ||
      log.event_type === "AUTH_SUCCESS" ||
      log.event_type === "APP_LOGIN_SUCCESS"
  ).length;

  const lowCount = logs.filter(
    
    log =>
      log.event_type === "SESSION_OPENED" ||
      log.event_type === "SESSION_CLOSED" ||
      log.event_type === "FIREWALL_ALLOWED" ||
      log.event_type === "SERVICE_RESTARTED"
  ).length;
  const threatChartData = {
  labels: ["Critical", "High", "Medium", "Low"],
  datasets: [
    {
      label: "Security Events",
      data: [
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      ],
      backgroundColor: [
        "#ef4444",
        "#f97316",
        "#facc15",
        "#22c55e",
      ],
      borderRadius: 8,
    },
  ],
};

const threatChartOptions = {
  responsive: true,
  plugins: {
    legend: {
      labels: {
        color: "#e5eefc",
      },
    },
  },
  scales: {
    y: {
      ticks: {
        color: "#cbd5e1",
      },
      grid: {
        color: "rgba(255,255,255,0.08)",
      },
    },
    x: {
      ticks: {
        color: "#cbd5e1",
      },
      grid: {
        color: "rgba(255,255,255,0.05)",
      },
    },
  }
};
const recentThreats = logs.filter(
  
  (log) =>
     log.event_type?.includes("FAILED") ||
      log.event_type?.includes("ERROR") ||
      log.event_type?.includes("TAMPER")
  )
  .slice(0, 5);

const ipCounts = {};

logs.forEach((log) => {
  if (log.ip_address) {
    ipCounts[log.ip_address] =
      (ipCounts[log.ip_address] || 0) + 1;
  }
});

const topIPs = Object.entries(ipCounts)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 5);

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
          <button
            type="button"
            className={activeNav === "dashboard" ? "active" : ""}
            onClick={() => { scrollToSection("dashboard"); setActiveNav("dashboard"); }}
          >
            <Database size={18} /> Dashboard
          </button>

          <button
            type="button"
            className={activeNav === "logs" ? "active" : ""}
            onClick={() => { scrollToSection("logs"); setActiveNav("logs"); }}
          >
            <FileText size={18} /> Logs
          </button>

          <button
            type="button"
            className={activeNav === "hash-chain" ? "active" : ""}
            onClick={() => { scrollToSection("hash-chain"); setActiveNav("hash-chain"); }}
          >
            <Link2 size={18} /> Hash Chain
          </button>

          <button
            type="button"
            className={activeNav === "merkle-tree" ? "active" : ""}
            onClick={() => { scrollToSection("merkle-tree"); setActiveNav("merkle-tree"); }}
          >
            <GitBranch size={18} /> Merkle Tree
          </button>

          <button
            type="button"
            className={activeNav === "key-section" ? "active" : ""}
            onClick={() => { scrollToSection("key-section"); setActiveNav("key-section"); }}
          >
            <KeyRound size={18} /> Forward Key
          </button>
        </nav>

        <div className="integrityBox">
          <p>System Integrity</p>
          <div className={isValid ? "integrity valid" : "integrity tampered"}>
            {isValid ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
            {stats?.integrity_status || "No Logs"}
          </div>
        </div>
      </aside>

      <main className="main" id="dashboard">
        <header className="header">
  <div>
    <span className="label">FINAL YEAR PROJECT — BS CYBERSECURITY</span>
    <h1>Secure Log Management System</h1>
    <p>
      Tamper-evident log storage using SHA-256, Hash Chaining, Merkle
      Tree verification, and Forward-Secure Key Evolution.
    </p>
  </div>

  <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>

    <div
  className={`liveStatus ${
    backendOnline ? "online" : "offline"
  }`}
>
  {backendOnline
    ? "🟢 BACKEND CONNECTED"
    : "🔴 BACKEND DISCONNECTED"}
</div>
<div className="lastUpdated">
  Last Updated: {lastUpdated || "--:--:--"}
</div>
    <button
  className="refreshBtn"
  onClick={() => refreshData(true)}
  disabled={loading}
>
  {loading ? (
    <Loader2 size={16} className="spin" />
  ) : (
    <RefreshCw size={16} />
  )}
  Refresh
</button>
  </div>
</header>
{recentThreats.length > 0 && (
  <div className="attackAlert">
    🚨 SECURITY ALERT: {recentThreats.length} suspicious events detected
  </div>
)}
        <section className="stats">
          <div className="alertSummary">
  <div className="alertCard critical">
    <h3>{criticalCount}</h3>
    <p>Critical Events</p>
  </div>

  <div className="alertCard high">
    <h3>{highCount}</h3>
    <p>High Severity</p>
  </div>

  <div className="alertCard medium">
    <h3>{mediumCount}</h3>
    <p>Medium Severity</p>
  </div>

  <div className="alertCard low">
    <h3>{lowCount}</h3>
    <p>Low Severity</p>
  </div>
</div>
          <div className="statCard clickableCard" onClick={() => { scrollToSection("logs"); setActiveNav("logs"); }}>
            <div>
              <p>Total Logs</p>
              <h2>{stats?.total_logs ?? 0}</h2>
            </div>
            <Database size={28} />
          </div>

          <div className="statCard clickableCard" onClick={() => { scrollToSection("merkle-tree"); setActiveNav("merkle-tree"); }}>
            <div>
              <p>Merkle Roots</p>
              <h2>{stats?.total_merkle_roots ?? 0}</h2>
            </div>
            <GitBranch size={28} />
          </div>

          <div className="statCard clickableCard" onClick={() => { scrollToSection("hash-chain"); setActiveNav("hash-chain"); }}>
            <div>
              <p>Integrity Status</p>
              <h2 className={isValid ? "greenText" : "redText"}>
                {stats?.integrity_status || "No Logs"}
              </h2>
            </div>
            {isValid ? <CheckCircle size={28} /> : <AlertTriangle size={28} />}
          </div>

          <div className="statCard clickableCard" onClick={() => { scrollToSection("key-section"); setActiveNav("key-section"); }}>
            <div>
              <p>Key Version</p>
              <h2>{latestKeyVersion}</h2>
            </div>
            <KeyRound size={28} />
          </div>
        </section>

        <section className="gridTwo" id="hash-chain">
          <div className="panel">
            <div className="panelHeader">
              <h3>Add Security Log</h3>
              <span>Hash generated automatically</span>
            </div>

            <form className="logForm" onSubmit={addLog}>
              <div className="field">
                <label>Source</label>
                <input value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
              </div>

              <div className="field">
                <label>Event Type</label>
                <input value={form.event_type} onChange={(e) => setForm({ ...form, event_type: e.target.value })} />
              </div>

              <div className="field">
                <label>Username</label>
                <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
              </div>

              <div className="field">
                <label>IP Address</label>
                <input value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />
              </div>

              <div className="field full">
                <label>Message</label>
                <input value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })} />
              </div>

              <button className="primaryBtn" type="submit" disabled={loading}>
                {loading ? <Loader2 size={16} className="spin" /> : <Plus size={16} />}
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
              <button onClick={verifyHashChain} disabled={loading}>
                {loading ? <Loader2 size={16} className="spin" /> : <Link2 size={16} />}
                Verify Hash Chain
              </button>

              <button onClick={generateMerkleRoot} disabled={loading}>
                {loading ? <Loader2 size={16} className="spin" /> : <GitBranch size={16} />}
                Generate Merkle Root
              </button>

              <button onClick={verifyMerkleRoot} disabled={loading}>
                {loading ? <Loader2 size={16} className="spin" /> : <ShieldCheck size={16} />}
                Verify Merkle Root
              </button>

              <button onClick={evolveKey} disabled={loading}>
                {loading ? <Loader2 size={16} className="spin" /> : <KeyRound size={16} />}
                Evolve Forward Key
              </button>

              <div className="tamperRow">
                <input
                  type="number"
                  placeholder="Log ID to tamper..."
                  value={tamperLogId}
                  onChange={(e) => setTamperLogId(e.target.value)}
                  className="tamperInput"
                />
                <button className="danger" onClick={simulateTampering} disabled={loading}>
                  {loading ? <Loader2 size={16} className="spin" /> : <AlertTriangle size={16} />}
                  Simulate Tamper
                </button>
              </div>
            </div>
          </div>
        </section>

        <section className="gridTwo">
          <div className="panel">
            <div className="panelHeader">
              <h3>Latest API Result</h3>
              <span>System response</span>
            </div>
            <pre>{result ? JSON.stringify(result, null, 2) : "No action yet"}</pre>
          </div>

          <div className="panel" id="merkle-tree">
            <div className="panelHeader">
              <h3>Latest Merkle Root</h3>
              <span>SHA-256 root hash</span>
            </div>
            <div className="hashBox">
              {stats?.latest_merkle_root || "No Merkle Root generated yet"}
            </div>
          </div>
        </section>
        <section className="panel">
  <div className="panelHeader">
     <h3>System Health</h3>
    <span>Live Status</span>
  </div>

  <div className="healthGrid">
    <div className="healthItem">
      🟢 Backend Online
    </div>

    <div className="healthItem">
      {isValid
        ? "🟢 Hash Chain Valid"
        : "🔴 Hash Chain Broken"}
    </div>

    <div className="healthItem">
      🟢 Merkle Tree Active
    </div>

    <div className="healthItem">
      🟢 Forward Key Active
    </div>
  </div>
    <h3>Severity Distribution</h3>
    <span>Security Analytics</span>
  

  <div className="severityChart">

    <div className="chartRow">
      <span>Critical</span>
      <div
        className="chartBar criticalBar"
        style={{ width: `${criticalCount * 5}px` }}
      />
      <strong>{criticalCount}</strong>
    </div>

    <div className="chartRow">
      <span>High</span>
      <div
        className="chartBar highBar"
        style={{ width: `${highCount * 5}px` }}
      />
      <strong>{highCount}</strong>
    </div>

    <div className="chartRow">
      <span>Medium</span>
      <div
        className="chartBar mediumBar"
        style={{ width: `${mediumCount * 5}px` }}
      />
      <strong>{mediumCount}</strong>
    </div>

    <div className="chartRow">
      <span>Low</span>
      <div
        className="chartBar lowBar"
        style={{ width: `${lowCount * 5}px` }}
      />
      <strong>{lowCount}</strong>
    </div>

  </div>
</section>
<section className="panel">
  <div className="panelHeader">
    <h3>Top Active IP Addresses</h3>
    <span>Traffic Sources</span>
  </div>

  <div className="topIpList">
    {topIPs.map(([ip, count]) => (
      <div key={ip} className="ipRow">
        <span>{ip}</span>
        <strong>{count} events</strong>
      </div>
    ))}
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
                <h2>{latestKeyVersion}</h2>
              </div>
              <div className="keyMetric">
                <p>Protection Mode</p>
                <h2>Forward Secure</h2>
              </div>
            </div>

            <div className="keyHashBlock">
              <div>
                <p>Current Key Hash</p>
                <strong>{shortenHash(latestKeyHash, 18, 12)}</strong>
              </div>
              <button type="button" onClick={() => copyToClipboard(latestKeyHash, "key")}>
                <Copy size={15} />
                {copied === "key" ? "Copied" : "Copy"}
              </button>
            </div>

            <p className="keyNote">
              Each evolved key is generated using HMAC-SHA256 one-way key derivation.
              Older keys cannot be reconstructed from the current key hash, ensuring
              forward security even if the current key is compromised.
            </p>
          </div>

          <div className="panel">
            <div className="panelHeader">
              <h3>Cryptographic Flow</h3>
              <span>Integrity pipeline</span>
            </div>
            <div className="flowSteps">
              <div>Ubuntu Logs</div><span>→</span>
              <div>SHA-256 Hash</div><span>→</span>
              <div>Hash Chain</div><span>→</span>
              <div>Merkle Root</div><span>→</span>
              <div>Forward Key</div>
            </div>
          </div>
        </section>
<section className="panel">
  <div className="panelHeader">
    <h3>Threat Activity Overview</h3>
    <span>Live Security Events</span>
  </div>

  <Bar data={threatChartData}
  options={threatChartOptions}
   />
   <section className="panel">
  <div className="panelHeader">
    <h3>Recent Threat Feed</h3>
    <span>Latest Security Incidents</span>
  </div>

  <div className="threatFeed">
    {recentThreats.length === 0 ? (
      <p>No threats detected.</p>
    ) : (
      recentThreats.map((log, index) => (
        <div key={index} className="threatItem">
          <div>
            <strong>{log.event_type}</strong>
            <p>{log.source}</p>
          </div>

          <span>
            {new Date(log.created_at).toLocaleString()}
          </span>
        </div>
      ))
    )}
  </div>
</section>
</section>
        <section className="panel" id="logs">
          <div className="panelHeader">
            <h3>Recent Security Logs</h3>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <span>{logs.length} records shown</span>
              <select
                value={logLimit}
                onChange={(e) => setLogLimit(Number(e.target.value))}
                className="limitSelect"
              >
                <option value={50}>Last 50</option>
                <option value={100}>Last 100</option>
                <option value={250}>Last 250</option>
                <option value={500}>Last 500</option>
              </select>
            </div>
          </div>
<div style={{ marginBottom: "15px" }}>
  <input
    type="text"
    placeholder="Search logs by user, IP, event, source..."
    value={searchTerm}
    onChange={(e) => setSearchTerm(e.target.value)}
    className="searchInput"
  />
</div>
          <div className="tableWrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Source</th>
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
                {filteredLogs.map((log) => (
                  <tr key={log.id}>
                    <td>{log.id}</td>
                    <td style={{ whiteSpace: "nowrap", color: "#94a3b8", fontSize: "13px" }}>
                      {log.timestamp ? new Date(log.timestamp).toLocaleString() : "-"}
                    </td>
                    <td>
                      <span className="source sourcePill" title={log.source}>
                        <Server size={14} />
                        {cleanSourceName(log.source)}
                      </span>
                    </td>
                    <td>
  <span
    className={`eventPill event-${getSeverity(log.event_type)}`}
  >
    {log.event_type}
  </span>
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

          {copied && copied !== "key" && (
            <div className="copyToast">Hash copied to clipboard</div>
          )}
        </section>
        <div className="footerBar">
  Secure Log Management System | BS Cybersecurity FYP |
  SHA-256 • Hash Chain • Merkle Tree • Forward Secure Keys
</div>
      </main>
    </div>
  );
}

export default App;
