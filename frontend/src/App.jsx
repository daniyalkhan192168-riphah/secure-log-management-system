import { useEffect, useState } from "react";
import axios from "axios";
import {
  ShieldCheck,
  FileText,
  Database,
  Link2,
  Fingerprint,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Plus,
  Server,
  GitBranch,
  KeyRound,
  Copy,
} from "lucide-react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [keyInfo, setKeyInfo] = useState(null);
  const [copied, setCopied] = useState("");

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

      setTimeout(() => {
        setCopied("");
      }, 1400);
    } catch (error) {
      setCopied("");
    }
  };

  const refreshData = async (showMessage = true) => {
    try {
      const statsRes = await axios.get(`${API_URL}/dashboard/stats`);
      const logsRes = await axios.get(`${API_URL}/logs/`);
      const keyRes = await axios.get(`${API_URL}/keys/current`);

      setStats(statsRes.data);
      setLogs(logsRes.data);
      setKeyInfo(keyRes.data);

      if (showMessage) {
        setResult({
          status: "Refreshed",
          message: "Dashboard data updated successfully",
          time: new Date().toLocaleTimeString(),
        });
      }
    } catch (error) {
      setResult({
        status: "Backend Error",
        message:
          "Backend server is not responding. Make sure FastAPI is running.",
      });
    }
  };

  useEffect(() => {
    refreshData(false);
  }, []);

  const addLog = async (e) => {
    e.preventDefault();

    try {
      const res = await axios.post(`${API_URL}/logs/add`, form);
      setResult(res.data);
      await refreshData(false);
    } catch (error) {
      setResult({
        status: "Error",
        message: "Failed to add log.",
      });
    }
  };

  const verifyHashChain = async () => {
    try {
      const res = await axios.get(`${API_URL}/verify/hash-chain`);
      setResult(res.data);
      await refreshData(false);
    } catch (error) {
      setResult({
        status: "Error",
        message: "Failed to verify hash chain.",
      });
    }
  };

  const generateMerkleRoot = async () => {
    try {
      const batchId = stats?.latest_batch_id || 1;
      const res = await axios.post(`${API_URL}/merkle/generate/${batchId}`);
      setResult(res.data);
      await refreshData(false);
    } catch (error) {
      setResult({
        status: "Error",
        message: "Failed to generate Merkle Root.",
      });
    }
  };

  const verifyMerkleRoot = async () => {
    try {
      const batchId = stats?.latest_batch_id || 1;
      const res = await axios.get(`${API_URL}/merkle/verify/${batchId}`);
      setResult(res.data);
      await refreshData(false);
    } catch (error) {
      setResult({
        status: "Error",
        message: "Failed to verify Merkle Root.",
      });
    }
  };

  const evolveKey = async () => {
    try {
      const res = await axios.post(`${API_URL}/keys/evolve`);
      setResult(res.data);
      await refreshData(false);
    } catch (error) {
      setResult({
        status: "Error",
        message: "Failed to evolve forward-secure key.",
      });
    }
  };

  const simulateTampering = async () => {
    const logId = prompt("Enter Log ID to tamper:", "1");
    if (!logId) return;

    try {
      const res = await axios.put(`${API_URL}/verify/simulate-tamper/${logId}`);
      setResult(res.data);
      await refreshData(false);
    } catch (error) {
      setResult({
        status: "Error",
        message: "Failed to simulate tampering.",
      });
    }
  };

  const isValid = stats?.integrity_status === "Valid";
  const latestKeyHash =
    result?.forward_secure_key_hash ||
    result?.current_key_hash ||
    keyInfo?.current_key_hash;

  const latestKeyVersion =
    result?.key_version || keyInfo?.key_version || "-";

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
            className="active"
            onClick={() => scrollToSection("dashboard")}
          >
            <Database size={18} />
            Dashboard
          </button>

          <button type="button" onClick={() => scrollToSection("logs")}>
            <FileText size={18} />
            Logs
          </button>

          <button type="button" onClick={() => scrollToSection("hash-chain")}>
            <Link2 size={18} />
            Hash Chain
          </button>

          <button type="button" onClick={() => scrollToSection("merkle-tree")}>
            <GitBranch size={18} />
            Merkle Tree
          </button>

          <button type="button" onClick={() => scrollToSection("key-section")}>
            <KeyRound size={18} />
            Forward Key
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
            <span className="label">FINAL YEAR PROJECT</span>

            <h1>Secure Log Management System</h1>

            <p>
              Tamper-evident log storage using SHA-256, Hash Chaining, Merkle
              Tree verification, and Forward-Secure Key Evolution.
            </p>
          </div>

          <button className="refreshBtn" onClick={() => refreshData(true)}>
            <RefreshCw size={16} />
            Refresh
          </button>
        </header>

        <section className="stats">
          <div
            className="statCard clickableCard"
            onClick={() => scrollToSection("logs")}
          >
            <div>
              <p>Total Logs</p>
              <h2>{stats?.total_logs ?? 0}</h2>
            </div>
            <Database size={28} />
          </div>

          <div
            className="statCard clickableCard"
            onClick={() => scrollToSection("merkle-tree")}
          >
            <div>
              <p>Merkle Roots</p>
              <h2>{stats?.total_merkle_roots ?? 0}</h2>
            </div>
            <GitBranch size={28} />
          </div>

          <div
            className="statCard clickableCard"
            onClick={() => scrollToSection("hash-chain")}
          >
            <div>
              <p>Integrity Status</p>
              <h2 className={isValid ? "greenText" : "redText"}>
                {stats?.integrity_status || "No Logs"}
              </h2>
            </div>
            {isValid ? <CheckCircle size={28} /> : <AlertTriangle size={28} />}
          </div>

          <div
            className="statCard clickableCard"
            onClick={() => scrollToSection("key-section")}
          >
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
              <span>Hash will be generated automatically</span>
            </div>

            <form className="logForm" onSubmit={addLog}>
              <div className="field">
                <label>Source</label>
                <input
                  value={form.source}
                  onChange={(e) =>
                    setForm({ ...form, source: e.target.value })
                  }
                />
              </div>

              <div className="field">
                <label>Event Type</label>
                <input
                  value={form.event_type}
                  onChange={(e) =>
                    setForm({ ...form, event_type: e.target.value })
                  }
                />
              </div>

              <div className="field">
                <label>Username</label>
                <input
                  value={form.username}
                  onChange={(e) =>
                    setForm({ ...form, username: e.target.value })
                  }
                />
              </div>

              <div className="field">
                <label>IP Address</label>
                <input
                  value={form.ip_address}
                  onChange={(e) =>
                    setForm({ ...form, ip_address: e.target.value })
                  }
                />
              </div>

              <div className="field full">
                <label>Message</label>
                <input
                  value={form.message}
                  onChange={(e) =>
                    setForm({ ...form, message: e.target.value })
                  }
                />
              </div>

              <button className="primaryBtn" type="submit">
                <Plus size={16} />
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
              <button onClick={verifyHashChain}>
                <Link2 size={16} />
                Verify Hash Chain
              </button>

              <button onClick={generateMerkleRoot}>
                <GitBranch size={16} />
                Generate Merkle Root
              </button>

              <button onClick={verifyMerkleRoot}>
                <ShieldCheck size={16} />
                Verify Merkle Root
              </button>

              <button onClick={evolveKey}>
                <KeyRound size={16} />
                Evolve Forward Key
              </button>

              <button className="danger" onClick={simulateTampering}>
                <AlertTriangle size={16} />
                Simulate Tampering
              </button>
            </div>
          </div>
        </section>

        <section className="gridTwo">
          <div className="panel">
            <div className="panelHeader">
              <h3>Latest API Result</h3>
              <span>System response</span>
            </div>

            <pre>
              {result ? JSON.stringify(result, null, 2) : "No action yet"}
            </pre>
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

        <section className="gridTwo" id="key-section">
          <div className="panel keyPanel">
            <div className="panelHeader">
              <h3>Forward-Secure Key State</h3>
              <span>One-way key evolution</span>
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
                <p>Current / Batch Key Hash</p>
                <strong>{shortenHash(latestKeyHash, 18, 12)}</strong>
              </div>

              <button
                type="button"
                onClick={() => copyToClipboard(latestKeyHash, "key")}
              >
                <Copy size={15} />
                {copied === "key" ? "Copied" : "Copy"}
              </button>
            </div>

            <p className="keyNote">
              Each evolved key is generated using a one-way SHA-256 function, so
              older keys cannot be reconstructed from the current key hash.
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
              <div>SHA-256 Hash</div>
              <span>→</span>
              <div>Hash Chain</div>
              <span>→</span>
              <div>Merkle Root</div>
              <span>→</span>
              <div>Forward Key</div>
            </div>
          </div>
        </section>

        <section className="panel" id="logs">
          <div className="panelHeader">
            <h3>Recent Security Logs</h3>
            <span>{logs.length} records</span>
          </div>

          <div className="tableWrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
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
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td>{log.id}</td>

                    <td>
                      <span className="source sourcePill" title={log.source}>
                        <Server size={14} />
                        {cleanSourceName(log.source)}
                      </span>
                    </td>

                    <td>
                      <span className="eventPill">{log.event_type}</span>
                    </td>

                    <td>{log.username || "-"}</td>
                    <td>{log.ip_address || "-"}</td>

                    <td className="messageCell" title={log.message}>
                      {log.message}
                    </td>

                    <td className="hash hashCell" title={log.previous_hash}>
                      <span>{shortenHash(log.previous_hash)}</span>
                      <button
                        type="button"
                        onClick={() =>
                          copyToClipboard(log.previous_hash, `prev-${log.id}`)
                        }
                      >
                        <Copy size={13} />
                      </button>
                    </td>

                    <td className="hash hashCell" title={log.current_hash}>
                      <span>{shortenHash(log.current_hash)}</span>
                      <button
                        type="button"
                        onClick={() =>
                          copyToClipboard(log.current_hash, `curr-${log.id}`)
                        }
                      >
                        <Copy size={13} />
                      </button>
                    </td>

                    <td>
                      <span className="batchPill">{log.batch_id}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {copied && copied !== "key" && (
            <div className="copyToast">Hash copied to clipboard</div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;