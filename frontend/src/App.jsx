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
} from "lucide-react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);

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

  const refreshData = async (showMessage = true) => {
    try {
      const statsRes = await axios.get(`${API_URL}/dashboard/stats`);
      const logsRes = await axios.get(`${API_URL}/logs/`);

      setStats(statsRes.data);
      setLogs(logsRes.data);

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
              Tamper-evident log storage using SHA-256, Hash Chaining, and
              Merkle Tree verification.
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
            onClick={() => scrollToSection("logs")}
          >
            <div>
              <p>Latest Log ID</p>
              <h2>{stats?.latest_log_id ?? "-"}</h2>
            </div>
            <Fingerprint size={28} />
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
                      <span className="source">
                        <Server size={14} />
                        {log.source}
                      </span>
                    </td>

                    <td>{log.event_type}</td>
                    <td>{log.username}</td>
                    <td>{log.ip_address}</td>
                    <td>{log.message}</td>

                    <td className="hash">
                      {log.previous_hash?.slice(0, 14)}...
                    </td>

                    <td className="hash">
                      {log.current_hash?.slice(0, 14)}...
                    </td>

                    <td>{log.batch_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;