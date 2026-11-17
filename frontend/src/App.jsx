import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, errorMessage } from "./api";
import {
  ShieldCheck, LayoutDashboard, Bell, Search, Server, Link2, GitBranch,
  Copy, Loader2, LogOut, UserCircle, RefreshCw, AlertTriangle, CheckCircle, Activity,
  Database, Crosshair, Plus, ChevronDown, ChevronRight, Gauge, Terminal, Target, Users, Zap, Layers, Clock,
} from "lucide-react";
import "./App.css";

// ------------------------------------------------------------------ constants
const POLL_MS = 5000;
const TIMELINE_MS = 30000;
const LEVELS = ["critical", "high", "medium", "low"];
const LEVEL_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const LEVEL_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#64748b" };

// Detection rules -> MITRE ATT&CK technique (shown like a SIEM rule table).
const RULES = {
  BRUTE_FORCE_DETECTED: { mitre: "T1110", tactic: "Credential Access", name: "SSH brute force" },
  BRUTE_FORCE_SUCCESS: { mitre: "T1078", tactic: "Initial Access", name: "Login after brute force" },
  SUDO_PASSWORD_GUESSING: { mitre: "T1548.003", tactic: "Privilege Escalation", name: "Sudo password guessing" },
  ADMIN_RIGHTS_GRANTED: { mitre: "T1098", tactic: "Persistence", name: "User added to admin group" },
  LOG_WIPING_DETECTED: { mitre: "T1070.002", tactic: "Defense Evasion", name: "Log wiping" },
  PORT_SCAN_DETECTED: { mitre: "T1046", tactic: "Discovery", name: "Port scan" },
  INTEGRITY_ALERT: { mitre: "T1565.001", tactic: "Impact", name: "Stored log tampering" },
  ROLLBACK_DETECTED: { mitre: "T1565.001", tactic: "Impact", name: "Database rollback" },
  SEAL_MISMATCH: { mitre: "T1565.001", tactic: "Impact", name: "Seal mismatch" },
  AGENT_SILENT: { mitre: "T1562.001", tactic: "Defense Evasion", name: "Agent silent" },
  AGENT_STOPPED: { mitre: "T1562.001", tactic: "Defense Evasion", name: "Agent stopped" },
  AGENT_ONLINE: { mitre: "-", tactic: "-", name: "Agent back online" },
};
const ruleInfo = (type) => RULES[type] || { mitre: "-", tactic: "-", name: type };

const NAV = [
  { section: "Monitoring" },
  { id: "overview", label: "Security Overview", icon: LayoutDashboard },
  { id: "alerts", label: "Security Alerts", icon: Bell },
  { id: "events", label: "Threat Hunting", icon: Crosshair },
  { section: "Log Integrity" },
  { id: "integrity", label: "Integrity & Ledger", icon: ShieldCheck },
  { section: "Endpoints" },
  { id: "agents", label: "Agents", icon: Server },
];

// ------------------------------------------------------------------ helpers
const toDate = (iso) => (iso ? new Date(/([zZ]|[+-]\d\d:\d\d)$/.test(iso) ? iso : `${iso}Z`) : null);
const fmtTime = (iso) => (iso ? toDate(iso).toLocaleString() : "-");
const fmtClock = (iso) => (iso ? toDate(iso).toLocaleTimeString() : "-");
const timeAgo = (iso) => {
  const d = toDate(iso);
  if (!d) return "never";
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};
const short = (h, a = 10, b = 6) => (!h ? "-" : h.length <= a + b ? h : `${h.slice(0, a)}…${h.slice(-b)}`);
const num = (n) => (n ?? 0).toLocaleString();

// ------------------------------------------------------------------ small UI pieces
function SevBadge({ level }) {
  return <span className={`sev sev-${level || "info"}`}>{LEVEL_LABEL[level] || level}</span>;
}

function Panel({ title, sub, right, children, className = "", icon: Icon }) {
  return (
    <section className={`panel ${className}`}>
      <header className="panelHead">
        <div>
          <h3>{Icon && <Icon size={14} className="phIcon" />}{title}</h3>
          {sub && <span>{sub}</span>}
        </div>
        {right}
      </header>
      <div className="panelBody">{children}</div>
    </section>
  );
}

function Kpi({ label, value, unit, hint, tone = "", icon: Icon, onClick, spark, color }) {
  return (
    <button type="button" className={`kpi ${tone}`} onClick={onClick}>
      <div className="kpiTop">
        <span>{label}</span>
        {Icon && <i className="kpiIcon"><Icon size={15} /></i>}
      </div>
      <strong>{value}{unit && <em>{unit}</em>}</strong>
      {hint && <small>{hint}</small>}
      {spark && <Sparkline values={spark} color={color} />}
    </button>
  );
}

function Donut({ counts }) {
  const total = LEVELS.reduce((s, l) => s + (counts[l] || 0), 0);
  const r = 54;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="donutWrap">
      <svg viewBox="0 0 140 140" className="donut" role="img" aria-label="Events by severity">
        <circle cx="70" cy="70" r={r} fill="none" stroke="#1c2740" strokeWidth="18" />
        {total > 0 &&
          LEVELS.map((l) => {
            const len = ((counts[l] || 0) / total) * c;
            const seg = (
              <circle key={l} cx="70" cy="70" r={r} fill="none" stroke={LEVEL_COLOR[l]} strokeWidth="18"
                strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-offset}
                transform="rotate(-90 70 70)" />
            );
            offset += len;
            return seg;
          })}
        <text x="70" y="66" textAnchor="middle" className="donutNum">{num(total)}</text>
        <text x="70" y="84" textAnchor="middle" className="donutLbl">events</text>
      </svg>
      <ul className="legend">
        {LEVELS.map((l) => (
          <li key={l}>
            <i style={{ background: LEVEL_COLOR[l] }} />
            <span>{LEVEL_LABEL[l]}</span>
            <strong>{num(counts[l])}</strong>
            <em>{total ? `${((100 * (counts[l] || 0)) / total).toFixed(1)}%` : "0%"}</em>
          </li>
        ))}
      </ul>
    </div>
  );
}

// Stacked bars of the latest events, grouped into equal time buckets.
function Timeline({ logs }) {
  const data = useMemo(() => {
    const pts = logs
      .map((l) => ({ t: toDate(l.event_time || l.timestamp)?.getTime(), s: l.severity }))
      .filter((p) => p.t);
    if (!pts.length) return null;
    const max = Math.max(Date.now(), ...pts.map((p) => p.t));
    const n = 24;
    const step = Math.max(60000, (max - Math.min(...pts.map((p) => p.t)) + 1) / n);
    const min = max - n * step;
    const buckets = Array.from({ length: n }, (_, i) => ({ start: min + i * step, critical: 0, high: 0, medium: 0, low: 0 }));
    pts.forEach((p) => {
      const i = Math.max(0, Math.min(n - 1, Math.floor((p.t - min) / step)));
      buckets[i][p.s] = (buckets[i][p.s] || 0) + 1;
    });
    const top = Math.max(1, ...buckets.map((b) => LEVELS.reduce((s, l) => s + b[l], 0)));
    return { buckets, top, step };
  }, [logs]);

  if (!data) return <p className="empty">No events yet.</p>;
  const W = 640, H = 190, padL = 34, padB = 22, padT = 10, bw = (W - padL) / data.buckets.length;
  const plotH = H - padB - padT;
  // square-root scale: one big burst no longer flattens every other bar
  const y = (v) => (plotH * Math.sqrt(v)) / Math.sqrt(data.top);
  const label = (t) => {
    const d = new Date(t);
    return data.step >= 86400000 ? d.toLocaleDateString() : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="timeline" role="img" aria-label="Event timeline">
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={padL} x2={W} y1={H - padB - plotH * f} y2={H - padB - plotH * f} className="gridLine" />
          <text x={padL - 6} y={H - padB - plotH * f + 4} textAnchor="end" className="axis">
            {Math.round(data.top * f * f)}
          </text>
        </g>
      ))}
      {data.buckets.map((b, i) => {
        let acc = 0;
        const total = LEVELS.reduce((s, l) => s + b[l], 0);
        return (
          <g key={i}>
            <title>{`${label(b.start)}: ${total} events (C ${b.critical}, H ${b.high}, M ${b.medium}, L ${b.low})`}</title>
            {["low", "medium", "high", "critical"].map((l) => {
              const h = total ? (y(total) * b[l]) / total : 0;
              const rect = h > 0 && (
                <rect key={l} x={padL + i * bw + 2} y={H - padB - acc - h} width={Math.max(1, bw - 4)} height={h}
                  fill={LEVEL_COLOR[l]} rx="1.5" />
              );
              acc += h;
              return rect;
            })}
            {i % 4 === 0 && (
              <text x={padL + i * bw + bw / 2} y={H - 6} textAnchor="middle" className="axis">{label(b.start)}</text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

function BarList({ rows, onPick, mono }) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  if (!rows.length) return <p className="empty">No data yet.</p>;
  return (
    <ul className="barList">
      {rows.map((r) => (
        <li key={r.key} onClick={() => onPick?.(r.key)} className={onPick ? "click" : ""}>
          <span className={mono ? "mono" : ""}>{r.key}</span>
          <div className="barTrack"><div style={{ width: `${(100 * r.count) / max}%` }} /></div>
          <strong>{num(r.count)}</strong>
        </li>
      ))}
    </ul>
  );
}


function Sparkline({ values, color = "#38bdf8" }) {
  if (!values || values.length < 2) return <div className="spark" />;
  const W = 120, H = 30, max = Math.max(1, ...values);
  const pts = values.map((v, i) => [(i * W) / (values.length - 1), H - 2 - ((H - 4) * v) / max]);
  const line = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="spark" preserveAspectRatio="none">
      <path d={`${line} L${W},${H} L0,${H} Z`} fill={color} opacity="0.14" />
      <path d={line} fill="none" stroke={color} strokeWidth="1.6" />
    </svg>
  );
}

function PostureGauge({ score, label, reasons }) {
  const r = 70, c = Math.PI * r, val = Math.max(0, Math.min(100, score));
  const color = val >= 80 ? "#22c55e" : val >= 50 ? "#f59e0b" : "#ef4444";
  return (
    <div className="gauge">
      <svg viewBox="0 0 180 104">
        <path d="M20 94 A70 70 0 0 1 160 94" fill="none" stroke="#1b2640" strokeWidth="14" strokeLinecap="round" />
        <path d="M20 94 A70 70 0 0 1 160 94" fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${(c * val) / 100} ${c}`} />
        <text x="90" y="80" textAnchor="middle" className="gaugeNum">{val}</text>
        <text x="90" y="98" textAnchor="middle" className="gaugeLbl">/ 100</text>
      </svg>
      <strong style={{ color }}>{label}</strong>
      <ul>{reasons.map((r) => <li key={r}>{r}</li>)}</ul>
    </div>
  );
}

const TACTICS = ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Impact"];

// ------------------------------------------------------------------ main app
export default function App({ user, onLogout }) {
  const [view, setView] = useState("overview");
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [logsTotal, setLogsTotal] = useState(0);
  const [timelineLogs, setTimelineLogs] = useState([]);
  const [stream, setStream] = useState([]);
  const [online, setOnline] = useState(false);
  const [updated, setUpdated] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState("");
  const [copied, setCopied] = useState("");

  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [limit, setLimit] = useState(100);
  const [openRow, setOpenRow] = useState(null);
  const [alertSev, setAlertSev] = useState("");

  const [proofId, setProofId] = useState("");
  const [proof, setProof] = useState(null);
  const [tamperId, setTamperId] = useState("");
  const [form, setForm] = useState({
    source: "SOC-Analyst", event_type: "ANALYST_NOTE", username: user?.username || "admin",
    ip_address: "127.0.0.1", message: "Manual note added from the console",
  });

  const inFlight = useRef(false);

  // ---------------------------------------------------------------- data
  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const p = new URLSearchParams({ limit: String(limit) });
      if (search) p.set("q", search);
      if (sevFilter) p.set("severity", sevFilter);
      const [s, a, l, st] = await Promise.all([
        api.get("/dashboard/stats"),
        api.get("/dashboard/alerts?limit=100"),
        api.get(`/logs/?${p.toString()}`),
        api.get("/logs/?limit=18"),
      ]);
      setStream(st.data.items);
      setStats(s.data);
      setAlerts(a.data);
      setLogs(l.data.items);
      setLogsTotal(l.data.total);
      setOnline(true);
      setUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      if (err?.response?.status === 401) return;
      setOnline(Boolean(err?.response));
    } finally {
      inFlight.current = false;
    }
  }, [limit, search, sevFilter]);

  const refreshTimeline = useCallback(async () => {
    try {
      const r = await api.get("/logs/?limit=1000");
      setTimelineLogs(r.data.items);
    } catch {
      /* the main poll reports connection problems */
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(() => !document.hidden && refresh(), POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    refreshTimeline();
    const t = setInterval(() => !document.hidden && refreshTimeline(), TIMELINE_MS);
    return () => clearInterval(t);
  }, [refreshTimeline]);

  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput.trim()), 400);
    return () => clearTimeout(t);
  }, [searchInput]);

  const run = async (name, req, fallback) => {
    setBusy(name);
    try {
      const r = await req();
      setResult(r.data);
      await refresh();
      return r.data;
    } catch (err) {
      setResult({ status: "Error", message: errorMessage(err, fallback) });
      return null;
    } finally {
      setBusy("");
    }
  };

  const verifyChain = () => run("verify", () => api.get("/verify/hash-chain"), "Verification failed.");
  const sealNow = () => run("seal", () => api.post("/merkle/seal"), "Could not seal the open batch.");
  const verifyBatch = (id) =>
    id ? run(`batch-${id}`, () => api.get(`/merkle/verify/${id}`), "Batch verification failed.")
      : setResult({ status: "Nothing to verify", message: "No batch has been sealed yet." });
  const getProof = async () => {
    if (!proofId) return setResult({ status: "Error", message: "Enter a log ID." });
    setProof(await run("proof", () => api.get(`/merkle/proof/${proofId}`), "Could not build the proof."));
  };
  const simulate = (kind) =>
    tamperId ? run(kind, () => api.put(`/verify/simulate-${kind}/${tamperId}`), `Simulation failed.`)
      : setResult({ status: "Error", message: "Enter a log ID first." });
  const addLog = (e) => {
    e.preventDefault();
    run("add", () => api.post("/logs/manual", form), "Could not add the log.");
  };
  const copy = async (v, k) => {
    try {
      await navigator.clipboard.writeText(v);
      setCopied(k);
      setTimeout(() => setCopied(""), 1300);
    } catch { /* clipboard blocked */ }
  };
  const hunt = (q, sev = "") => {
    setSearchInput(q);
    setSevFilter(sev);
    setView("events");
  };

  // ---------------------------------------------------------------- derived
  const counts = stats?.severity_counts || { critical: 0, high: 0, medium: 0, low: 0 };
  const integrity = stats?.integrity;
  const valid = stats?.integrity_status === "Valid";
  const agents = stats?.agents || [];
  const agentsOnline = agents.filter((a) => a.status === "online").length;

  const agentResolved = (a) =>
    (a.alert_type === "AGENT_STOPPED" || a.alert_type === "AGENT_SILENT") &&
    agents.some((g) => g.status === "online" && (a.description || "").includes(`'${g.agent_id}'`));
  const banner = alerts.find(
    (a) => (a.severity === "critical" || a.severity === "high") && !agentResolved(a) &&
      Date.now() - (toDate(a.created_at)?.getTime() ?? 0) < 3600000
  );

  const ruleRows = useMemo(() => {
    const m = {};
    alerts.filter((a) => a.severity !== "info" && a.alert_type !== "AGENT_ONLINE").forEach((a) => {
      const r = (m[a.alert_type] ||= { type: a.alert_type, severity: a.severity, count: 0, last: a.created_at });
      r.count += 1;
      if (toDate(a.created_at) > toDate(r.last)) r.last = a.created_at;
    });
    return Object.values(m).sort((x, y) => y.count - x.count);
  }, [alerts]);

  const alerts24h = alerts.filter((a) => Date.now() - (toDate(a.created_at)?.getTime() ?? 0) < 86400000).length;
  const shownAlerts = alertSev ? alerts.filter((a) => a.severity === alertSev) : alerts;
  const openPct = stats ? Math.min(100, Math.round((100 * stats.open_batch_logs) / stats.batch_size)) : 0;
  const spin = (n, Icon) => (busy === n ? <Loader2 size={15} className="spin" /> : <Icon size={15} />);

  const analytics = useMemo(() => {
    const pts = timelineLogs.map((l) => ({ t: toDate(l.event_time || l.timestamp)?.getTime(), s: l.severity, u: l.username, e: l.event_type })).filter((p) => p.t);
    const out = { all: [], threat: [], perMin: 0, users: [], types: [] };
    if (!pts.length) return out;
    const min = Math.min(...pts.map((p) => p.t)), max = Math.max(...pts.map((p) => p.t));
    const n = 20, step = Math.max(1, (max - min + 1) / n);
    out.all = Array(n).fill(0); out.threat = Array(n).fill(0);
    const users = {}, types = {};
    pts.forEach((p) => {
      const i = Math.min(n - 1, Math.floor((p.t - min) / step));
      out.all[i] += 1;
      if (p.s === "critical" || p.s === "high") out.threat[i] += 1;
      if (p.u && p.u !== "-") users[p.u] = (users[p.u] || 0) + 1;
      types[p.e] = (types[p.e] || 0) + 1;
    });
    out.perMin = Math.round(pts.filter((p) => p.t > Date.now() - 300000).length / 5);
    const top = (o, k) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, k).map(([key, count]) => ({ key, count }));
    out.users = top(users, 6); out.types = top(types, 6);
    return out;
  }, [timelineLogs]);

  const tactics = useMemo(() => {
    const m = Object.fromEntries(TACTICS.map((t) => [t, 0]));
    alerts.forEach((a) => { const t = ruleInfo(a.alert_type).tactic; if (t in m) m[t] += 1; });
    return m;
  }, [alerts]);

  const crit24 = alerts.filter((a) => a.severity === "critical" && Date.now() - (toDate(a.created_at)?.getTime() ?? 0) < 86400000).length;
  const high24 = alerts.filter((a) => a.severity === "high" && Date.now() - (toDate(a.created_at)?.getTime() ?? 0) < 86400000).length;
  const offline = agents.length - agentsOnline;
  const posture = (() => {
    let sc = 100; const why = [];
    if (stats && !valid) { sc -= 40; why.push("Log integrity check failed"); }
    if (crit24) { sc -= Math.min(32, crit24 * 8); why.push(`${crit24} critical alert(s) in 24 h`); }
    if (high24) { sc -= Math.min(18, high24 * 3); why.push(`${high24} high alert(s) in 24 h`); }
    if (offline > 0) { sc -= offline * 15; why.push(`${offline} agent(s) offline`); }
    if (!why.length) why.push("No open findings");
    sc = Math.max(0, sc);
    return { sc, label: sc >= 80 ? "Healthy" : sc >= 50 ? "Elevated risk" : "High risk", why };
  })();
  const title = NAV.find((n) => n.id === view)?.label;

  // ---------------------------------------------------------------- views
  const overview = (
    <>
      <div className="topRow">
        <Panel title="Security posture" sub="Heuristic risk score" className="posture">
          <PostureGauge score={posture.sc} label={posture.label} reasons={posture.why} />
        </Panel>
        <div className="kpis">
          <Kpi label="Events ingested" value={num(stats?.total_logs)} hint={`${num(stats?.total_merkle_roots)} sealed batches`}
            icon={Database} onClick={() => hunt("")} spark={analytics.all} color="#38bdf8" />
          <Kpi label="Threat events" value={num((counts.critical || 0) + (counts.high || 0))} hint={`${num(counts.critical)} critical · ${num(counts.high)} high`}
            icon={Target} tone="high" onClick={() => hunt("", "high")} spark={analytics.threat} color="#f97316" />
          <Kpi label="Open alerts (24 h)" value={num(alerts24h)} hint={`${num(stats?.total_alerts)} alerts in total`}
            icon={Bell} tone={crit24 ? "crit" : alerts24h ? "high" : "ok"} onClick={() => setView("alerts")} />
          <Kpi label="Ingest rate" value={`${num(analytics.perMin)}`} unit="events/min" hint="Average over last 5 minutes"
            icon={Zap} onClick={() => hunt("")} spark={analytics.all.slice(-8)} color="#a78bfa" />
          <Kpi label="Agents online" value={`${agentsOnline}/${agents.length}`} hint={offline ? `${offline} not reporting` : "All endpoints reporting"}
            tone={offline ? "crit" : "ok"} icon={Server} onClick={() => setView("agents")} />
          <Kpi label="Log integrity" value={stats?.integrity_status || "…"}
            hint={integrity ? `${num(integrity.total_logs_verified)} logs verified ${timeAgo(integrity.checked_at)}` : "Checking"}
            tone={valid ? "ok" : "crit"} icon={valid ? ShieldCheck : AlertTriangle} onClick={() => setView("integrity")} />
        </div>
      </div>

      <div className="grid g-act">
        <Panel title="Event activity" sub={`Latest ${num(timelineLogs.length)} events, stacked by severity`} icon={Activity}>
          <Timeline logs={timelineLogs} />
          <div className="miniStats four">
            <div><span>Critical</span><strong className="c-crit">{num(counts.critical)}</strong></div>
            <div><span>High</span><strong className="c-high">{num(counts.high)}</strong></div>
            <div><span>Medium</span><strong className="c-med">{num(counts.medium)}</strong></div>
            <div><span>Low</span><strong className="c-low">{num(counts.low)}</strong></div>
          </div>
        </Panel>
        <Panel title="Severity distribution" sub="All stored events" icon={Layers}>
          <Donut counts={counts} />
        </Panel>
      </div>

      <div className="grid g-1-1-1">
        <Panel title="MITRE ATT&CK tactics" sub="Detections mapped to tactics (latest 100 alerts)" icon={Target}>
          <div className="tactics">
            {TACTICS.map((t) => (
              <div key={t} className={`tactic ${tactics[t] ? "hit" : ""}`} style={{ "--heat": Math.min(1, tactics[t] / 4) }}>
                <span>{t}</span><strong>{tactics[t]}</strong>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Detection rules" sub="Rules fired · latest 100 alerts" icon={Crosshair}
          right={<button className="link" onClick={() => setView("alerts")}>All alerts</button>}>
          {ruleRows.length === 0 ? <p className="empty">No rule has fired.</p> : (
            <table className="tbl compact">
              <thead><tr><th>Rule</th><th>Technique</th><th className="r">Hits</th><th className="r">Last</th></tr></thead>
              <tbody>
                {ruleRows.slice(0, 7).map((r) => (
                  <tr key={r.type} className="click" onClick={() => setView("alerts")}>
                    <td><i className="dot" style={{ background: LEVEL_COLOR[r.severity] || LEVEL_COLOR.info }} />{ruleInfo(r.type).name}</td>
                    <td className="mono muted">{ruleInfo(r.type).mitre}</td>
                    <td className="r"><b>{r.count}</b></td>
                    <td className="r muted nowrap">{timeAgo(r.last)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <Panel title="Top source IPs" sub="Most active addresses · click to hunt" icon={Target}>
          <BarList mono rows={(stats?.top_ips || []).map((r) => ({ key: r.ip, count: r.count }))} onPick={(ip) => hunt(ip)} />
        </Panel>
      </div>

      <div className="grid g-1-1">
        <Panel title="Live event stream" sub="Newest events as they arrive · refreshes every 5 s" icon={Terminal}
          right={<span className="liveTag"><i />LIVE</span>}>
          <div className="stream">
            {stream.length === 0 && <p className="empty">Waiting for events…</p>}
            {stream.map((l) => (
              <div key={l.id} className={`streamRow s-${l.severity}`} onClick={() => hunt(String(l.id))}>
                <span className="t">{fmtClock(l.event_time || l.timestamp)}</span>
                <span className="lv">{{ critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW" }[l.severity] || "INFO"}</span>
                <span className="ag">{l.agent_id}</span>
                <span className="et">{l.event_type}</span>
                <span className="mg" title={l.message}>{l.username && l.username !== "-" ? `user=${l.username} ` : ""}{l.ip_address && l.ip_address !== "-" ? `src=${l.ip_address} ` : ""}{l.message}</span>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Latest security alerts" sub="Detection rules and integrity monitor" icon={Bell}
          right={<button className="link" onClick={() => setView("alerts")}>View all</button>}>
          {renderAlertFeed(alerts.slice(0, 5))}
        </Panel>
      </div>

      <div className="grid g-1-1-1">
        <Panel title="Top users" sub={`Latest ${num(timelineLogs.length)} events`} icon={Users}>
          <BarList rows={analytics.users} onPick={(u) => hunt(u)} />
        </Panel>
        <Panel title="Top event types" sub={`Latest ${num(timelineLogs.length)} events`} icon={Layers}>
          <BarList rows={analytics.types} onPick={(t) => hunt(t)} />
        </Panel>
        <Panel title="Endpoints" sub="Heartbeat every 60 s · silent after 180 s" icon={Server}>
          {agents.length === 0 ? <p className="empty">No agent registered.</p> : (
            <ul className="agentMini">
              {agents.map((a) => (
                <li key={a.agent_id}>
                  <i className={`pulse ${a.status === "online" ? "on" : "off"}`} />
                  <div><strong>{a.agent_id}</strong><span>{a.hostname || "-"} · v{a.version || "-"} · queue {a.spool_size ?? 0}</span></div>
                  <em>{a.status === "online" ? timeAgo(a.last_seen) : a.status}</em>
                </li>
              ))}
            </ul>
          )}
          <div className="miniStats">
            <div><span>Open batch</span><strong>#{stats?.open_batch_id ?? "-"}</strong></div>
            <div><span>Key version</span><strong>{stats?.key_version ?? "-"}</strong></div>
            <div><span>Last seal</span><strong>#{stats?.latest_batch_id ?? "-"}</strong></div>
          </div>
        </Panel>
      </div>
    </>
  );

  function renderAlertFeed(items) {
    if (!items.length) return <p className="empty">No alerts. The system has not detected anything.</p>;
    return (
      <ul className="feed">
        {items.map((a) => (
          <li key={a.id} className={a.log_id ? "click" : ""} onClick={() => a.log_id && hunt(String(a.log_id))}>
            <SevBadge level={a.severity} />
            <div>
              <strong>{a.alert_type} {ruleInfo(a.alert_type).mitre !== "-" && <small className="mono muted">{ruleInfo(a.alert_type).mitre}</small>}</strong>
              <span>{a.description}</span>
            </div>
            <em>{timeAgo(a.created_at)}</em>
          </li>
        ))}
      </ul>
    );
  }

  const alertsView = (
    <>
      <div className="chips">
        {["", "critical", "high", "medium", "low", "info"].map((s) => (
          <button key={s || "all"} className={`chip ${alertSev === s ? "on" : ""}`} onClick={() => setAlertSev(s)}>
            {s ? LEVEL_LABEL[s] : "All"} <b>{s ? alerts.filter((a) => a.severity === s).length : alerts.length}</b>
          </button>
        ))}
      </div>
      <Panel title="Security alerts" sub={`${shownAlerts.length} of the latest ${alerts.length} alerts`}>
        <div className="tblWrap">
          <table className="tbl">
            <thead>
              <tr><th>Time</th><th>Severity</th><th>Rule</th><th>MITRE ATT&amp;CK</th><th>Description</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {shownAlerts.length === 0 && <tr><td colSpan={6} className="empty">No alerts.</td></tr>}
              {shownAlerts.map((a) => (
                <tr key={a.id} className={`sevRow-${a.severity}`}>
                  <td className="nowrap muted">{a.created_at ? <>{toDate(a.created_at).toLocaleDateString()}<br />{toDate(a.created_at).toLocaleTimeString()}</> : "-"}</td>
                  <td><SevBadge level={a.severity} /></td>
                  <td className="nowrap"><strong>{a.alert_type}</strong></td>
                  <td className="nowrap">{ruleInfo(a.alert_type).mitre !== "-" && <><span className="mono">{ruleInfo(a.alert_type).mitre}</span><br /><small className="muted">{ruleInfo(a.alert_type).tactic}</small></>}</td>
                  <td className="wrap">{a.description}</td>
                  <td className="nowrap">{a.log_id ? <button className="link" onClick={() => hunt(String(a.log_id))}>Log #{a.log_id}</button> : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </>
  );

  const eventsView = (
    <Panel title="Threat hunting" sub={`Showing ${num(logs.length)} of ${num(logsTotal)}${search || sevFilter ? " matching" : ""} events · newest first`}>
      <div className="filters">
        <div className="searchBox">
          <Search size={15} />
          <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search user, IP, event type, message, agent or log ID…" />
        </div>
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
          <option value="">All severities</option>
          {LEVELS.map((l) => <option key={l} value={l}>{LEVEL_LABEL[l]}</option>)}
        </select>
        <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
          {[50, 100, 250, 500].map((n) => <option key={n} value={n}>Last {n}</option>)}
        </select>
        {(searchInput || sevFilter) && <button className="btn ghost" onClick={() => { setSearchInput(""); setSevFilter(""); }}>Clear</button>}
      </div>
      <div className="tblWrap tall">
        <table className="tbl events">
          <thead>
            <tr><th /><th>ID</th><th>Time</th><th>Agent</th><th>Event type</th><th>Severity</th><th>User</th><th>Source IP</th><th>Message</th><th>Batch</th></tr>
          </thead>
          <tbody>
            {logs.length === 0 && <tr><td colSpan={10} className="empty">No events found.</td></tr>}
            {logs.map((l) => (
              renderEventRow(l, openRow === l.id, () => setOpenRow(openRow === l.id ? null : l.id))
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );

  function renderEventRow(l, open, toggle) {
    return (
      <Fragment key={l.id}>
        <tr className={`click sevRow-${l.severity}`} onClick={toggle}>
          <td>{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
          <td className="mono">{l.id}</td>
          <td className="nowrap muted">{fmtTime(l.event_time || l.timestamp)}</td>
          <td className="nowrap">{l.agent_id}</td>
          <td className="nowrap"><strong>{l.event_type}</strong></td>
          <td><SevBadge level={l.severity} /></td>
          <td>{l.username || "-"}</td>
          <td className="mono nowrap">{l.ip_address || "-"}</td>
          <td className="msg" title={l.message}>{l.message}</td>
          <td><span className="pill">{l.batch_id}</span></td>
        </tr>
        {open && (
          <tr className="detail">
            <td />
            <td colSpan={9}>
              <div className="detailGrid">
                <div><span>Source</span><b>{l.source}</b></div>
                <div><span>Event time</span><b>{fmtTime(l.event_time)}</b></div>
                <div><span>Received</span><b>{fmtTime(l.timestamp)}</b></div>
                <div><span>Batch</span><b>#{l.batch_id}</b></div>
                {[["Previous hash", l.previous_hash], ["Entry hash", l.current_hash], ["HMAC tag", l.mac]].map(([k, v]) => (
                  <div key={k} className="wide">
                    <span>{k}</span>
                    <b className="mono">{v || "-"}</b>
                    {v && <button className="icon" onClick={(e) => { e.stopPropagation(); copy(v, `${k}${l.id}`); }}>
                      <Copy size={13} /> {copied === `${k}${l.id}` ? "Copied" : ""}
                    </button>}
                  </div>
                ))}
                <div className="wide"><span>Message</span><b>{l.message}</b></div>
              </div>
            </td>
          </tr>
        )}
      </Fragment>
    );
  }

  const resultTone = !result ? "" : ["Valid", "Sealed", "Included"].includes(result.status) ? "ok"
    : ["Tampered", "Error", "Not Included"].includes(result.status) || /Simulated/.test(result.status || "") ? "crit" : "neutral";

  const integrityView = (
    <>
      <div className={`statusHero ${valid ? "ok" : "crit"}`}>
        {valid ? <CheckCircle size={30} /> : <AlertTriangle size={30} />}
        <div>
          <h2>Log integrity: {stats?.integrity_status || "Checking…"}</h2>
          <p>
            {integrity
              ? `${num(integrity.total_logs_verified)} logs and ${num(stats?.total_merkle_roots)} sealed batches checked in ${integrity.duration_ms} ms · last check ${fmtClock(integrity.checked_at)} · automatic every ${integrity.interval_seconds} s`
              : "Waiting for the first check"}
            {!valid && integrity?.problem_types?.length ? ` · problems: ${integrity.problem_types.join(", ")}` : ""}
          </p>
        </div>
        <div className="heroActions">
          <button className="btn primary" onClick={verifyChain} disabled={!!busy}>{spin("verify", Link2)} Verify hash chain</button>
          <button className="btn" onClick={sealNow} disabled={!!busy}>{spin("seal", GitBranch)} Seal open batch</button>
          <button className="btn" onClick={() => verifyBatch(stats?.latest_batch_id)} disabled={!!busy}>{spin(`batch-${stats?.latest_batch_id}`, ShieldCheck)} Verify latest batch</button>
        </div>
      </div>

      <div className="grid g-1-1">
        <Panel title="Verification result" sub="Response of the last action">
          {!result ? <p className="empty">Run an action above to see its result.</p> : (
            <>
              <div className={`resultTag ${resultTone}`}>{result.status || "Done"}</div>
              {(result.message || result.note) && <p className="resultMsg">{result.message || result.note}</p>}
              {Array.isArray(result.checks) && (
                <div className="checks">{result.checks.map((c) => <span key={c}><CheckCircle size={12} /> {c}</span>)}</div>
              )}
              {Array.isArray(result.problems) && result.problems.length > 0 && (
                <ul className="problems">
                  {result.problems.slice(0, 8).map((p, i) => (
                    <li key={i}>{typeof p === "string" ? p : <><b>{p.type}</b> {p.detail}{p.log_id !== undefined && ` (log ${p.log_id})`}{p.batch_id !== undefined && ` (batch ${p.batch_id})`}</>}</li>
                  ))}
                </ul>
              )}
              <details className="raw"><summary>Full response</summary><pre>{JSON.stringify(result, null, 2)}</pre></details>
            </>
          )}
        </Panel>

        <Panel title="Forward-secure key" sub="HMAC-SHA256 key evolution">
          <div className="keyRow">
            <div><span>Current key version</span><strong>{stats?.key_version ?? "-"}</strong></div>
            <div><span>Open batch</span><strong>#{stats?.open_batch_id ?? "-"}</strong></div>
            <div><span>Sealed batches</span><strong>{num(stats?.total_merkle_roots)}</strong></div>
          </div>
          <div className="fp">
            <span>K0 fingerprint (public commitment)</span>
            <code>{short(stats?.k0_fingerprint, 20, 14)}</code>
            <button className="icon" onClick={() => copy(stats?.k0_fingerprint, "k0")}><Copy size={13} /> {copied === "k0" ? "Copied" : ""}</button>
          </div>
          <p className="note">
            Every log is tagged with the key of its batch. After a batch is sealed the key evolves one-way,
            K(b+1) = SHA-256("SLv1-evolve" ‖ K(b)), and the old key is overwritten. The secret key never leaves the
            server; only the auditor holding K0 offline can re-check old seals.
          </p>
          <div className="flow">
            {["Ubuntu logs", "Hash chain", "HMAC (Kb)", "Merkle root", "Seal + evolve"].map((s, i) => (
              <span key={s}>{i > 0 && <i>→</i>}<b>{s}</b></span>
            ))}
          </div>
        </Panel>
      </div>

      <div className="grid g-2-1">
        <Panel title="Sealed Merkle batches" sub={`Open batch #${stats?.open_batch_id ?? "-"}: ${stats?.open_batch_logs ?? 0}/${stats?.batch_size ?? 100} logs · seals when full or after ${Math.round((stats?.seal_max_age_seconds ?? 600) / 60)} min`}>
          <div className="progress"><div style={{ width: `${openPct}%` }} /></div>
          <table className="tbl">
            <thead><tr><th>Batch</th><th>Logs</th><th>Merkle root</th><th>Seal</th><th>Sealed</th><th /></tr></thead>
            <tbody>
              {!stats?.recent_batches?.length && <tr><td colSpan={6} className="empty">No batch sealed yet.</td></tr>}
              {stats?.recent_batches?.map((b) => (
                <tr key={b.batch_id}>
                  <td><span className="pill">{b.batch_id}</span></td>
                  <td className="nowrap">{b.total_logs} <small className="muted">#{b.first_log_id}–{b.last_log_id}</small></td>
                  <td className="mono" title={b.root_hash}>{short(b.root_hash)}</td>
                  <td className="mono" title={b.seal}>{short(b.seal)}</td>
                  <td className="nowrap muted">{fmtTime(b.created_at)}</td>
                  <td><button className="btn small" onClick={() => verifyBatch(b.batch_id)} disabled={!!busy}>
                    {busy === `batch-${b.batch_id}` ? <Loader2 size={13} className="spin" /> : "Verify"}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel title="Merkle inclusion proof" sub="Prove one log belongs to its sealed batch">
          <div className="inline">
            <input type="number" placeholder="Log ID" value={proofId} onChange={(e) => setProofId(e.target.value)} />
            <button className="btn primary" onClick={getProof} disabled={!!busy}>{spin("proof", ShieldCheck)} Get proof</button>
          </div>
          {proof?.proof && (
            <>
              <div className={`resultTag ${proof.status === "Included" ? "ok" : "crit"}`}>{proof.status}</div>
              <p className="note">Log {proof.log_id} is leaf {proof.leaf_index} of batch {proof.batch_id}; {proof.proof_length} sibling hashes reach the root.</p>
              <ol className="proofPath mono">
                <li>leaf {short(proof.entry_hash)}</li>
                {proof.proof.map((s, i) => <li key={i}>+ {s.position} {short(s.sibling)}</li>)}
                <li>= root {short(proof.root_hash)}</li>
              </ol>
            </>
          )}
          {proof && !proof.proof && <p className="note">{proof.message}</p>}
        </Panel>
      </div>

      <Panel title="Lab tools" sub="Add an analyst note; demo attacks appear only when demo mode is on">
        <form className="labForm" onSubmit={addLog}>
          {[["source", "Source"], ["event_type", "Event type"], ["username", "User"], ["ip_address", "IP address"], ["message", "Message"]].map(([k, lbl]) => (
            <label key={k} className={k === "message" ? "wide" : ""}>{lbl}
              <input value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} />
            </label>
          ))}
          <button className="btn primary" type="submit" disabled={!!busy}>{spin("add", Plus)} Add log</button>
        </form>
        {user?.demo_mode && (
          <div className="inline demo">
            <span className="sev sev-critical">Demo mode</span>
            <input type="number" placeholder="Log ID to attack" value={tamperId} onChange={(e) => setTamperId(e.target.value)} />
            <button className="btn danger" onClick={() => simulate("tamper")} disabled={!!busy}>{spin("tamper", AlertTriangle)} Simulate tamper</button>
            <button className="btn danger" onClick={() => simulate("rewrite")} disabled={!!busy}>{spin("rewrite", AlertTriangle)} Simulate rewrite</button>
          </div>
        )}
      </Panel>
    </>
  );

  const agentsView = (
    <Panel title="Registered agents" sub="An agent is reported silent after 180 s without a heartbeat">
      <div className="tblWrap">
        <table className="tbl">
          <thead><tr><th>Status</th><th>Agent</th><th>Hostname</th><th>Last IP</th><th>Version</th><th>Last heartbeat</th><th className="r">Queued logs</th><th>Witness batch</th></tr></thead>
          <tbody>
            {agents.length === 0 && <tr><td colSpan={8} className="empty">No agent registered. Use manage.py add-agent.</td></tr>}
            {agents.map((a) => (
              <tr key={a.agent_id}>
                <td><span className={`status ${a.status === "online" ? "on" : "off"}`}><i className={`pulse ${a.status === "online" ? "on" : "off"}`} />{a.status}</span></td>
                <td><strong>{a.agent_id}</strong></td>
                <td>{a.hostname || "-"}</td>
                <td className="mono">{a.last_ip || "-"}</td>
                <td>{a.version || "-"}</td>
                <td className="nowrap">{a.last_seen ? `${fmtTime(a.last_seen)} (${timeAgo(a.last_seen)})` : "never"}</td>
                <td className="r">{num(a.spool_size)}</td>
                <td>{a.witness_batch ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );

  const views = { overview, alerts: alertsView, events: eventsView, integrity: integrityView, agents: agentsView };

  // ---------------------------------------------------------------- layout
  return (
    <div className="shell">
      <header className="topbar">
        <div className="logo"><span className="logoMark"><ShieldCheck size={18} /></span><b>SecureLog</b><span>SIEM</span></div>
        <div className="crumb"><span>SOC workspace</span><ChevronRight size={13} />{title}</div>
        <div className="topSearch">
          <Search size={15} />
          <input placeholder="Hunt: IP, user, event type, log ID…" value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)} onFocus={() => setView("events")} />
        </div>
        <div className={`live ${online ? "on" : "off"}`}><i />{online ? "Live" : "Disconnected"}<small>{updated && `updated ${updated}`}</small></div>
        <button className="iconBtn" title="Refresh now" onClick={() => { refresh(); refreshTimeline(); }}><RefreshCw size={16} /></button>
        <button className="iconBtn bell" title="Alerts in the last 24 h" onClick={() => setView("alerts")}><Bell size={16} />{alerts24h > 0 && <b>{alerts24h}</b>}</button>
        <div className="user"><UserCircle size={18} />{user?.username}</div>
        <button className="iconBtn" title="Log out" onClick={onLogout}><LogOut size={16} /></button>
      </header>

      <aside className="side">
        <nav>
          {NAV.map((n, i) => n.section ? <p key={i} className="navSec">{n.section}</p> : (
            <button key={n.id} className={view === n.id ? "on" : ""} onClick={() => setView(n.id)}>
              <n.icon size={17} /> {n.label}
              {n.id === "alerts" && alerts24h > 0 && <em className="count">{alerts24h}</em>}
              {n.id === "agents" && agents.length > 0 && agentsOnline < agents.length && <em className="count">!</em>}
            </button>
          ))}
        </nav>
        <div className={`sideStatus ${valid ? "ok" : "crit"}`}>
          <span>System integrity</span>
          <strong>{valid ? <CheckCircle size={16} /> : <AlertTriangle size={16} />} {stats?.integrity_status || "Checking…"}</strong>
          <small>{integrity ? `checked ${fmtClock(integrity.checked_at)} · every ${integrity.interval_seconds}s` : ""}</small>
        </div>
      </aside>

      <main className="content">
        {stats && !valid && (
          <div className="banner crit"><AlertTriangle size={18} />
            <b>INTEGRITY ALERT</b> {integrity?.problems_found} problem(s){integrity?.problem_types?.length ? ` (${integrity.problem_types.join(", ")})` : ""}.
            <button className="link" onClick={() => { setView("integrity"); verifyChain(); }}>Investigate</button>
          </div>
        )}
        {banner && valid && (
          <div className={`banner ${banner.severity === "critical" ? "crit" : "high"}`}><Bell size={18} />
            <b>{banner.alert_type}</b> <span className="bannerText">{banner.description}</span>
            <em>{timeAgo(banner.created_at)}</em>
            <button className="link" onClick={() => setView("alerts")}>View alerts</button>
          </div>
        )}
        {views[view]}
        <footer className="statusBar">
          <span><i className={`pulse ${online ? "on" : "off"}`} />Backend {online ? "connected (HTTPS)" : "disconnected"}</span>
          <span><Clock size={12} />Integrity monitor every {integrity?.interval_seconds ?? 30} s</span>
          <span><GitBranch size={12} />Last sealed batch #{stats?.latest_batch_id ?? "-"}</span>
          <span><Gauge size={12} />Key version {stats?.key_version ?? "-"}</span>
          <span><Zap size={12} />{num(analytics.perMin)} events/min</span>
          <span className="right">SecureLog SIEM · BS Cyber Security FYP · Riphah International University</span>
        </footer>
      </main>
    </div>
  );
}
