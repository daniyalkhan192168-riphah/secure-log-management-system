import { useState } from "react";
import { ShieldCheck, Loader2, LogIn } from "lucide-react";
import { api, setToken, errorMessage } from "./api";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await api.post("/auth/login", { username, password });
      setToken(res.data.access_token);
      onLogin(res.data.user);
    } catch (err) {
      setError(errorMessage(err, "Login failed."));
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="app loginPage">
      <form className="loginCard" onSubmit={submit}>
        <div className="loginBrand">
          <ShieldCheck size={34} />
          <div>
            <h2>SecureLog</h2>
            <p>Cyber Integrity Console</p>
          </div>
        </div>

        <label>
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>

        {error && <div className="loginError">{error}</div>}

        <button type="submit" disabled={busy}>
          {busy ? <Loader2 size={16} className="spin" /> : <LogIn size={16} />}
          Sign in
        </button>
        <p className="loginNote">
          Every login attempt is recorded in the tamper-evident log.
        </p>
      </form>
    </div>
  );
}