import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import App from "./App.jsx";
import Login from "./Login.jsx";
import { api, getToken, setToken } from "./api";

export default function AuthGate() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(Boolean(getToken()));

  // Restore an existing session (e.g. after a page refresh).
  useEffect(() => {
    if (!getToken()) return;
    api
      .get("/auth/me")
      .then((res) => setUser(res.data))
      .catch(() => setToken(null))
      .finally(() => setChecking(false));
  }, []);

  // The API client fires this when the server answers 401.
  useEffect(() => {
    const onLogout = () => setUser(null);
    window.addEventListener("securelog:logout", onLogout);
    return () => window.removeEventListener("securelog:logout", onLogout);
  }, []);

  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      /* token may already be invalid */
    }
    setToken(null);
    setUser(null);
  };

  if (checking) {
    return (
      <div className="app loginPage">
        <Loader2 size={28} className="spin" />
      </div>
    );
  }
  return user ? <App user={user} onLogout={logout} /> : <Login onLogin={setUser} />;
}