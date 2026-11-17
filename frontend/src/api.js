import axios from "axios";

export const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
const TOKEN_KEY = "securelog_token";

// sessionStorage: the login ends when the browser tab is closed.
export const getToken = () => sessionStorage.getItem(TOKEN_KEY);
export const setToken = (token) =>
  token ? sessionStorage.setItem(TOKEN_KEY, token) : sessionStorage.removeItem(TOKEN_KEY);

export const api = axios.create({ baseURL: API_URL, timeout: 20000 });

// Attach the session token to every request.
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Session expired or revoked -> back to the login page.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const url = error.config?.url || "";
    if (error.response?.status === 401 && !url.includes("/auth/login")) {
      setToken(null);
      window.dispatchEvent(new Event("securelog:logout"));
    }
    return Promise.reject(error);
  }
);

export const errorMessage = (error, fallback) =>
  error?.response?.data?.detail
    ? typeof error.response.data.detail === "string"
      ? error.response.data.detail
      : fallback
    : error?.response
    ? fallback
    : "Backend is not reachable. Is the FastAPI server running?";