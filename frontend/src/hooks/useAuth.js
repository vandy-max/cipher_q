import { useState, useCallback } from "react";

function randomId() {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  return `id-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

// Stable per-browser device identity — the same `device_id` used
// throughout the continuous-monitoring / continuous-authorization
// demo, so "revoke this device" and the monitoring session agree on
// what device they're talking about.
function getOrCreateDeviceId() {
  let id = localStorage.getItem("ibqc_device_id");
  if (!id) {
    id = randomId();
    localStorage.setItem("ibqc_device_id", id);
  }
  return id;
}

export function useAuth() {
  const [token, setToken] = useState(() => localStorage.getItem("ibqc_token"));
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("ibqc_user") || "null");
    } catch {
      return null;
    }
  });
  const [deviceId, setDeviceId] = useState(() => getOrCreateDeviceId());
  // Fresh per login — mirrors a real CID `session_id`: it identifies
  // THIS authenticated session, not the browser/device.
  const [sessionId, setSessionId] = useState(() => localStorage.getItem("ibqc_session_id"));

  const saveAuth = useCallback((authResult) => {
    const u = {
      userId: authResult.user_id,
      username: authResult.username,
      role: authResult.role,
    };
    const newSessionId = randomId();
    const freshDeviceId = randomId();
    localStorage.setItem("ibqc_token", authResult.token);
    localStorage.setItem("ibqc_user", JSON.stringify(u));
    localStorage.setItem("ibqc_device_id", freshDeviceId);
    localStorage.setItem("ibqc_session_id", newSessionId);
    setToken(authResult.token);
    setUser(u);
    setDeviceId(freshDeviceId);
    setSessionId(newSessionId);
  }, []);

  const logout = useCallback(() => {
    const freshDeviceId = randomId();
    localStorage.removeItem("ibqc_token");
    localStorage.removeItem("ibqc_user");
    localStorage.removeItem("ibqc_session_id");
    localStorage.setItem("ibqc_device_id", freshDeviceId);
    setToken(null);
    setUser(null);
    setDeviceId(freshDeviceId);
    setSessionId(null);
  }, []);

  return { token, user, deviceId, sessionId, saveAuth, logout, isAuthenticated: !!token };
}
