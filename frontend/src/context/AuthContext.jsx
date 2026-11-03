"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import api from "../services/api.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const logout = useCallback(() => {
    if (typeof window !== "undefined") window.localStorage.removeItem("sdvit_access_token");
    setUser(null);
  }, []);

  useEffect(() => {
    let active = true;
    const onExpired = () => { if (active) setUser(null); };
    window.addEventListener("sdvit:auth-expired", onExpired);
    const token = window.localStorage.getItem("sdvit_access_token");
    if (!token) {
      setLoading(false);
    } else {
      api.get("/auth/me")
        .then(({ data }) => { if (active) setUser(data); })
        .catch(() => { if (active) logout(); })
        .finally(() => { if (active) setLoading(false); });
    }
    return () => {
      active = false;
      window.removeEventListener("sdvit:auth-expired", onExpired);
    };
  }, [logout]);

  const login = useCallback(async (email, password) => {
    const { data } = await api.post("/auth/login", { email, password });
    window.localStorage.setItem("sdvit_access_token", data.token);
    setUser(data.user);
  }, []);

  const value = useMemo(() => ({ user, loading, login, logout }), [user, loading, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider.");
  return value;
}
