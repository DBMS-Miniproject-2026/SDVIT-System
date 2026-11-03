"use client";

import React, { useState } from "react";
import { ArrowRight, KeyRound, ShieldCheck } from "lucide-react";
import { useAuth } from "../context/AuthContext.jsx";
import api from "../services/api.js";

export default function Login() {
  const { login } = useAuth();
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("admin@sdvit.example");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    setNotice("");
    if (mode === "setup" && password !== confirm) {
      setError("The passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      if (mode === "setup") {
        const { data } = await api.post("/auth/bootstrap", { email, password });
        setNotice(data.message);
        setMode("login");
        setPassword("");
        setConfirm("");
      } else {
        await login(email, password);
      }
    } catch (err) {
      setError(err.response?.data?.message || "Could not complete the request. Check that the API and MySQL are running.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-screen">
      <section className="auth-card">
        <div className="auth-brand"><span><ShieldCheck size={26} /></span><div><strong>SDVIT<span>.</span></strong><small>SECURITY INTELLIGENCE</small></div></div>
        <div className="auth-intro">
          <div className="auth-eyebrow">SOFTWARE DEPENDENCY SECURITY</div>
          <h1>{mode === "setup" ? "Initialize administrator" : "Sign in to SDVIT"}</h1>
          <p>{mode === "setup" ? "Set a password for the seeded administrator account. This one-time setup replaces the SQL demo placeholder." : "Access project exposure, vulnerability alerts and dependency risk insights."}</p>
        </div>
        <form onSubmit={submit} className="auth-form">
          <label>Email address<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required disabled={mode === "setup"} /></label>
          <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === "setup" ? "new-password" : "current-password"} minLength={12} maxLength={128} required placeholder="At least 12 characters" /></label>
          {mode === "setup" && <label>Confirm password<input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" minLength={12} maxLength={128} required /></label>}
          {error && <div className="auth-message error">{error}</div>}
          {notice && <div className="auth-message success">{notice}</div>}
          <button className="button button-quiet auth-submit" disabled={busy}>{busy ? "Please wait…" : mode === "setup" ? "Set administrator password" : "Sign in"}<ArrowRight size={15} /></button>
        </form>
        <div className="auth-footer">
          <KeyRound size={14} />
          {mode === "login" ? "First run? " : "Already initialized? "}
          <button type="button" onClick={() => { setMode(mode === "login" ? "setup" : "login"); setError(""); setNotice(""); setPassword(""); setConfirm(""); }}> {mode === "login" ? "Initialize admin" : "Return to sign in"}</button>
        </div>
        <div className="auth-security">Passwords are stored as salted scrypt hashes. Sessions expire after 8 hours.</div>
      </section>
    </main>
  );
}
