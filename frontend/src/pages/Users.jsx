"use client";

import React, { useEffect, useState } from "react";
import { Plus, RefreshCw, Shield, UserRound } from "lucide-react";
import api from "../services/api.js";
import { apiError } from "../lib/format.js";
import { ErrorState, Field, PageHeading } from "../components/ui.jsx";

export default function Users() {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ name: "", email: "", password: "", role: "developer" });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try { setError(""); setUsers((await api.get("/users")).data); }
    catch (err) { setError(apiError(err, "Could not load users.")); }
  }
  useEffect(() => { load(); }, []);

  async function createUser(event) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      await api.post("/auth/users", form);
      setForm({ name: "", email: "", password: "", role: "developer" });
      setNotice("User account created successfully.");
      await load();
    } catch (err) { setError(apiError(err, "Could not create user.")); }
    finally { setBusy(false); }
  }

  return <>
    <PageHeading eyebrow="ACCESS CONTROL / USERS" title="User management" description="Create accounts and assign the Admin or Developer role. The API enforces permissions on protected operations." action={<button className="button button-secondary" onClick={load}><RefreshCw size={15}/> Refresh</button>} />
    {error && <ErrorState message={error} retry={load}/>}
    {notice && <div className="notice success">{notice}</div>}
    <section className="panel user-admin-panel">
      <div className="panel-heading"><div><h2>Create user account</h2><p>Passwords must be at least 12 characters and are hashed before storage.</p></div></div>
      <form className="form-grid users-form" onSubmit={createUser}>
        <Field label="Full name"><input required maxLength={120} value={form.name} onChange={(e)=>setForm({...form,name:e.target.value})}/></Field>
        <Field label="Email"><input type="email" required maxLength={255} value={form.email} onChange={(e)=>setForm({...form,email:e.target.value})}/></Field>
        <Field label="Temporary password"><input type="password" required minLength={12} maxLength={128} value={form.password} onChange={(e)=>setForm({...form,password:e.target.value})}/></Field>
        <Field label="Role"><select value={form.role} onChange={(e)=>setForm({...form,role:e.target.value})}><option value="developer">Developer</option><option value="admin">Admin</option></select></Field>
        <div className="form-actions"><button className="button button-quiet" disabled={busy}><Plus size={14}/> {busy ? "Creating…" : "Create account"}</button></div>
      </form>
    </section>
    <section className="panel user-list-panel">
      <div className="panel-heading"><div><h2>Registered users</h2><p>{users.length} account(s) in the MySQL users table.</p></div></div>
      <div className="user-list">{users.map((user)=><div className="user-row" key={user.id}><span className="user-avatar"><UserRound size={16}/></span><div className="user-info"><strong>{user.name}</strong><small>{user.email}</small></div><span className={`role-chip ${user.role}`}><Shield size={12}/>{user.role}</span></div>)}</div>
    </section>
  </>;
}
