import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronRight, Plus, RefreshCw, Search, Trash2 } from "lucide-react";
import api from "../services/api.js";
import { useAuth } from "../context/AuthContext.jsx";
import { apiError, fmtScore } from "../lib/format.js";
import { DataTable, DbNotice, ErrorState, Field, Modal, PageHeading, SqlTag } from "../components/ui.jsx";

function NewProjectModal({ onClose, onCreated }) {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ name: "", owner_id: "", repo_url: "", description: "" });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.get("/users").then((r) => {
      setUsers(r.data);
      if (r.data[0]) setForm((f) => ({ ...f, owner_id: r.data[0].id }));
    });
  }, []);

  async function submit(e) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      await api.post("/projects", form);
      onCreated();
    } catch (err) {
      setError(apiError(err, "Could not create the project."));
      setSaving(false);
    }
  }
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  return (
    <Modal title="New project" subtitle="INSERT INTO projects. The (owner, name) pair must be unique." onClose={onClose}>
      <form onSubmit={submit} className="form-grid">
        {error && <ErrorState message={error} />}
        <Field label="Project name">
          <input value={form.name} onChange={set("name")} required maxLength={150} />
        </Field>
        <Field label="Owner">
          <select value={form.owner_id} onChange={set("owner_id")} required>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.name} ({u.role})
              </option>
            ))}
          </select>
        </Field>
        <Field label="Repository URL">
          <input value={form.repo_url} onChange={set("repo_url")} placeholder="https://github.com/…" maxLength={500} />
        </Field>
        <Field label="Description">
          <input value={form.description} onChange={set("description")} maxLength={500} />
        </Field>
        <div className="form-actions">
          <button type="button" className="button button-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="button button-quiet" disabled={saving}>
            Create project
          </button>
        </div>
      </form>
    </Modal>
  );
}

export default function Projects() {
  const { user } = useAuth();
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [notice, setNotice] = useState(null);

  async function load() {
    try {
      setError("");
      setRows((await api.get("/projects")).data);
    } catch (e) {
      setError(apiError(e, "Could not load projects."));
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function remove(row) {
    if (!window.confirm(`Delete project "${row.name}"? Its dependencies, alerts and risk history are deleted with it.`)) return;
    try {
      const { data } = await api.delete(`/projects/${row.id}`);
      const c = data.cascaded || {};
      setNotice({
        title: `Deleted ${row.name}`,
        lines: [`ON DELETE CASCADE also removed ${c.dependencies} dependencies, ${c.alerts} alerts and ${c.risk_snapshots} risk snapshots.`],
      });
      load();
    } catch (e) {
      setError(apiError(e, "Could not delete the project."));
    }
  }

  const filtered = rows.filter((r) =>
    [r.name, r.owner_name, r.repo_url].some((v) => String(v || "").toLowerCase().includes(query.toLowerCase())),
  );

  return (
    <>
      <PageHeading
        eyebrow="INVENTORY / PROJECTS"
        title="Projects"
        description="Review registered repositories, dependencies, and current vulnerability exposure."
        action={
          <>
            <button className="button button-quiet" onClick={() => setShowNew(true)}>
              <Plus size={15} /> New project
            </button>
            <button className="button button-secondary" onClick={load}>
              <RefreshCw size={15} /> Refresh
            </button>
          </>
        }
      />
      <DbNotice notice={notice} onDismiss={() => setNotice(null)} />
      {error && <ErrorState message={error} retry={load} />}
      <div className="toolbar">
        <div className="search-box">
          <Search size={16} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search projects, owners, repositories…" />
        </div>
        <SqlTag kind="VIEW" name="project_risk_overview" />
        <SqlTag kind="FUNCTION" name="get_open_alert_count" />
        <span className="panel-count">{filtered.length} projects</span>
      </div>
      <section className="panel table-panel">
        <DataTable
          rows={filtered}
          rowKey={(r) => r.id}
          emptyMessage="No matching projects."
          columns={[
            {
              key: "name",
              label: "Project",
              render: (r) => (
                <Link to={`/projects/${r.id}`} className="project-cell">
                  <span className="project-avatar">{r.name.slice(0, 1).toUpperCase()}</span>
                  <div>
                    <strong>{r.name}</strong>
                    <small>{r.description || "No description provided"}</small>
                  </div>
                </Link>
              ),
            },
            { key: "owner_name", label: "Owner" },
            { key: "dependency_count", label: "Dependencies" },
            { key: "open_alert_count", label: "Open alerts" },
            { key: "max_cvss_score", label: "Max CVSS", render: (r) => <span className="mono">{fmtScore(r.max_cvss_score)}</span> },
            { key: "latest_risk_score", label: "Risk score", render: (r) => <span className="mono">{fmtScore(r.latest_risk_score, 2)}</span> },
            {
              key: "repo_url",
              label: "Repository",
              render: (r) =>
                r.repo_url ? (
                  <a className="text-link" href={r.repo_url} target="_blank" rel="noreferrer">
                    Open repo <ChevronRight size={13} />
                  </a>
                ) : (
                  "—"
                ),
            },
            {
              key: "actions",
              label: "",
              render: (r) => user.role === "admin" ? (
                <button className="button button-small button-danger" onClick={() => remove(r)} aria-label={`Delete ${r.name}`}>
                  <Trash2 size={12} />
                </button>
              ) : null,
            },
          ]}
        />
      </section>
      {showNew && (
        <NewProjectModal
          onClose={() => setShowNew(false)}
          onCreated={() => {
            setShowNew(false);
            load();
          }}
        />
      )}
    </>
  );
}
