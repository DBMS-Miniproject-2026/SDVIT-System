import React, { useEffect, useState } from "react";
import { Plus, RefreshCw, Search, Trash2 } from "lucide-react";
import api from "../services/api.js";
import { useAuth } from "../context/AuthContext.jsx";
import { apiError, fmtDate } from "../lib/format.js";
import { DbNotice, EmptyState, ErrorState, Field, Modal, PageHeading, SqlTag } from "../components/ui.jsx";

const ECOSYSTEMS = ["npm", "pypi", "maven", "cargo", "other"];

function NewVersionModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ name: "", ecosystem: "npm", version: "", release_date: "" });
  const [error, setError] = useState("");
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  async function submit(e) {
    e.preventDefault();
    setError("");
    try {
      await api.post("/packages/versions", form);
      onCreated();
    } catch (err) {
      setError(apiError(err, "Could not add the package version."));
    }
  }
  return (
    <Modal title="Add package version" subtitle="Creates the package if it is new, then inserts the version, in one transaction." onClose={onClose}>
      <form className="form-grid" onSubmit={submit}>
        {error && <ErrorState message={error} />}
        <Field label="Package name">
          <input value={form.name} onChange={set("name")} required maxLength={150} />
        </Field>
        <Field label="Ecosystem">
          <select value={form.ecosystem} onChange={set("ecosystem")}>
            {ECOSYSTEMS.map((e) => (
              <option key={e}>{e}</option>
            ))}
          </select>
        </Field>
        <Field label="Version">
          <input value={form.version} onChange={set("version")} required maxLength={50} placeholder="4.17.21" />
        </Field>
        <Field label="Release date">
          <input type="date" value={form.release_date} onChange={set("release_date")} />
        </Field>
        <div className="form-actions">
          <button type="button" className="button button-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="button button-quiet">Add version</button>
        </div>
      </form>
    </Modal>
  );
}

export default function Packages() {
  const { user } = useAuth();
  const [packages, setPackages] = useState([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [notice, setNotice] = useState(null);

  async function load() {
    try {
      setError("");
      setPackages((await api.get("/packages")).data);
    } catch (e) {
      setError(apiError(e, "Could not load packages."));
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function remove(pkg) {
    if (!window.confirm(`Delete package "${pkg.name}" and all of its versions?`)) return;
    try {
      const { data } = await api.delete(`/packages/${pkg.id}`);
      setNotice({ title: `Deleted ${pkg.name}`, lines: [`ON DELETE CASCADE removed its ${data.cascaded?.versions ?? 0} version(s) and the CVE links attached to them.`] });
      load();
    } catch (e) {
      setNotice({
        tone: "error",
        title: `Could not delete ${pkg.name}`,
        lines: [apiError(e, "Request failed."), "A version that a project still depends on is protected by the foreign key from project_dependencies."],
      });
    }
  }

  const filtered = packages.filter((p) => `${p.name} ${p.ecosystem}`.toLowerCase().includes(query.toLowerCase()));

  return (
    <>
      <PageHeading
        eyebrow="INVENTORY / PACKAGES"
        title="Packages"
        description="Libraries and their released versions, with how many CVEs and projects touch each version."
        action={
          <>
            {user.role === "admin" && <button className="button button-quiet" onClick={() => setShowNew(true)}>
              <Plus size={15} /> Add version
            </button>}
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
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search packages or ecosystems…" />
        </div>
        <SqlTag kind="TABLE" name="packages" />
        <SqlTag kind="TABLE" name="package_versions" />
        <span className="panel-count">{filtered.length} packages</span>
      </div>
      {filtered.length === 0 ? (
        <section className="panel">
          <EmptyState message="No packages match." />
        </section>
      ) : (
        <div className="card-grid">
          {filtered.map((p) => (
            <section className="panel package-card" key={p.id}>
              <div className="panel-heading">
                <div>
                  <h2>{p.name}</h2>
                  <p>{p.ecosystem}</p>
                </div>
                {user.role === "admin" && <button className="button button-small button-danger" onClick={() => remove(p)} aria-label={`Delete ${p.name}`}>
                  <Trash2 size={12} />
                </button>}
              </div>
              {p.versions.length === 0 ? (
                <p className="muted-text">No versions recorded.</p>
              ) : (
                <ul className="version-list">
                  {p.versions.map((v) => (
                    <li key={v.id}>
                      <span className="mono">{v.version}</span>
                      <small>{fmtDate(v.release_date)}</small>
                      <span className={v.cve_count ? "pill pill-warn" : "pill"}>{v.cve_count} CVE</span>
                      <span className="pill">{v.project_count} project</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ))}
        </div>
      )}
      {showNew && (
        <NewVersionModal
          onClose={() => setShowNew(false)}
          onCreated={() => {
            setShowNew(false);
            setNotice({ title: "Package version added", lines: ["It can now be added to a project or linked to a CVE."] });
            load();
          }}
        />
      )}
    </>
  );
}
