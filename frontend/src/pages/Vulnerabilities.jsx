import React, { useEffect, useState } from "react";
import { Plus, RefreshCw, Search } from "lucide-react";
import api from "../services/api.js";
import { useAuth } from "../context/AuthContext.jsx";
import { apiError, fmtDate, fmtScore } from "../lib/format.js";
import { DataTable, DbNotice, ErrorState, Field, Modal, PackageVersionSelect, PageHeading, SeverityPill, SqlTag, StatusPill } from "../components/ui.jsx";

const today = () => new Date().toISOString().slice(0, 10);

function describeTrigger(r) {
  const n = r.alertsCreated?.length || 0;
  if (n) return `Trigger ${r.trigger} created ${n} alert(s) for: ${r.alertsCreated.map((a) => a.project_name).join(", ")}.`;
  if (r.belowThreshold) return `Trigger ${r.trigger} created no alerts because the CVSS score is below the 7.0 threshold.`;
  return `Trigger ${r.trigger} found no project depending on an affected version, so no alerts were created.`;
}

function NewVulnerabilityModal({ packages, onClose, onCreated }) {
  const [form, setForm] = useState({ cve_id: "", description: "", cvss_score: "", published_date: today() });
  const [affected, setAffected] = useState([{ package_version_id: "", version_range: "" }]);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  const setAff = (i, k, v) => setAffected(affected.map((a, j) => (j === i ? { ...a, [k]: v } : a)));

  async function submit(e) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      const { data } = await api.post("/vulnerabilities", { ...form, affected: affected.filter((a) => a.package_version_id) });
      onCreated(data);
    } catch (err) {
      setError(apiError(err, "Could not record the vulnerability."));
      setSaving(false);
    }
  }

  return (
    <Modal title="Record a vulnerability" subtitle="Inserts the CVE and its affected versions in one transaction. A trigger then alerts dependent projects." onClose={onClose} wide>
      <form className="form-grid" onSubmit={submit}>
        {error && <ErrorState message={error} />}
        <div className="form-row">
          <Field label="CVE id">
            <input value={form.cve_id} onChange={set("cve_id")} required placeholder="CVE-2024-12345" />
          </Field>
          <Field label="CVSS score (0-10)">
            <input type="number" min="0" max="10" step="0.1" value={form.cvss_score} onChange={set("cvss_score")} required />
          </Field>
          <Field label="Published">
            <input type="date" value={form.published_date} onChange={set("published_date")} required />
          </Field>
        </div>
        <Field label="Description">
          <input value={form.description} onChange={set("description")} required />
        </Field>
        <div className="affected-list">
          <span className="field-label">Affected package versions</span>
          {affected.map((a, i) => (
            <div className="inline-form" key={i}>
              <PackageVersionSelect packages={packages} value={a.package_version_id} onChange={(v) => setAff(i, "package_version_id", v)} />
              <input value={a.version_range} onChange={(e) => setAff(i, "version_range", e.target.value)} placeholder="Range, e.g. <4.17.19" maxLength={100} />
            </div>
          ))}
          <button type="button" className="button button-secondary button-small" onClick={() => setAffected([...affected, { package_version_id: "", version_range: "" }])}>
            <Plus size={12} /> Another version
          </button>
        </div>
        <div className="form-actions">
          <button type="button" className="button button-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="button button-quiet" disabled={saving}>
            Record vulnerability
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DetailModal({ id, packages, onClose, onChanged, canManage }) {
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState("");
  const [note, setNote] = useState(null);
  const [link, setLink] = useState({ package_version_id: "", version_range: "" });

  async function load() {
    try {
      setDetail((await api.get(`/vulnerabilities/${id}`)).data);
    } catch (e) {
      setError(apiError(e, "Could not load this vulnerability."));
    }
  }
  useEffect(() => {
    load();
  }, [id]);

  async function linkVersion(e) {
    e.preventDefault();
    setNote(null);
    try {
      const { data } = await api.post(`/vulnerabilities/${id}/affected-versions`, link);
      setNote({ title: "Affected version linked", lines: [describeTrigger(data)] });
      setLink({ package_version_id: "", version_range: "" });
      await load();
      onChanged();
    } catch (err) {
      setNote({ tone: "error", title: "Could not link the version", lines: [apiError(err, "Request failed.")] });
    }
  }

  return (
    <Modal title={detail?.vulnerability.cve_id || "Vulnerability"} subtitle={detail?.vulnerability.description} onClose={onClose} wide>
      {error && <ErrorState message={error} />}
      {detail && (
        <div className="form-grid">
          <div className="detail-meta">
            <SeverityPill severity={detail.vulnerability.severity} />
            <span className="mono">CVSS {fmtScore(detail.vulnerability.cvss_score)}</span>
            <span className="muted-text">Published {fmtDate(detail.vulnerability.published_date)}</span>
          </div>
          <DbNotice notice={note} onDismiss={() => setNote(null)} />
          <h3 className="sub-heading">Affected versions</h3>
          <DataTable
            rows={detail.affected}
            rowKey={(r) => r.id}
            emptyMessage="No affected versions linked yet."
            columns={[
              { key: "package_name", label: "Package", render: (r) => <strong>{r.package_name}</strong> },
              { key: "version", label: "Version", render: (r) => <span className="mono">{r.version}</span> },
              { key: "ecosystem", label: "Ecosystem" },
              { key: "version_range", label: "Range", render: (r) => <span className="mono">{r.version_range || "—"}</span> },
            ]}
          />
          {canManage && <form className="inline-form" onSubmit={linkVersion}>
            <PackageVersionSelect packages={packages} value={link.package_version_id} onChange={(v) => setLink({ ...link, package_version_id: v })} placeholder="Link another version" />
            <input value={link.version_range} onChange={(e) => setLink({ ...link, version_range: e.target.value })} placeholder="Range (optional)" maxLength={100} />
            <button className="button button-quiet" disabled={!link.package_version_id}>
              Link
            </button>
          </form>}
          <h3 className="sub-heading">Projects alerted</h3>
          <DataTable
            rows={detail.alerts}
            rowKey={(r) => r.project_id}
            emptyMessage="No project has an alert for this CVE."
            columns={[
              { key: "project_name", label: "Project" },
              { key: "status", label: "Status", render: (r) => <StatusPill status={r.status} /> },
            ]}
          />
        </div>
      )}
    </Modal>
  );
}

export default function Vulnerabilities() {
  const { user } = useAuth();
  const [rows, setRows] = useState([]);
  const [packages, setPackages] = useState([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [showNew, setShowNew] = useState(false);
  const [openId, setOpenId] = useState(null);
  const [notice, setNotice] = useState(null);

  async function load() {
    try {
      setError("");
      const [v, p] = await Promise.all([api.get("/vulnerabilities"), api.get("/packages")]);
      setRows(v.data);
      setPackages(p.data);
    } catch (e) {
      setError(apiError(e, "Could not load vulnerabilities."));
    }
  }
  useEffect(() => {
    load();
  }, []);

  const filtered = rows.filter(
    (r) =>
      (severity === "all" || r.severity.toLowerCase() === severity) &&
      [r.cve_id, r.description].some((v) => String(v || "").toLowerCase().includes(query.toLowerCase())),
  );

  return (
    <>
      <PageHeading
        eyebrow="THREAT INTELLIGENCE / CVE DATABASE"
        title="Vulnerabilities"
        description="Explore CVE records, CVSS scores, severity classifications, and affected package versions."
        action={
          <>
            {user.role === "admin" && <button className="button button-quiet" onClick={() => setShowNew(true)}>
              <Plus size={15} /> Record CVE
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
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search CVE ID or description…" />
        </div>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <SqlTag kind="FUNCTION" name="get_vulnerability_severity" />
        <span className="panel-count">{filtered.length} CVEs</span>
      </div>
      <section className="panel table-panel">
        <DataTable
          rows={filtered}
          rowKey={(r) => r.id}
          emptyMessage="No vulnerabilities match your filters."
          columns={[
            { key: "cve_id", label: "CVE", render: (r) => <strong className="mono cve-id">{r.cve_id}</strong> },
            { key: "description", label: "Description", render: (r) => <span className="description-cell">{r.description}</span> },
            { key: "cvss_score", label: "CVSS", render: (r) => <strong className="mono">{r.cvss_score == null ? "N/A" : fmtScore(r.cvss_score)}</strong> },
            { key: "severity", label: "Severity", render: (r) => <SeverityPill severity={r.severity} /> },
            { key: "affected_version_count", label: "Affected versions" },
            { key: "alert_count", label: "Alerts" },
            { key: "published_date", label: "Published", render: (r) => fmtDate(r.published_date) },
            {
              key: "actions",
              label: "",
              render: (r) => (
                <button className="button button-small button-secondary" onClick={() => setOpenId(r.id)}>
                  Details
                </button>
              ),
            },
          ]}
        />
      </section>
      {showNew && (
        <NewVulnerabilityModal
          packages={packages}
          onClose={() => setShowNew(false)}
          onCreated={(r) => {
            setShowNew(false);
            setNotice({ title: "Vulnerability recorded", lines: [describeTrigger(r)] });
            load();
          }}
        />
      )}
      {openId && <DetailModal id={openId} packages={packages} onClose={() => setOpenId(null)} onChanged={load} canManage={user.role === "admin"} />}
    </>
  );
}
