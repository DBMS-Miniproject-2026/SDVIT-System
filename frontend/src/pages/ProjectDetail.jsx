import React, { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Gauge, LoaderCircle, Plus, RefreshCw, Trash2 } from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import api from "../services/api.js";
import { apiError, fmtDateTime, fmtScore } from "../lib/format.js";
import { DataTable, DbNotice, EmptyState, ErrorState, PackageVersionSelect, PageHeading, SeverityPill, SqlTag, StatusPill } from "../components/ui.jsx";

const TABS = [
  { id: "dependencies", label: "Dependencies" },
  { id: "findings", label: "Findings" },
  { id: "report", label: "Report" },
  { id: "history", label: "Risk history" },
];

export default function ProjectDetail() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [packages, setPackages] = useState([]);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("dependencies");
  const [notice, setNotice] = useState(null);
  const [busy, setBusy] = useState(false);
  const [dep, setDep] = useState({ package_version_id: "", dependency_type: "direct" });

  const load = useCallback(async () => {
    try {
      setError("");
      const [detail, pk] = await Promise.all([api.get(`/projects/${id}`), api.get("/packages")]);
      setData(detail.data);
      setPackages(pk.data);
    } catch (e) {
      setError(apiError(e, "Could not load this project."));
    }
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  async function addDependency(e) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const { data: r } = await api.post(`/projects/${id}/dependencies`, dep);
      const created = r.alertsCreated || [];
      setNotice({
        title: "Dependency added",
        lines: created.length
          ? [`Trigger ${r.trigger} fired and created ${created.length} alert(s): ${created.map((a) => `${a.cve_id} (${fmtScore(a.cvss_score)})`).join(", ")}.`]
          : [`Trigger ${r.trigger} ran but found no known vulnerability with CVSS 7.0 or higher for this version.`],
      });
      setDep({ ...dep, package_version_id: "" });
      await load();
    } catch (err) {
      setNotice({ tone: "error", title: "Could not add the dependency", lines: [apiError(err, "Request failed.")] });
    } finally {
      setBusy(false);
    }
  }

  async function removeDependency(row) {
    if (!window.confirm(`Remove ${row.package_name} ${row.version} from this project?`)) return;
    try {
      await api.delete(`/projects/${id}/dependencies/${row.id}`);
      setNotice({ title: "Dependency removed", lines: ["Existing alerts are kept; resolve them from the Alert center."] });
      await load();
    } catch (err) {
      setNotice({ tone: "error", title: "Could not remove the dependency", lines: [apiError(err, "Request failed.")] });
    }
  }

  async function recompute() {
    setBusy(true);
    setNotice(null);
    try {
      const { data: r } = await api.post(`/risk/recompute/${id}`);
      setNotice({ title: "Risk snapshot recorded", lines: [`Procedure ${r.procedure} stored a score of ${fmtScore(r.score, 2)} in risk_snapshots.`] });
      await load();
    } catch (err) {
      setNotice({ tone: "error", title: "Could not recompute risk", lines: [apiError(err, "Request failed.")] });
    } finally {
      setBusy(false);
    }
  }

  if (error && !data) return <ErrorState message={error} retry={load} />;
  if (!data)
    return (
      <div className="loading">
        <LoaderCircle className="spin" size={24} /> Loading project…
      </div>
    );

  const { project, dependencies, findings, report, history } = data;
  const chartData = history.map((h) => ({ time: fmtDateTime(h.computed_at), score: Number(h.score) }));
  const latest = history.length ? history[history.length - 1].score : null;

  return (
    <>
      <PageHeading
        eyebrow={`INVENTORY / PROJECTS / ${project.name.toUpperCase()}`}
        title={project.name}
        description={project.description || `Owned by ${project.owner_name}. ${project.repo_url || ""}`}
        action={
          <>
            <Link to="/projects" className="button button-secondary">
              <ArrowLeft size={15} /> Projects
            </Link>
            <button className="button button-quiet" onClick={recompute} disabled={busy}>
              <Gauge size={15} /> Recompute risk
            </button>
            <button className="button button-secondary" onClick={load}>
              <RefreshCw size={15} /> Refresh
            </button>
          </>
        }
      />
      <DbNotice notice={notice} onDismiss={() => setNotice(null)} />
      {error && <ErrorState message={error} retry={load} />}

      <div className="stat-strip">
        <div>
          <span>Open alerts</span>
          <strong>{project.open_alert_count}</strong>
          <SqlTag kind="FUNCTION" name="get_open_alert_count" />
        </div>
        <div>
          <span>Max CVSS</span>
          <strong>{fmtScore(project.max_cvss_score)}</strong>
          <SqlTag kind="VIEW" name="project_risk_overview" />
        </div>
        <div>
          <span>Avg. CVSS</span>
          <strong>{fmtScore(project.avg_cvss_score, 2)}</strong>
          <SqlTag kind="VIEW" name="project_risk_overview" />
        </div>
        <div>
          <span>Latest risk score</span>
          <strong>{fmtScore(latest, 2)}</strong>
          <SqlTag kind="TABLE" name="risk_snapshots" />
        </div>
        <div>
          <span>Alert center</span>
          <Link className="text-link" to={`/alerts?project=${id}`}>
            Manage this project's alerts
          </Link>
        </div>
      </div>

      <div className="toolbar">
        <div className="filter-tabs">
          {TABS.map((t) => (
            <button key={t.id} className={tab === t.id ? "filter-tab active" : "filter-tab"} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {tab === "dependencies" && (
        <>
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Add a dependency</h2>
                <p>INSERT INTO project_dependencies. A trigger checks the version against known CVEs and raises alerts.</p>
              </div>
              <SqlTag kind="TRIGGER" name="trg_alert_on_new_dependency" />
            </div>
            <form className="inline-form" onSubmit={addDependency}>
              <PackageVersionSelect packages={packages} value={dep.package_version_id} onChange={(v) => setDep({ ...dep, package_version_id: v })} />
              <select value={dep.dependency_type} onChange={(e) => setDep({ ...dep, dependency_type: e.target.value })}>
                <option value="direct">direct</option>
                <option value="dev">dev</option>
                <option value="transitive">transitive</option>
              </select>
              <button className="button button-quiet" disabled={busy || !dep.package_version_id}>
                <Plus size={14} /> Add
              </button>
            </form>
          </section>
          <section className="panel table-panel">
            <div className="panel-heading">
              <div>
                <h2>Declared dependencies</h2>
                <p>{dependencies.length} package versions</p>
              </div>
              <SqlTag kind="TABLE" name="project_dependencies" />
            </div>
            <DataTable
              rows={dependencies}
              rowKey={(r) => r.id}
              emptyMessage="This project has no dependencies yet."
              columns={[
                { key: "package_name", label: "Package", render: (r) => <strong>{r.package_name}</strong> },
                { key: "version", label: "Version", render: (r) => <span className="mono">{r.version}</span> },
                { key: "ecosystem", label: "Ecosystem" },
                { key: "dependency_type", label: "Type" },
                { key: "known_cve_count", label: "Known CVEs", render: (r) => <span className={r.known_cve_count ? "score score-high" : "muted-text"}>{r.known_cve_count}</span> },
                { key: "added_at", label: "Added", render: (r) => fmtDateTime(r.added_at) },
                {
                  key: "actions",
                  label: "",
                  render: (r) => (
                    <button className="button button-small button-danger" onClick={() => removeDependency(r)} aria-label={`Remove ${r.package_name}`}>
                      <Trash2 size={12} />
                    </button>
                  ),
                },
              ]}
            />
          </section>
        </>
      )}

      {tab === "findings" && (
        <section className="panel table-panel">
          <div className="panel-heading">
            <div>
              <h2>Vulnerable dependencies</h2>
              <p>Every dependency joined to the CVEs that affect it and to the alert raised for it</p>
            </div>
            <SqlTag kind="VIEW" name="project_vulnerability_details" />
          </div>
          <DataTable
            rows={findings}
            rowKey={(r) => `${r.package_name}-${r.package_version}-${r.cve_id}`}
            emptyMessage="No vulnerable dependencies found for this project."
            columns={[
              { key: "package_name", label: "Package", render: (r) => <strong>{r.package_name}</strong> },
              { key: "package_version", label: "Version", render: (r) => <span className="mono">{r.package_version}</span> },
              { key: "ecosystem", label: "Ecosystem" },
              { key: "cve_id", label: "CVE", render: (r) => <strong className="mono cve-id">{r.cve_id}</strong> },
              { key: "cvss_score", label: "CVSS", render: (r) => <span className="mono">{fmtScore(r.cvss_score)}</span> },
              { key: "severity", label: "Severity", render: (r) => <SeverityPill severity={r.severity} /> },
              { key: "alert_status", label: "Alert", render: (r) => <StatusPill status={r.alert_status} /> },
            ]}
          />
        </section>
      )}

      {tab === "report" && (
        <section className="panel table-panel">
          <div className="panel-heading">
            <div>
              <h2>Vulnerability report</h2>
              <p>Result set returned by CALL get_project_vulnerability_report(project_id), sorted by CVSS</p>
            </div>
            <SqlTag kind="PROCEDURE" name="get_project_vulnerability_report" />
          </div>
          <DataTable
            rows={report}
            rowKey={(r) => r.cve_id}
            emptyMessage="This project has no alerts."
            columns={[
              { key: "cve_id", label: "CVE", render: (r) => <strong className="mono cve-id">{r.cve_id}</strong> },
              { key: "description", label: "Description", render: (r) => <span className="description-cell">{r.description}</span> },
              { key: "cvss_score", label: "CVSS", render: (r) => <span className="mono">{fmtScore(r.cvss_score)}</span> },
              { key: "severity", label: "Severity", render: (r) => <SeverityPill severity={r.severity} /> },
              { key: "alert_status", label: "Status", render: (r) => <StatusPill status={r.alert_status} /> },
              { key: "alert_created_at", label: "Raised", render: (r) => fmtDateTime(r.alert_created_at) },
            ]}
          />
        </section>
      )}

      {tab === "history" && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Risk score over time</h2>
              <p>Each point is a risk_snapshots row: from the recompute procedures, or written by the trigger when an alert is resolved</p>
            </div>
            <SqlTag kind="TABLE" name="risk_snapshots" />
          </div>
          {chartData.length === 0 ? (
            <EmptyState message="No snapshots yet. Use “Recompute risk” or resolve an alert to create one." />
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={chartData} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#67e8f9" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#67e8f9" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1e2a3c" vertical={false} />
                <XAxis dataKey="time" tick={{ fill: "#718198", fontSize: 9 }} tickLine={false} axisLine={false} minTickGap={30} />
                <YAxis tick={{ fill: "#718198", fontSize: 9 }} tickLine={false} axisLine={false} width={36} />
                <Tooltip contentStyle={{ background: "#111827", border: "1px solid #263247", borderRadius: 10, color: "#e5edf8" }} />
                <Area type="stepAfter" dataKey="score" stroke="#67e8f9" strokeWidth={2} fill="url(#riskFill)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </section>
      )}
    </>
  );
}
