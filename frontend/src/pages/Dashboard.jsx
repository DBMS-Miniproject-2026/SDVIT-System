import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Activity, AlertTriangle, Boxes, FolderKanban, LoaderCircle, RefreshCw, ShieldAlert, Gauge } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import api from "../services/api.js";
import { useAuth } from "../context/AuthContext.jsx";
import { apiError, fmtScore } from "../lib/format.js";
import { DataTable, DbNotice, EmptyState, ErrorState, MetricCard, PageHeading, SqlTag, StatusPill } from "../components/ui.jsx";

const SEVERITY_COLORS = { Critical: "#fb7185", High: "#fb923c", Medium: "#facc15", Low: "#34d399" };

export default function Dashboard() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);

  async function load() {
    setLoading(true);
    setError("");
    try {
      setData((await api.get("/dashboard")).data);
    } catch (e) {
      setError(apiError(e, "Check that the backend and MySQL server are running."));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function recomputeAll() {
    setBusy(true);
    setNotice(null);
    try {
      const { data: r } = await api.post("/risk/recompute");
      setNotice({
        title: "Risk snapshots recorded",
        lines: [`Procedure ${r.procedure} looped over ${r.processed} projects with a cursor and stored one risk_snapshots row for each.`],
      });
      await load();
    } catch (e) {
      setNotice({ tone: "error", title: "Could not recompute risk", lines: [apiError(e, "Request failed.")] });
    } finally {
      setBusy(false);
    }
  }

  const counts = data?.counts || {};
  const severityData = useMemo(
    () =>
      ["Critical", "High", "Medium", "Low"].map((name) => ({
        name,
        count: Number(data?.severity?.find((s) => s.severity === name)?.count || 0),
      })),
    [data],
  );

  const projectColumns = [
    {
      key: "project_name",
      label: "Project",
      render: (r) => (
        <Link to={`/projects/${r.project_id}`} className="project-cell">
          <span className="project-avatar">{(r.project_name || "?").slice(0, 1).toUpperCase()}</span>
          <div>
            <strong>{r.project_name}</strong>
            <small>{r.dependency_count} dependencies</small>
          </div>
        </Link>
      ),
    },
    { key: "open_alert_count", label: "Open alerts" },
    {
      key: "max_cvss_score",
      label: "Max CVSS",
      render: (r) => (
        <span className={Number(r.max_cvss_score) >= 9 ? "score score-critical" : Number(r.max_cvss_score) >= 7 ? "score score-high" : "score"}>
          {fmtScore(r.max_cvss_score)}
        </span>
      ),
    },
    { key: "avg_cvss_score", label: "Avg. CVSS", render: (r) => fmtScore(r.avg_cvss_score, 2) },
    { key: "latest_risk_score", label: "Risk score", render: (r) => <span className="mono">{fmtScore(r.latest_risk_score, 2)}</span> },
  ];

  const alertColumns = [
    {
      key: "cve_id",
      label: "Vulnerability",
      render: (r) => (
        <div>
          <strong className="mono">{r.cve_id}</strong>
          <small className="truncate">{r.description}</small>
        </div>
      ),
    },
    { key: "project_name", label: "Project" },
    { key: "cvss_score", label: "CVSS", render: (r) => <span className="mono">{fmtScore(r.cvss_score)}</span> },
    { key: "status", label: "Status", render: (r) => <StatusPill status={r.status} /> },
  ];

  if (loading && !data)
    return (
      <div className="loading">
        <LoaderCircle className="spin" size={24} /> Connecting to SDVIT database…
      </div>
    );

  return (
    <>
      <PageHeading
        eyebrow="SECURITY POSTURE / OVERVIEW"
        title="Security overview"
        description="Monitor your software supply chain, vulnerable dependencies, and project exposure."
        action={
          <>
            {user.role === "admin" && <button className="button button-quiet" onClick={recomputeAll} disabled={busy}>
              {busy ? <LoaderCircle size={15} className="spin" /> : <Gauge size={15} />} Recompute all risk
            </button>}
            <button className="button button-secondary" onClick={load}>
              <RefreshCw size={15} /> Refresh
            </button>
          </>
        }
      />
      <DbNotice notice={notice} onDismiss={() => setNotice(null)} />
      {error && <ErrorState message={error} retry={load} />}
      <div className="metric-grid">
        <MetricCard label="Tracked projects" value={counts.project_count} detail="Projects registered" icon={FolderKanban} />
        <MetricCard label="Packages" value={counts.package_count} detail="Unique libraries tracked" icon={Boxes} tone="violet" />
        <MetricCard label="Known vulnerabilities" value={counts.vulnerability_count} detail="CVE records in database" icon={ShieldAlert} tone="orange" />
        <MetricCard
          label="Open alerts"
          value={counts.open_alert_count}
          detail={`${counts.acknowledged_alert_count || 0} acknowledged · ${counts.resolved_alert_count || 0} resolved`}
          icon={AlertTriangle}
          tone="red"
        />
      </div>
      <div className="content-grid">
        <section className="panel chart-panel">
          <div className="panel-heading">
            <div>
              <h2>Open vulnerability severity</h2>
              <p>Distinct CVEs linked to open alerts</p>
            </div>
            <SqlTag kind="FUNCTION" name="get_vulnerability_severity" />
          </div>
          {severityData.reduce((n, s) => n + s.count, 0) === 0 ? (
            <EmptyState message="No open vulnerability data available yet." />
          ) : (
            <div className="chart-area">
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie data={severityData.filter((s) => s.count > 0)} dataKey="count" nameKey="name" innerRadius={65} outerRadius={90} paddingAngle={4} stroke="none">
                    {severityData
                      .filter((s) => s.count > 0)
                      .map((s) => (
                        <Cell key={s.name} fill={SEVERITY_COLORS[s.name]} />
                      ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#111827", border: "1px solid #263247", borderRadius: 10, color: "#e5edf8" }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="legend">
                {severityData.map((s) => (
                  <div className="legend-row" key={s.name}>
                    <span className={`legend-dot ${s.name.toLowerCase()}`} />
                    <span>{s.name}</span>
                    <strong>{s.count}</strong>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Risk snapshot</h2>
              <p>Projects ranked by highest CVSS</p>
            </div>
            <Activity size={18} className="muted-icon" />
          </div>
          {!data?.projects?.length ? (
            <EmptyState message="Projects will appear here when data is available." />
          ) : (
            <div className="risk-list">
              {data.projects.slice(0, 5).map((p) => (
                <div className="risk-item" key={p.project_id}>
                  <div className="risk-item-top">
                    <span>{p.project_name}</span>
                    <strong>
                      {fmtScore(p.max_cvss_score)} <small>CVSS</small>
                    </strong>
                  </div>
                  <div className="risk-track">
                    <span style={{ width: `${Math.max(0, Math.min(100, Number(p.max_cvss_score || 0) * 10))}%` }} />
                  </div>
                  <div className="risk-item-bottom">
                    <span>{p.open_alert_count} open alerts</span>
                    <span>{p.dependency_count} dependencies</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <h2>Highest exposure projects</h2>
            <p>Risk score is the latest row in risk_snapshots (sum of open CVSS scores)</p>
          </div>
          <SqlTag kind="VIEW" name="project_risk_overview" />
        </div>
        <DataTable columns={projectColumns} rows={data?.projects || []} rowKey={(r) => r.project_id} emptyMessage="No projects found in the database." />
      </section>
      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <h2>Recent alerts</h2>
            <p>Latest vulnerability alerts across projects</p>
          </div>
          <span className="panel-count">{data?.recentAlerts?.length || 0} shown</span>
        </div>
        <DataTable columns={alertColumns} rows={data?.recentAlerts || []} emptyMessage="No alerts found." />
      </section>
    </>
  );
}
