import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { LoaderCircle, RefreshCw, X } from "lucide-react";
import api from "../services/api.js";
import { useAuth } from "../context/AuthContext.jsx";
import { apiError, fmtDate, fmtScore } from "../lib/format.js";
import { DataTable, DbNotice, ErrorState, PageHeading, SeverityPill, SqlTag, StatusPill } from "../components/ui.jsx";

export default function Alerts() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const projectId = searchParams.get("project") || "";
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("open");
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState(null);

  async function load() {
    try {
      setError("");
      const params = {};
      if (status !== "all") params.status = status;
      if (projectId) params.project_id = projectId;
      setRows((await api.get("/alerts", { params })).data);
    } catch (e) {
      setError(apiError(e, "Could not load alerts."));
    }
  }
  useEffect(() => {
    load();
  }, [status, projectId]);

  async function act(row, action) {
    const key = `${row.project_id}:${row.vulnerability_id}`;
    if (action === "resolve" && !window.confirm(`Resolve ${row.cve_id} for project ${row.project_name}?`)) return;
    setBusy(`${key}:${action}`);
    setNotice(null);
    try {
      const { data } = await api.patch(`/alerts/${row.project_id}/${row.vulnerability_id}/${action}`);
      setNotice(
        action === "resolve"
          ? {
              title: `${row.cve_id} resolved`,
              lines: [
                `Procedure ${data.procedure} ran inside a transaction.`,
                `Trigger ${data.trigger} then stored a new risk snapshot for ${row.project_name}: ${fmtScore(data.riskSnapshot?.score, 2)}.`,
              ],
            }
          : { title: `${row.cve_id} acknowledged`, lines: [`Procedure ${data.procedure} moved the alert to “acknowledged”.`] },
      );
      await load();
    } catch (e) {
      setNotice({ tone: "error", title: "The database rejected the request", lines: [apiError(e, "Request failed.")] });
    } finally {
      setBusy("");
    }
  }

  return (
    <>
      <PageHeading
        eyebrow="INCIDENT RESPONSE / ALERTS"
        title="Alert center"
        description={user.role === "admin" ? "Review security findings, acknowledge them, and resolve them through stored procedures." : "Review security findings and acknowledge alerts for follow-up."}
        action={
          <button className="button button-secondary" onClick={load}>
            <RefreshCw size={15} /> Refresh
          </button>
        }
      />
      <DbNotice notice={notice} onDismiss={() => setNotice(null)} />
      {error && <ErrorState message={error} retry={load} />}
      <div className="toolbar">
        <div className="filter-tabs">
          {["open", "acknowledged", "resolved", "all"].map((s) => (
            <button key={s} className={status === s ? "filter-tab active" : "filter-tab"} onClick={() => setStatus(s)}>
              {s[0].toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        {projectId && (
          <button className="chip" onClick={() => setSearchParams({})}>
            Filtered to one project <X size={12} />
          </button>
        )}
        <SqlTag kind="PROCEDURE" name="resolve_alert" />
        <SqlTag kind="PROCEDURE" name="acknowledge_alert" />
        <span className="panel-count">{rows.length} alerts</span>
      </div>
      <section className="panel table-panel">
        <DataTable
          rows={rows}
          rowKey={(r) => r.id}
          emptyMessage={`No ${status === "all" ? "" : status + " "}alerts found.`}
          columns={[
            {
              key: "cve_id",
              label: "Finding",
              render: (r) => (
                <div>
                  <strong className="mono cve-id">{r.cve_id}</strong>
                  <small className="truncate">{r.description}</small>
                </div>
              ),
            },
            { key: "project_name", label: "Project" },
            { key: "cvss_score", label: "CVSS", render: (r) => <strong className="mono">{fmtScore(r.cvss_score)}</strong> },
            { key: "severity", label: "Severity", render: (r) => <SeverityPill severity={r.severity} /> },
            { key: "status", label: "Status", render: (r) => <StatusPill status={r.status} /> },
            { key: "created_at", label: "Detected", render: (r) => fmtDate(r.created_at) },
            {
              key: "action",
              label: "Action",
              render: (r) => {
                if (r.status === "resolved") return <span className="muted-text">Closed</span>;
                const key = `${r.project_id}:${r.vulnerability_id}`;
                const working = busy.startsWith(key);
                return (
                  <div className="row-actions">
                    {r.status === "open" && (
                      <button disabled={working} className="button button-small button-secondary" onClick={() => act(r, "acknowledge")}>
                        {busy === `${key}:acknowledge` ? <LoaderCircle size={13} className="spin" /> : "Acknowledge"}
                      </button>
                    )}
                    {user.role === "admin" && <button disabled={working} className="button button-small button-resolve" onClick={() => act(r, "resolve")}>
                      {busy === `${key}:resolve` ? <LoaderCircle size={13} className="spin" /> : "Resolve"}
                    </button>}
                  </div>
                );
              },
            },
          ]}
        />
      </section>
    </>
  );
}
