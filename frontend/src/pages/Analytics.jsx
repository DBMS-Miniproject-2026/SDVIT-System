import React, { useEffect, useState } from "react";
import { Code2, RefreshCw } from "lucide-react";
import api from "../services/api.js";
import { apiError } from "../lib/format.js";
import { DataTable, ErrorState, PageHeading } from "../components/ui.jsx";

const label = (k) => k.replace(/_/g, " ");

function QueryPanel({ q }) {
  const [showSql, setShowSql] = useState(false);
  const keys = q.rows[0] ? Object.keys(q.rows[0]) : [];
  const columns = keys.map((k) => ({
    key: k,
    label: label(k),
    render: (r) => (typeof r[k] === "number" ? <span className="mono">{r[k]}</span> : (r[k] ?? "—")),
  }));
  return (
    <section className="panel table-panel">
      <div className="panel-heading">
        <div>
          <h2>{q.title}</h2>
          <p>{q.concept}</p>
        </div>
        <button className="button button-small button-secondary" onClick={() => setShowSql(!showSql)}>
          <Code2 size={12} /> {showSql ? "Hide SQL" : "Show SQL"}
        </button>
      </div>
      {showSql && <pre className="sql-block">{q.sql}</pre>}
      <DataTable columns={columns} rows={q.rows} rowKey={(r) => JSON.stringify(r)} emptyMessage="The query returned no rows." />
    </section>
  );
}

export default function Analytics() {
  const [queries, setQueries] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    try {
      setError("");
      setQueries((await api.get("/analytics")).data);
    } catch (e) {
      setError(apiError(e, "Could not run the analytics queries."));
    }
  }
  useEffect(() => {
    load();
  }, []);

  return (
    <>
      <PageHeading
        eyebrow="INSIGHTS / SQL ANALYTICS"
        title="Analytics"
        description="Live results of the project's analytical SQL: joins, grouping, set operations and subqueries."
        action={
          <button className="button button-secondary" onClick={load}>
            <RefreshCw size={15} /> Refresh
          </button>
        }
      />
      {error && <ErrorState message={error} retry={load} />}
      {queries.map((q) => (
        <QueryPanel key={q.key} q={q} />
      ))}
    </>
  );
}
