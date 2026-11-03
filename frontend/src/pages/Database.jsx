import React, { useEffect, useState } from "react";
import { FlaskConical, RefreshCw } from "lucide-react";
import api from "../services/api.js";
import { apiError } from "../lib/format.js";
import { DataTable, DbNotice, ErrorState, Modal, PageHeading } from "../components/ui.jsx";

export default function Database() {
  const [objects, setObjects] = useState(null);
  const [explain, setExplain] = useState(null);
  const [demo, setDemo] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState(null);

  async function load() {
    try {
      setError("");
      const [o, x] = await Promise.all([api.get("/database/objects"), api.get("/database/explain")]);
      setObjects(o.data);
      setExplain(x.data);
    } catch (e) {
      setError(apiError(e, "Could not read the database catalog."));
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function runDemo() {
    setBusy(true);
    setDemo(null);
    try {
      setDemo({ ok: true, ...(await api.post("/database/rollback-demo")).data });
      await load();
    } catch (e) {
      setDemo({ ok: false, message: apiError(e, "The demo could not run.") });
    } finally {
      setBusy(false);
    }
  }

  const viewSource = (kind) => (r) => (
    <button className="button button-small button-secondary" onClick={() => setSource({ title: `${kind} ${r.name}`, body: r.definition })}>
      View source
    </button>
  );
  const usedBy = { key: "usedBy", label: "Used in the app", render: (r) => <span className="muted-text">{r.usedBy || "—"}</span> };

  return (
    <>
      <PageHeading
        eyebrow="SYSTEM / DATABASE"
        title="Database objects"
        description="Everything defined in MySQL for this system, read live from information_schema, and where the app uses it."
        action={
          <button className="button button-secondary" onClick={load}>
            <RefreshCw size={15} /> Refresh
          </button>
        }
      />
      {error && <ErrorState message={error} retry={load} />}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Transaction demo</h2>
            <p>Resolves the most severe open alert inside a transaction, shows the effect (including the snapshot written by the trigger), then ROLLBACK undoes both.</p>
          </div>
          <button className="button button-quiet" onClick={runDemo} disabled={busy}>
            <FlaskConical size={14} /> Run demo
          </button>
        </div>
        {demo && !demo.ok && <DbNotice notice={{ tone: "error", title: "Demo not run", lines: [demo.message] }} onDismiss={() => setDemo(null)} />}
        {demo?.ok && (
          <div className="demo-steps">
            <p className="muted-text">
              Alert {demo.cve_id} on {demo.project_name}
            </p>
            {[
              ["Before", demo.before],
              ["Inside transaction", demo.inside],
              ["After ROLLBACK", demo.after],
            ].map(([name, s]) => (
              <div key={name} className="demo-step">
                <strong>{name}</strong>
                <span>
                  status <b>{s.status}</b>
                </span>
                <span>
                  snapshots <b>{s.snapshots}</b>
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      {explain && (
        <section className="panel table-panel">
          <div className="panel-heading">
            <div>
              <h2>Index usage (EXPLAIN)</h2>
              <p>{explain.sql}</p>
            </div>
          </div>
          <DataTable
            rows={explain.plan}
            rowKey={(r) => JSON.stringify(r)}
            columns={["table", "type", "possible_keys", "key", "rows", "Extra"].map((k) => ({ key: k, label: k, render: (r) => <span className="mono">{String(r[k] ?? "—")}</span> }))}
          />
        </section>
      )}

      {objects && (
        <>
          <section className="panel table-panel">
            <div className="panel-heading">
              <div>
                <h2>Tables</h2>
                <p>{objects.tables.length} base tables</p>
              </div>
            </div>
            <DataTable
              rows={objects.tables}
              rowKey={(r) => r.name}
              columns={[{ key: "name", label: "Table", render: (r) => <strong className="mono">{r.name}</strong> }, { key: "row_count", label: "Rows" }, usedBy]}
            />
          </section>
          <section className="panel table-panel">
            <div className="panel-heading">
              <div>
                <h2>Triggers</h2>
                <p>{objects.triggers.length} triggers</p>
              </div>
            </div>
            <DataTable
              rows={objects.triggers}
              rowKey={(r) => r.name}
              columns={[
                { key: "name", label: "Trigger", render: (r) => <strong className="mono">{r.name}</strong> },
                { key: "timing", label: "When", render: (r) => `${r.timing} ${r.event}` },
                { key: "table_name", label: "On table" },
                usedBy,
                { key: "src", label: "", render: viewSource("TRIGGER") },
              ]}
            />
          </section>
          <section className="panel table-panel">
            <div className="panel-heading">
              <div>
                <h2>Functions and procedures</h2>
                <p>{objects.routines.length} stored routines</p>
              </div>
            </div>
            <DataTable
              rows={objects.routines}
              rowKey={(r) => r.name}
              columns={[
                { key: "name", label: "Routine", render: (r) => <strong className="mono">{r.name}</strong> },
                { key: "type", label: "Type" },
                usedBy,
                { key: "src", label: "", render: viewSource("ROUTINE") },
              ]}
            />
          </section>
          <section className="panel table-panel">
            <div className="panel-heading">
              <div>
                <h2>Views</h2>
                <p>{objects.views.length} views</p>
              </div>
            </div>
            <DataTable
              rows={objects.views}
              rowKey={(r) => r.name}
              columns={[{ key: "name", label: "View", render: (r) => <strong className="mono">{r.name}</strong> }, usedBy, { key: "src", label: "", render: viewSource("VIEW") }]}
            />
          </section>
          <section className="panel table-panel">
            <div className="panel-heading">
              <div>
                <h2>Indexes</h2>
                <p>Secondary indexes (primary keys excluded)</p>
              </div>
            </div>
            <DataTable
              rows={objects.indexes}
              rowKey={(r) => `${r.table_name}.${r.name}`}
              columns={[
                { key: "table_name", label: "Table" },
                { key: "name", label: "Index", render: (r) => <span className="mono">{r.name}</span> },
                { key: "columns_list", label: "Columns", render: (r) => <span className="mono">{r.columns_list}</span> },
                { key: "non_unique", label: "Unique", render: (r) => (Number(r.non_unique) === 0 ? "yes" : "no") },
              ]}
            />
          </section>
        </>
      )}
      {source && (
        <Modal title={source.title} onClose={() => setSource(null)} wide>
          <pre className="sql-block">{source.body}</pre>
        </Modal>
      )}
    </>
  );
}
