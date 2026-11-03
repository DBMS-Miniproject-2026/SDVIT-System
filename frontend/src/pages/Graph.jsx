"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Network, RefreshCw, Search, Upload, DatabaseZap } from "lucide-react";
import api from "../services/api.js";
import { useAuth } from "../context/AuthContext.jsx";
import { apiError, fmtScore } from "../lib/format.js";
import { DataTable, ErrorState, PageHeading } from "../components/ui.jsx";

const COL_W = 230;
const ROW_H = 40;
const NODE_W = 196;
const NODE_H = 28;
const short = (text, n = 28) => (text.length > n ? `${text.slice(0, n - 1)}…` : text);

// Layered layout: column = shortest distance from the project, rows stacked in each column.
function layout(graph) {
  const project = graph.nodes.find((n) => n.type === "project");
  if (!project) return null;
  const out = new Map();
  graph.links.forEach((l) => out.set(l.source, [...(out.get(l.source) || []), l.target]));
  const depth = new Map([[project.id, 0]]);
  const queue = [project.id];
  while (queue.length) {
    const id = queue.shift();
    for (const next of out.get(id) || []) {
      if (!depth.has(next)) { depth.set(next, depth.get(id) + 1); queue.push(next); }
    }
  }
  const columns = [];
  graph.nodes.forEach((n) => {
    const d = depth.get(n.id) ?? 0;
    (columns[d] = columns[d] || []).push(n);
  });
  const pos = new Map();
  columns.forEach((col, d) => col.forEach((n, i) => pos.set(n.id, { x: 20 + d * COL_W, y: 20 + i * ROW_H })));
  const height = Math.max(...columns.map((c) => c.length)) * ROW_H + 40;
  return { pos, width: columns.length * COL_W + 20, height };
}

function GraphView({ graph }) {
  const view = useMemo(() => layout(graph), [graph]);
  if (!view) return <div className="graph-empty">No dependencies for this project in Neo4j yet. Rebuild the graph from MySQL.</div>;
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  return (
    <div className="graph-scroll">
      <svg width={view.width} height={view.height} role="img" aria-label="Dependency graph">
        {graph.links.map((l, i) => {
          const a = view.pos.get(l.source); const b = view.pos.get(l.target);
          if (!a || !b) return null;
          const x1 = a.x + NODE_W; const y1 = a.y + NODE_H / 2; const x2 = b.x; const y2 = b.y + NODE_H / 2;
          const mid = (x1 + x2) / 2;
          return <path key={i} d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`} className={`graph-edge ${l.type === "REQUIRES" ? "requires" : "depends"}`} />;
        })}
        {[...view.pos.entries()].map(([id, p]) => {
          const n = nodeById.get(id);
          const vulnerable = n.vulns.length > 0;
          return (
            <g key={id} transform={`translate(${p.x},${p.y})`}>
              <title>{n.label}{vulnerable ? ` — ${n.vulns.map((v) => v.cve).join(", ")}` : ""}</title>
              <rect width={NODE_W} height={NODE_H} rx="7" className={`graph-node ${n.type} ${vulnerable ? "vulnerable" : ""}`} />
              <text x="10" y={NODE_H / 2 + 3} className="graph-label">{short(n.label)}</text>
              {vulnerable && <text x={NODE_W - 8} y={NODE_H / 2 + 3} textAnchor="end" className="graph-badge">{n.vulns.length} CVE</text>}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export default function Graph() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [status, setStatus] = useState(null);
  const [overview, setOverview] = useState([]);
  const [critical, setCritical] = useState([]);
  const [selected, setSelected] = useState(null);
  const [exposure, setExposure] = useState([]);
  const [graph, setGraph] = useState({ nodes: [], links: [], truncated: false });
  const [cve, setCve] = useState("");
  const [blast, setBlast] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      setError("");
      const [s, o, c] = await Promise.all([api.get("/graph/status"), api.get("/graph/overview"), api.get("/graph/critical-packages")]);
      setStatus(s.data); setOverview(o.data); setCritical(c.data);
      if (!selected && o.data.length) inspect(o.data[0]);
    } catch (err) { setError(apiError(err, "Could not load the Neo4j graph. Check the Neo4j connection.")); }
  }
  async function inspect(project) {
    setSelected(project);
    try {
      const [e, g] = await Promise.all([api.get(`/graph/exposure/${project.id}`), api.get(`/graph/subgraph/${project.id}`)]);
      setExposure(e.data); setGraph(g.data);
    } catch (err) { setError(apiError(err, "Could not load the project graph.")); }
  }
  useEffect(() => { load(); }, []);

  async function runAdmin(task, success) {
    setBusy(true); setError(""); setNotice("");
    try { const { data } = await task(); setNotice(data.message || success); await load(); if (selected) await inspect(selected); }
    catch (err) { setError(err.response ? apiError(err, "Request failed.") : err.message); }
    finally { setBusy(false); }
  }
  const rebuild = () => runAdmin(() => api.post("/graph/rebuild", {}, { timeout: 120000 }));
  function importLockfile(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    runAdmin(async () => {
      const lockfile = JSON.parse(await file.text());
      return api.post("/graph/import-lockfile", { lockfile }, { timeout: 120000 });
    });
  }
  async function lookupBlast(event) {
    event.preventDefault(); setBlast(null); setError("");
    try { const { data } = await api.get(`/graph/blast-radius/${encodeURIComponent(cve.trim())}`); setBlast(data); }
    catch (err) { setError(apiError(err, "Blast-radius lookup failed.")); }
  }

  const stat = (label, value, hint) => <div key={label}><span>{label}</span><strong>{value ?? "—"}</strong><small className="muted-text">{hint}</small></div>;
  return <>
    <PageHeading eyebrow="INTELLIGENCE / GRAPH DATABASE" title="Dependency graph"
      description="Neo4j stores the dependency graph, including transitive links. MySQL remains the system of record for projects, packages, CVEs and alerts."
      action={<>
        <button className="button button-secondary" onClick={load}><RefreshCw size={15} /> Refresh</button>
        {isAdmin && <button className="button button-quiet" disabled={busy} onClick={rebuild}><DatabaseZap size={15} /> Rebuild from MySQL</button>}
        {isAdmin && <label className="button button-quiet"><Upload size={15} /> Import package-lock.json<input type="file" accept="application/json,.json" hidden disabled={busy} onChange={importLockfile} /></label>}
      </>} />
    {error && <ErrorState message={error} retry={load} />}
    {notice && <div className="notice success">{notice}</div>}
    <div className="stat-strip">
      {stat("PROJECTS", status?.projects, "Project nodes")}
      {stat("PACKAGE VERSIONS", status?.packageVersions, "From MySQL + lockfiles")}
      {stat("VULNERABILITIES", status?.vulnerabilities, "CVE nodes")}
      {stat("DEPENDS_ON", status?.dependsOn, "Project → package")}
      {stat("REQUIRES", status?.requires, "Transitive links (graph only)")}
    </div>

    <section className="panel table-panel">
      <div className="panel-heading"><div><h2>Exposure by project</h2><p>CVEs reachable through direct or transitive dependencies (variable-length traversal).</p></div><span className="panel-count">{overview.length} projects</span></div>
      <DataTable rows={overview} rowKey={(r) => r.id} emptyMessage="The graph is empty. An administrator can rebuild it from MySQL."
        columns={[
          { key: "name", label: "Project", render: (r) => <strong>{r.name}</strong> },
          { key: "vulnerabilities", label: "Reachable CVEs", render: (r) => <span className="mono">{r.vulnerabilities}</span> },
          { key: "worstCvss", label: "Worst CVSS", render: (r) => <span className="mono">{fmtScore(r.worstCvss)}</span> },
          { key: "act", label: "", render: (r) => <button className={`button button-small ${selected?.id === r.id ? "button-quiet" : "button-secondary"}`} onClick={() => inspect(r)}><Network size={12} /> Inspect</button> }
        ]} />
    </section>

    {selected && <>
      <section className="panel table-panel">
        <div className="panel-heading"><div><h2>Why is “{selected.name}” exposed?</h2><p>Shortest dependency chain from the project to each vulnerable package.</p></div><span className="panel-count">{exposure.length} findings</span></div>
        <DataTable rows={exposure} rowKey={(r) => `${r.cve}|${r.vulnerablePackage}`} emptyMessage="No vulnerable package is reachable from this project."
          columns={[
            { key: "cve", label: "CVE", render: (r) => <span className="mono cve-id">{r.cve}</span> },
            { key: "cvss", label: "CVSS", render: (r) => <span className="mono">{fmtScore(r.cvss)}</span> },
            { key: "vulnerablePackage", label: "Vulnerable package", render: (r) => <span className="mono">{r.vulnerablePackage}</span> },
            { key: "depth", label: "Reach", render: (r) => r.depth === 0 ? "Direct" : `Transitive (${r.depth} hop${r.depth > 1 ? "s" : ""})` },
            { key: "chain", label: "Chain", render: (r) => <span className="mono muted-text">{r.chain.join("  →  ")}</span> }
          ]} />
      </section>
      <section className="panel">
        <div className="panel-heading"><div><h2>Dependency graph</h2><p>Blue edges are direct dependencies; dashed edges are transitive. Red packages are affected by a CVE.</p></div>{graph.truncated && <span className="panel-count">truncated at 400 edges</span>}</div>
        <GraphView graph={graph} />
      </section>
    </>}

    <div className="content-grid">
      <section className="panel">
        <div className="panel-heading"><div><h2>CVE blast radius</h2><p>Which projects reach a CVE, and how deep.</p></div></div>
        <form className="toolbar" onSubmit={lookupBlast}>
          <div className="search-box"><Search size={16} /><input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2021-23337" /></div>
          <button className="button button-quiet" disabled={!cve.trim()}>Trace</button>
        </form>
        {blast && <DataTable rows={blast.projects} rowKey={(r) => r.projectId} emptyMessage="No project reaches this CVE."
          columns={[
            { key: "project", label: "Project", render: (r) => <strong>{r.project}</strong> },
            { key: "depth", label: "Reach", render: (r) => r.depth === 0 ? "Direct" : `${r.depth} hop${r.depth > 1 ? "s" : ""}` },
            { key: "vulnerablePackages", label: "Via", render: (r) => <span className="mono muted-text">{r.vulnerablePackages.join(", ")}</span> }
          ]} />}
      </section>
      <section className="panel">
        <div className="panel-heading"><div><h2>Most depended-on packages</h2><p>Ranked by transitive dependents.</p></div></div>
        <DataTable rows={critical} rowKey={(r) => r.package} emptyMessage="No package data yet."
          columns={[
            { key: "package", label: "Package", render: (r) => <span className="mono">{r.package}</span> },
            { key: "dependents", label: "Dependents", render: (r) => <span className="mono">{r.dependents}</span> },
            { key: "projects", label: "Projects", render: (r) => <span className="mono">{r.projects}</span> },
            { key: "vulnerabilities", label: "CVEs", render: (r) => <span className="mono">{r.vulnerabilities}</span> }
          ]} />
      </section>
    </div>
  </>;
}
