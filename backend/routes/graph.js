import { Router } from "express";
import { asyncRoute, HttpError } from "../lib/http.js";
import { requireRole } from "../lib/auth.js";
import pool from "../config/db.js";
import { readQuery, writeTx } from "../graph/client.js";
import { parseLockfile, parsePackageKey } from "../lib/lockfile.js";

// Neo4j holds the dependency GRAPH. MySQL stays the system of record:
//   (:Project)-[:DEPENDS_ON]->(:PackageVersion)   copied from project_dependencies
//   (:Vulnerability)-[:AFFECTS]->(:PackageVersion) copied from vuln_affected_versions
//   (:PackageVersion)-[:REQUIRES]->(:PackageVersion) transitive links, stored ONLY here
// Variable-length bounds cannot be parameterised in Cypher, so the depth cap is a constant.
const router = Router();
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
const ID_PATTERN = /^[0-9a-fA-F-]{36}$/;
const BATCH = 500;

const projectIdParam = (value) => {
  if (!ID_PATTERN.test(String(value))) throw new HttpError(400, "Invalid project id.");
  return String(value);
};

const chunks = (items, size = BATCH) => {
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
};

router.get("/status", asyncRoute(async (_req, res) => {
  const [row] = await readQuery(`
    RETURN COUNT { (:Project) } AS projects,
           COUNT { (:PackageVersion) } AS packageVersions,
           COUNT { (:Vulnerability) } AS vulnerabilities,
           COUNT { ()-[:DEPENDS_ON]->() } AS dependsOn,
           COUNT { ()-[:REQUIRES]->() } AS requires,
           COUNT { ()-[:AFFECTS]->() } AS affects`);
  res.json(row);
}));

// Per-project exposure: distinct CVEs reachable through direct OR transitive dependencies.
router.get("/overview", asyncRoute(async (_req, res) => {
  const rows = await readQuery(`
    MATCH (p:Project)
    CALL {
      WITH p
      OPTIONAL MATCH (p)-[:DEPENDS_ON]->(:PackageVersion)-[:REQUIRES*0..10]->(:PackageVersion)<-[:AFFECTS]-(v:Vulnerability)
      RETURN count(DISTINCT v) AS vulnerabilities, max(v.cvss_score) AS worstCvss
    }
    RETURN p.id AS id, p.name AS name, vulnerabilities, worstCvss
    ORDER BY vulnerabilities DESC, name`);
  res.json(rows);
}));

// Why is this project exposed? One row per (CVE, vulnerable package) with the SHORTEST chain.
router.get("/exposure/:projectId", asyncRoute(async (req, res) => {
  const projectId = projectIdParam(req.params.projectId);
  const rows = await readQuery(`
    MATCH path = (p:Project {id: $projectId})-[:DEPENDS_ON]->(:PackageVersion)-[:REQUIRES*0..10]->(pv:PackageVersion)<-[:AFFECTS]-(v:Vulnerability)
    WITH v, pv, path, length(path) - 1 AS depth
    ORDER BY depth
    WITH v, pv, head(collect(path)) AS best
    RETURN v.cve_id AS cve, v.cvss_score AS cvss, pv.key AS vulnerablePackage,
           length(best) - 1 AS depth,
           [n IN tail(nodes(best)) | n.key] AS chain
    ORDER BY coalesce(cvss, -1.0) DESC, depth ASC
    LIMIT 200`, { projectId });
  res.json(rows);
}));

// Blast radius of one CVE: every project that reaches an affected package, and how deep.
router.get("/blast-radius/:cve", asyncRoute(async (req, res) => {
  const cve = String(req.params.cve).trim().toUpperCase();
  if (!CVE_PATTERN.test(cve)) throw new HttpError(400, "CVE ID must look like CVE-2024-12345.");
  const [found] = await readQuery("MATCH (v:Vulnerability {cve_id: $cve}) RETURN v.cve_id AS cve, v.cvss_score AS cvss", { cve });
  if (!found) throw new HttpError(404, "That CVE is not in the graph. Rebuild the graph from MySQL first.");
  const projects = await readQuery(`
    MATCH (v:Vulnerability {cve_id: $cve})-[:AFFECTS]->(pv:PackageVersion)
    MATCH path = (p:Project)-[:DEPENDS_ON]->(:PackageVersion)-[:REQUIRES*0..10]->(pv)
    WITH p, pv, min(length(path) - 1) AS depth
    RETURN p.id AS projectId, p.name AS project, min(depth) AS depth, collect(DISTINCT pv.key) AS vulnerablePackages
    ORDER BY depth, project`, { cve });
  res.json({ cve: found.cve, cvss: found.cvss, projectCount: projects.length, projects });
}));

// Packages that the most other packages (transitively) depend on.
router.get("/critical-packages", asyncRoute(async (_req, res) => {
  const rows = await readQuery(`
    MATCH (pv:PackageVersion)
    CALL { WITH pv MATCH (d:PackageVersion)-[:REQUIRES*1..10]->(pv) RETURN count(DISTINCT d) AS dependents }
    CALL { WITH pv MATCH (p:Project)-[:DEPENDS_ON]->(:PackageVersion)-[:REQUIRES*0..10]->(pv) RETURN count(DISTINCT p) AS projects }
    RETURN pv.key AS package, dependents, projects,
           COUNT { (:Vulnerability)-[:AFFECTS]->(pv) } AS vulnerabilities
    ORDER BY dependents DESC, projects DESC, package
    LIMIT 10`);
  res.json(rows);
}));

// Nodes + links for the dependency graph picture (up to 6 hops below a direct dependency).
router.get("/subgraph/:projectId", asyncRoute(async (req, res) => {
  const projectId = projectIdParam(req.params.projectId);
  const edges = await readQuery(`
    MATCH path = (:Project {id: $projectId})-[:DEPENDS_ON]->(:PackageVersion)-[:REQUIRES*0..6]->(:PackageVersion)
    UNWIND relationships(path) AS r
    WITH DISTINCT r, startNode(r) AS a, endNode(r) AS b
    RETURN CASE WHEN a:Project THEN 'project:' + a.id ELSE a.key END AS aId,
           CASE WHEN a:Project THEN 'project' ELSE 'package' END AS aType,
           CASE WHEN a:Project THEN a.name ELSE a.name + '@' + a.version END AS aLabel,
           b.key AS bId, 'package' AS bType, b.name + '@' + b.version AS bLabel, type(r) AS rel
    LIMIT 400`, { projectId });

  const nodes = new Map();
  const links = [];
  for (const e of edges) {
    nodes.set(e.aId, { id: e.aId, type: e.aType, label: e.aLabel, vulns: [] });
    nodes.set(e.bId, { id: e.bId, type: e.bType, label: e.bLabel, vulns: [] });
    links.push({ source: e.aId, target: e.bId, type: e.rel });
  }
  const keys = [...nodes.keys()].filter((k) => !k.startsWith("project:"));
  if (keys.length) {
    const vulns = await readQuery(`
      MATCH (v:Vulnerability)-[:AFFECTS]->(pv:PackageVersion) WHERE pv.key IN $keys
      RETURN pv.key AS packageKey, v.cve_id AS cve, v.cvss_score AS cvss`, { keys });
    for (const v of vulns) nodes.get(v.packageKey)?.vulns.push({ cve: v.cve, cvss: v.cvss });
  }
  res.json({ nodes: [...nodes.values()], links, truncated: edges.length >= 400 });
}));

// Admin: copy relational facts from MySQL into the graph in ONE transaction.
// Transitive REQUIRES edges (graph-only data) are preserved.
router.post("/rebuild", requireRole("admin"), asyncRoute(async (_req, res) => {
  const [[projects], [versions], [deps], [vulns], [affects]] = await Promise.all([
    pool.query("SELECT id, name FROM projects"),
    pool.query("SELECT pv.id, pv.version, p.name, p.ecosystem FROM package_versions pv JOIN packages p ON p.id = pv.package_id"),
    pool.query("SELECT project_id, package_version_id, dependency_type FROM project_dependencies"),
    pool.query("SELECT id, cve_id, cvss_score FROM vulnerabilities"),
    pool.query("SELECT vulnerability_id, package_version_id FROM vuln_affected_versions")
  ]);
  const versionRows = versions.map((v) => ({ id: v.id, name: v.name, ecosystem: v.ecosystem, version: v.version, key: `${v.ecosystem}:${v.name}@${v.version}` }));

  await writeTx(async (tx) => {
    // 1) MySQL-derived edges are recreated from scratch; REQUIRES edges are left alone.
    await tx.run("MATCH ()-[r:DEPENDS_ON|AFFECTS]->() DELETE r");
    // 2) Remove nodes whose MySQL row no longer exists (graph-only package versions have no id and are kept).
    await tx.run("MATCH (n:Project) WHERE NOT n.id IN $ids DETACH DELETE n", { ids: projects.map((r) => r.id) });
    await tx.run("MATCH (n:Vulnerability) WHERE NOT n.id IN $ids DETACH DELETE n", { ids: vulns.map((r) => r.id) });
    await tx.run("MATCH (n:PackageVersion) WHERE n.id IS NOT NULL AND NOT n.id IN $ids DETACH DELETE n", { ids: versionRows.map((r) => r.id) });
    // 3) Upsert nodes.
    for (const rows of chunks(projects)) await tx.run("UNWIND $rows AS row MERGE (n:Project {id: row.id}) SET n.name = row.name", { rows });
    for (const rows of chunks(versionRows)) {
      await tx.run(`UNWIND $rows AS row MERGE (n:PackageVersion {key: row.key})
                    SET n.id = row.id, n.name = row.name, n.ecosystem = row.ecosystem, n.version = row.version`, { rows });
    }
    for (const rows of chunks(vulns)) {
      await tx.run("UNWIND $rows AS row MERGE (n:Vulnerability {id: row.id}) SET n.cve_id = row.cve_id, n.cvss_score = row.cvss_score", { rows });
    }
    // 4) Recreate edges.
    for (const rows of chunks(deps)) {
      await tx.run(`UNWIND $rows AS row
                    MATCH (p:Project {id: row.project_id}) MATCH (pv:PackageVersion {id: row.package_version_id})
                    MERGE (p)-[r:DEPENDS_ON]->(pv) SET r.type = row.dependency_type`, { rows });
    }
    for (const rows of chunks(affects)) {
      await tx.run(`UNWIND $rows AS row
                    MATCH (v:Vulnerability {id: row.vulnerability_id}) MATCH (pv:PackageVersion {id: row.package_version_id})
                    MERGE (v)-[:AFFECTS]->(pv)`, { rows });
    }
  });
  res.json({
    message: "Graph rebuilt from MySQL.",
    projects: projects.length, packageVersions: versionRows.length, vulnerabilities: vulns.length,
    dependsOn: deps.length, affects: affects.length
  });
}));

// Admin: load transitive "A requires B" links from an npm package-lock.json (v2/v3).
router.post("/import-lockfile", requireRole("admin"), asyncRoute(async (req, res) => {
  const { nodes, edges } = parseLockfile(req.body?.lockfile);
  await writeTx(async (tx) => {
    for (const rows of chunks(nodes)) {
      await tx.run(`UNWIND $rows AS row MERGE (n:PackageVersion {key: row.key})
                    ON CREATE SET n.name = row.name, n.ecosystem = row.ecosystem, n.version = row.version`, { rows });
    }
    for (const rows of chunks(edges)) {
      await tx.run(`UNWIND $rows AS row
                    MATCH (a:PackageVersion {key: row.from}) MATCH (b:PackageVersion {key: row.to})
                    MERGE (a)-[:REQUIRES]->(b)`, { rows });
    }
  });
  const [{ linked }] = await readQuery("MATCH (n:PackageVersion) WHERE n.id IS NOT NULL AND n.key IN $keys RETURN count(n) AS linked", { keys: nodes.map((n) => n.key) });
  res.json({
    message: "Lockfile imported into Neo4j.",
    packageVersions: nodes.length, requiresEdges: edges.length, matchedMysqlPackageVersions: linked
  });
}));

// Admin: add one transitive link by hand, e.g. {"from":"npm:express@4.17.1","to":"npm:qs@6.7.0"}.
router.post("/requires", requireRole("admin"), asyncRoute(async (req, res) => {
  const from = parsePackageKey(req.body?.from);
  const to = parsePackageKey(req.body?.to);
  if (!from || !to) throw new HttpError(400, "Use package keys like npm:express@4.17.1.");
  if (from.key === to.key) throw new HttpError(400, "A package version cannot require itself.");
  await writeTx((tx) => tx.run(`
    MERGE (a:PackageVersion {key: $from.key}) ON CREATE SET a.name = $from.name, a.ecosystem = $from.ecosystem, a.version = $from.version
    MERGE (b:PackageVersion {key: $to.key})   ON CREATE SET b.name = $to.name,   b.ecosystem = $to.ecosystem,   b.version = $to.version
    MERGE (a)-[:REQUIRES]->(b)`, { from, to }));
  res.status(201).json({ message: `${from.key} now requires ${to.key}.` });
}));

export default router;
