import { Router } from "express";
import pool from "../config/db.js";
import { asyncRoute } from "../lib/http.js";

const router = Router();

// Each entry is a query from the project's SQL demo (Part F), run live.
// The SQL text is returned too so the UI can show it next to the result.
const QUERIES = [
  {
    key: "blast-radius",
    title: "Blast radius per vulnerable package version",
    concept: "JOIN + GROUP BY + COUNT DISTINCT + MAX",
    sql: `SELECT pkg.name AS package, pv.version,
       COUNT(DISTINCT pd.project_id) AS projects_using,
       COUNT(DISTINCT vav.vulnerability_id) AS cves,
       MAX(v.cvss_score) AS worst_cvss
FROM package_versions pv
JOIN packages pkg ON pkg.id = pv.package_id
JOIN vuln_affected_versions vav ON vav.package_version_id = pv.id
JOIN vulnerabilities v ON v.id = vav.vulnerability_id
LEFT JOIN project_dependencies pd ON pd.package_version_id = pv.id
GROUP BY pv.id, pkg.name, pv.version
ORDER BY worst_cvss DESC, projects_using DESC`
  },
  {
    key: "ecosystem-stats",
    title: "CVE statistics per ecosystem",
    concept: "Aggregates: COUNT, AVG, MIN, MAX",
    sql: `SELECT pkg.ecosystem,
       COUNT(DISTINCT v.id) AS cve_count,
       ROUND(AVG(v.cvss_score), 2) AS avg_cvss,
       MIN(v.cvss_score) AS min_cvss,
       MAX(v.cvss_score) AS max_cvss
FROM packages pkg
JOIN package_versions pv ON pv.package_id = pkg.id
JOIN vuln_affected_versions vav ON vav.package_version_id = pv.id
JOIN vulnerabilities v ON v.id = vav.vulnerability_id
GROUP BY pkg.ecosystem
ORDER BY avg_cvss DESC`
  },
  {
    key: "open-high-alerts",
    title: "Projects with open high-severity alerts",
    concept: "GROUP BY + HAVING",
    sql: `SELECT p.name AS project, COUNT(a.id) AS open_high_alerts
FROM projects p
JOIN alerts a ON a.project_id = p.id
JOIN vulnerabilities v ON v.id = a.vulnerability_id
WHERE a.status = 'open' AND v.cvss_score >= 7.0
GROUP BY p.name
HAVING COUNT(a.id) >= 1
ORDER BY open_high_alerts DESC`
  },
  {
    key: "dependency-counts",
    title: "Dependencies per project (including projects with none)",
    concept: "LEFT JOIN",
    sql: `SELECT p.name AS project, COUNT(pd.id) AS dependency_count
FROM projects p
LEFT JOIN project_dependencies pd ON pd.project_id = p.id
GROUP BY p.id, p.name
ORDER BY p.name`
  },
  {
    key: "severity-buckets",
    title: "CVEs grouped into severity buckets",
    concept: "UNION ALL",
    sql: `SELECT cve_id, cvss_score, 'Critical' AS bucket
FROM vulnerabilities WHERE cvss_score >= 9.0
UNION ALL
SELECT cve_id, cvss_score, 'High'
FROM vulnerabilities WHERE cvss_score >= 7.0 AND cvss_score < 9.0
UNION ALL
SELECT cve_id, cvss_score, 'Medium'
FROM vulnerabilities WHERE cvss_score >= 4.0 AND cvss_score < 7.0
UNION ALL
SELECT cve_id, cvss_score, 'Low'
FROM vulnerabilities WHERE cvss_score < 4.0
ORDER BY cvss_score DESC`
  },
  {
    key: "above-average",
    title: "CVEs scoring above the average CVSS",
    concept: "Nested (scalar) subquery",
    sql: `SELECT cve_id, cvss_score
FROM vulnerabilities
WHERE cvss_score > (SELECT AVG(cvss_score) FROM vulnerabilities)
ORDER BY cvss_score DESC`
  },
  {
    key: "clean-versions",
    title: "Package versions with no known CVE",
    concept: "NOT EXISTS (correlated subquery)",
    sql: `SELECT pkg.name AS package, pv.version
FROM package_versions pv
JOIN packages pkg ON pkg.id = pv.package_id
WHERE NOT EXISTS (SELECT 1 FROM vuln_affected_versions vav
                  WHERE vav.package_version_id = pv.id)
ORDER BY pkg.name, pv.version`
  }
];

router.get("/", asyncRoute(async (_req, res) => {
  const results = [];
  for (const q of QUERIES) {
    const [rows] = await pool.query(q.sql);
    results.push({ key: q.key, title: q.title, concept: q.concept, sql: q.sql, rows });
  }
  res.json(results);
}));

export default router;
