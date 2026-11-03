import { Router } from "express";
import { randomUUID } from "node:crypto";
import pool from "../config/db.js";
import { asyncRoute, HttpError, requireFields } from "../lib/http.js";
import { requireRole } from "../lib/auth.js";

const router = Router();
const TRIGGER_THRESHOLD = 7.0; // must match trg_alert_on_new_vuln_affected_version

async function alertedProjects(conn, vulnerabilityId) {
  const [rows] = await conn.query(
    `SELECT a.project_id, p.name AS project_name, a.status
     FROM alerts a JOIN projects p ON p.id = a.project_id
     WHERE a.vulnerability_id = ?`,
    [vulnerabilityId]
  );
  return rows;
}

// FUNCTION get_vulnerability_severity() classifies each CVE
router.get("/", asyncRoute(async (_req, res) => {
  const [rows] = await pool.query(`
    SELECT v.id, v.cve_id, v.description, v.cvss_score, v.published_date,
           get_vulnerability_severity(v.cvss_score) AS severity,
           COUNT(DISTINCT vav.package_version_id) AS affected_version_count,
           (SELECT COUNT(*) FROM alerts a WHERE a.vulnerability_id = v.id) AS alert_count
    FROM vulnerabilities v
    LEFT JOIN vuln_affected_versions vav ON vav.vulnerability_id = v.id
    GROUP BY v.id, v.cve_id, v.description, v.cvss_score, v.published_date
    ORDER BY v.cvss_score DESC, v.published_date DESC
  `);
  res.json(rows);
}));

router.get("/:id", asyncRoute(async (req, res) => {
  const { id } = req.params;
  const [[vulnerability]] = await pool.query(
    `SELECT v.id, v.cve_id, v.description, v.cvss_score, v.published_date,
            get_vulnerability_severity(v.cvss_score) AS severity
     FROM vulnerabilities v WHERE v.id = ?`,
    [id]
  );
  if (!vulnerability) throw new HttpError(404, "Vulnerability not found.");

  const [affected] = await pool.query(
    `SELECT vav.id, vav.version_range, pv.id AS package_version_id, pv.version,
            pkg.name AS package_name, pkg.ecosystem
     FROM vuln_affected_versions vav
     JOIN package_versions pv ON pv.id = vav.package_version_id
     JOIN packages pkg ON pkg.id = pv.package_id
     WHERE vav.vulnerability_id = ?
     ORDER BY pkg.name, pv.version`,
    [id]
  );
  const alerts = await alertedProjects(pool, id);
  res.json({ vulnerability, affected, alerts });
}));

// INSERT vulnerability + vuln_affected_versions in one transaction. Each affected
// version row fires trg_alert_on_new_vuln_affected_version (alerts for CVSS >= 7.0).
router.post("/", requireRole("admin"), asyncRoute(async (req, res) => {
  requireFields(req.body, ["cve_id", "description", "cvss_score", "published_date"]);
  const cveId = String(req.body.cve_id).trim().toUpperCase();
  const score = Number(req.body.cvss_score);
  const affected = Array.isArray(req.body.affected) ? req.body.affected : [];

  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) throw new HttpError(400, "CVE id must look like CVE-2024-12345.");
  if (!Number.isFinite(score) || score < 0 || score > 10) throw new HttpError(400, "CVSS score must be between 0 and 10.");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(req.body.published_date)) throw new HttpError(400, "Published date must be YYYY-MM-DD.");

  const id = randomUUID();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query(
      `INSERT INTO vulnerabilities (id, cve_id, description, cvss_score, published_date)
       VALUES (?, ?, ?, ?, ?)`,
      [id, cveId, String(req.body.description).trim(), score, req.body.published_date]
    );
    for (const a of affected) {
      if (!a.package_version_id) continue;
      await conn.query(
        `INSERT INTO vuln_affected_versions (id, vulnerability_id, package_version_id, version_range)
         VALUES (?, ?, ?, ?)`,
        [randomUUID(), id, a.package_version_id, a.version_range?.trim() || null]
      );
    }
    await conn.commit();
    const alertsCreated = await alertedProjects(conn, id);
    res.status(201).json({
      id,
      message: "Vulnerability recorded.",
      trigger: "trg_alert_on_new_vuln_affected_version",
      belowThreshold: score < TRIGGER_THRESHOLD,
      alertsCreated
    });
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}));

// Link an existing CVE to one more package version -> fires the same trigger
router.post("/:id/affected-versions", requireRole("admin"), asyncRoute(async (req, res) => {
  requireFields(req.body, ["package_version_id"]);
  const { id } = req.params;
  const [[vulnerability]] = await pool.query("SELECT cvss_score FROM vulnerabilities WHERE id = ?", [id]);
  if (!vulnerability) throw new HttpError(404, "Vulnerability not found.");

  const conn = await pool.getConnection();
  try {
    const before = new Set((await alertedProjects(conn, id)).map((a) => a.project_id));
    await conn.query(
      `INSERT INTO vuln_affected_versions (id, vulnerability_id, package_version_id, version_range)
       VALUES (?, ?, ?, ?)`,
      [randomUUID(), id, req.body.package_version_id, req.body.version_range?.trim() || null]
    );
    const after = await alertedProjects(conn, id);
    res.status(201).json({
      message: "Affected version linked.",
      trigger: "trg_alert_on_new_vuln_affected_version",
      belowThreshold: Number(vulnerability.cvss_score) < TRIGGER_THRESHOLD,
      alertsCreated: after.filter((a) => !before.has(a.project_id))
    });
  } finally {
    conn.release();
  }
}));

export default router;
