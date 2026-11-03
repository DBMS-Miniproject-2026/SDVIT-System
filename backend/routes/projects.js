import { Router } from "express";
import { randomUUID } from "node:crypto";
import pool from "../config/db.js";
import { asyncRoute, HttpError, requireFields } from "../lib/http.js";
import { requireRole } from "../lib/auth.js";

const router = Router();
const DEP_TYPES = ["direct", "dev", "transitive"];

// vulnerability_ids (+ details) of every alert a project currently has
async function projectAlerts(conn, projectId) {
  const [rows] = await conn.query(
    `SELECT a.vulnerability_id, v.cve_id, v.cvss_score,
            get_vulnerability_severity(v.cvss_score) AS severity
     FROM alerts a JOIN vulnerabilities v ON v.id = a.vulnerability_id
     WHERE a.project_id = ?`,
    [projectId]
  );
  return rows;
}

// List: VIEW project_risk_overview + FUNCTION get_open_alert_count()
router.get("/", asyncRoute(async (_req, res) => {
  const [rows] = await pool.query(`
    SELECT p.id, p.name, p.description, p.repo_url, p.created_at,
           u.name AS owner_name,
           r.open_vulnerability_count, r.max_cvss_score, r.avg_cvss_score,
           get_open_alert_count(p.id) AS open_alert_count,
           (SELECT rs.score FROM risk_snapshots rs
             WHERE rs.project_id = p.id ORDER BY rs.computed_at DESC LIMIT 1) AS latest_risk_score,
           (SELECT COUNT(*) FROM project_dependencies pd WHERE pd.project_id = p.id) AS dependency_count
    FROM projects p
    JOIN users u ON u.id = p.owner_id
    LEFT JOIN project_risk_overview r ON r.project_id = p.id
    ORDER BY p.created_at DESC, p.name
  `);
  res.json(rows);
}));

// Detail: dependencies, VIEW project_vulnerability_details, PROCEDURE
// get_project_vulnerability_report(), and risk_snapshots history
router.get("/:id", asyncRoute(async (req, res) => {
  const { id } = req.params;
  const [[project]] = await pool.query(
    `SELECT p.id, p.name, p.description, p.repo_url, p.created_at, u.name AS owner_name,
            r.open_vulnerability_count, r.max_cvss_score, r.avg_cvss_score,
            get_open_alert_count(p.id) AS open_alert_count
     FROM projects p
     JOIN users u ON u.id = p.owner_id
     LEFT JOIN project_risk_overview r ON r.project_id = p.id
     WHERE p.id = ?`,
    [id]
  );
  if (!project) throw new HttpError(404, "Project not found.");

  const [dependencies] = await pool.query(
    `SELECT pd.id, pd.dependency_type, pd.added_at,
            pkg.name AS package_name, pkg.ecosystem,
            pv.id AS package_version_id, pv.version,
            (SELECT COUNT(*) FROM vuln_affected_versions vav
              WHERE vav.package_version_id = pv.id) AS known_cve_count
     FROM project_dependencies pd
     JOIN package_versions pv ON pv.id = pd.package_version_id
     JOIN packages pkg ON pkg.id = pv.package_id
     WHERE pd.project_id = ?
     ORDER BY pkg.name, pv.version`,
    [id]
  );

  const [findings] = await pool.query(
    `SELECT package_name, ecosystem, package_version, cve_id, description,
            cvss_score, severity, alert_status, alert_created_at
     FROM project_vulnerability_details
     WHERE project_id = ?
     ORDER BY cvss_score DESC, package_name`,
    [id]
  );

  const [reportSets] = await pool.query("CALL get_project_vulnerability_report(?)", [id]);
  const report = reportSets[0];

  const [history] = await pool.query(
    `SELECT id, score, computed_at FROM risk_snapshots
     WHERE project_id = ? ORDER BY computed_at ASC`,
    [id]
  );

  res.json({ project, dependencies, findings, report, history });
}));

// INSERT into projects
router.post("/", asyncRoute(async (req, res) => {
  requireFields(req.body, ["name", "owner_id"]);
  const { name, owner_id, repo_url, description } = req.body;
  const id = randomUUID();
  await pool.query(
    "INSERT INTO projects (id, owner_id, name, repo_url, description) VALUES (?, ?, ?, ?, ?)",
    [id, owner_id, String(name).trim(), repo_url?.trim() || null, description?.trim() || null]
  );
  res.status(201).json({ id, message: "Project created." });
}));

// DELETE with ON DELETE CASCADE (dependencies, alerts and risk_snapshots go with it)
router.delete("/:id", requireRole("admin"), asyncRoute(async (req, res) => {
  const { id } = req.params;
  const [[removed]] = await pool.query(
    `SELECT (SELECT COUNT(*) FROM project_dependencies WHERE project_id = ?) AS dependencies,
            (SELECT COUNT(*) FROM alerts WHERE project_id = ?) AS alerts,
            (SELECT COUNT(*) FROM risk_snapshots WHERE project_id = ?) AS risk_snapshots`,
    [id, id, id]
  );
  const [result] = await pool.query("DELETE FROM projects WHERE id = ?", [id]);
  if (result.affectedRows === 0) throw new HttpError(404, "Project not found.");
  res.json({ message: "Project deleted.", cascaded: removed });
}));

// INSERT into project_dependencies -> fires trigger trg_alert_on_new_dependency
router.post("/:id/dependencies", asyncRoute(async (req, res) => {
  requireFields(req.body, ["package_version_id"]);
  const projectId = req.params.id;
  const dependencyType = req.body.dependency_type || "direct";
  if (!DEP_TYPES.includes(dependencyType)) throw new HttpError(400, "Invalid dependency type.");

  const conn = await pool.getConnection();
  try {
    const before = new Set((await projectAlerts(conn, projectId)).map((a) => a.vulnerability_id));
    await conn.query(
      `INSERT INTO project_dependencies (id, project_id, package_version_id, dependency_type)
       VALUES (?, ?, ?, ?)`,
      [randomUUID(), projectId, req.body.package_version_id, dependencyType]
    );
    const after = await projectAlerts(conn, projectId);
    const alertsCreated = after.filter((a) => !before.has(a.vulnerability_id));
    res.status(201).json({
      message: "Dependency added.",
      trigger: "trg_alert_on_new_dependency",
      alertsCreated
    });
  } finally {
    conn.release();
  }
}));

router.delete("/:id/dependencies/:dependencyId", asyncRoute(async (req, res) => {
  const [result] = await pool.query(
    "DELETE FROM project_dependencies WHERE id = ? AND project_id = ?",
    [req.params.dependencyId, req.params.id]
  );
  if (result.affectedRows === 0) throw new HttpError(404, "Dependency not found.");
  res.json({ message: "Dependency removed." });
}));

export default router;
