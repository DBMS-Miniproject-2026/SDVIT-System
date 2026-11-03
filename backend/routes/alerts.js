import { Router } from "express";
import pool from "../config/db.js";
import { asyncRoute, HttpError } from "../lib/http.js";
import { requireRole } from "../lib/auth.js";

const router = Router();
const STATUSES = new Set(["open", "acknowledged", "resolved"]);

router.get("/", asyncRoute(async (req, res) => {
  const status = String(req.query.status || "").toLowerCase();
  const projectId = String(req.query.project_id || "");
  if (status && !STATUSES.has(status)) throw new HttpError(400, "Invalid status filter.");

  const where = [];
  const params = [];
  if (status) { where.push("a.status = ?"); params.push(status); }
  if (projectId) { where.push("a.project_id = ?"); params.push(projectId); }

  // FUNCTION get_vulnerability_severity(); the status filter uses idx_alerts_status
  const [rows] = await pool.query(
    `SELECT a.id, a.project_id, p.name AS project_name,
            a.vulnerability_id, v.cve_id, v.description, v.cvss_score,
            get_vulnerability_severity(v.cvss_score) AS severity,
            a.status, a.created_at
     FROM alerts a
     JOIN projects p ON p.id = a.project_id
     JOIN vulnerabilities v ON v.id = a.vulnerability_id
     ${where.length ? "WHERE " + where.join(" AND ") : ""}
     ORDER BY FIELD(a.status, 'open', 'acknowledged', 'resolved'), v.cvss_score DESC, a.created_at DESC`,
    params
  );
  res.json(rows);
}));

async function latestSnapshot(projectId) {
  const [[row]] = await pool.query(
    `SELECT score, computed_at FROM risk_snapshots
     WHERE project_id = ? ORDER BY computed_at DESC LIMIT 1`,
    [projectId]
  );
  return row || null;
}

// PROCEDURE resolve_alert (transaction + error handling). Its UPDATE fires
// trg_risk_snapshot_on_alert_resolved, which writes a new risk snapshot.
router.patch("/:projectId/:vulnerabilityId/resolve", requireRole("admin"), asyncRoute(async (req, res) => {
  const { projectId, vulnerabilityId } = req.params;
  await pool.query("CALL resolve_alert(?, ?)", [projectId, vulnerabilityId]);
  res.json({
    message: "Alert resolved.",
    procedure: "resolve_alert",
    trigger: "trg_risk_snapshot_on_alert_resolved",
    riskSnapshot: await latestSnapshot(projectId)
  });
}));

// PROCEDURE acknowledge_alert (see SDVIT_REVIEW3_APP_EXTENSIONS.sql)
router.patch("/:projectId/:vulnerabilityId/acknowledge", asyncRoute(async (req, res) => {
  const { projectId, vulnerabilityId } = req.params;
  await pool.query("CALL acknowledge_alert(?, ?)", [projectId, vulnerabilityId]);
  res.json({ message: "Alert acknowledged.", procedure: "acknowledge_alert" });
}));

export default router;
