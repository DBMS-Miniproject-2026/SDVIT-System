import { Router } from "express";
import pool from "../config/db.js";
import { asyncRoute, HttpError } from "../lib/http.js";

const router = Router();

// Where each database object is exercised in the web app (shown on the Database page)
const USED_BY = {
  users: "Owner dropdown when creating a project",
  projects: "Projects page: create, view, delete",
  packages: "Packages page: add package, delete (cascade)",
  package_versions: "Packages page and dependency / CVE pickers",
  project_dependencies: "Project page: add or remove a dependency",
  vulnerabilities: "Vulnerabilities page: record a CVE",
  vuln_affected_versions: "Vulnerabilities page: affected versions of a CVE",
  alerts: "Alert center and dashboard",
  risk_snapshots: "Risk history chart on the project page",
  trg_alert_on_new_vuln_affected_version: "Fires when a CVE is linked to a package version (Vulnerabilities page)",
  trg_alert_on_new_dependency: "Fires when a project adds a dependency (Project page)",
  trg_risk_snapshot_on_alert_resolved: "Fires when an alert is resolved (Alert center)",
  get_vulnerability_severity: "Severity labels on every page that shows a CVE",
  get_open_alert_count: "Open-alert counts on Projects and Dashboard",
  recompute_project_risk: "Recompute risk button on the project page",
  recompute_all_project_risk: "Recompute all risk button on the Dashboard (cursor loop)",
  get_project_vulnerability_report: "Report tab on the project page",
  resolve_alert: "Resolve button in the Alert center (transaction + SIGNAL)",
  acknowledge_alert: "Acknowledge button in the Alert center",
  project_risk_overview: "Dashboard and Projects page risk columns",
  project_vulnerability_details: "Findings tab on the project page"
};

router.get("/objects", asyncRoute(async (_req, res) => {
  const [tableNames] = await pool.query(
    `SELECT TABLE_NAME AS name FROM information_schema.TABLES
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
     ORDER BY TABLE_NAME`
  );
  const tables = [];
  for (const { name } of tableNames) {
    // names come from information_schema, not from the client
    const [[row]] = await pool.query(`SELECT COUNT(*) AS row_count FROM \`${name}\``);
    tables.push({ name, row_count: row.row_count, usedBy: USED_BY[name] || null });
  }

  const [triggers] = await pool.query(
    `SELECT TRIGGER_NAME AS name, EVENT_MANIPULATION AS event, EVENT_OBJECT_TABLE AS table_name,
            ACTION_TIMING AS timing, ACTION_STATEMENT AS definition
     FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() ORDER BY TRIGGER_NAME`
  );
  const [routines] = await pool.query(
    `SELECT ROUTINE_NAME AS name, ROUTINE_TYPE AS type, ROUTINE_DEFINITION AS definition
     FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE()
     ORDER BY ROUTINE_TYPE, ROUTINE_NAME`
  );
  const [views] = await pool.query(
    `SELECT TABLE_NAME AS name, VIEW_DEFINITION AS definition
     FROM information_schema.VIEWS WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME`
  );
  const [indexes] = await pool.query(
    `SELECT TABLE_NAME AS table_name, INDEX_NAME AS name,
            CAST(GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS CHAR) AS columns_list,
            NON_UNIQUE AS non_unique
     FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND INDEX_NAME <> 'PRIMARY'
     GROUP BY TABLE_NAME, INDEX_NAME, NON_UNIQUE
     ORDER BY TABLE_NAME, INDEX_NAME`
  );

  const tag = (rows) => rows.map((r) => ({ ...r, usedBy: USED_BY[r.name] || null }));
  res.json({
    tables,
    triggers: tag(triggers),
    routines: tag(routines),
    views: tag(views),
    indexes
  });
}));

// EXPLAIN: shows the optimizer using idx_alerts_status
router.get("/explain", asyncRoute(async (_req, res) => {
  const sql = "SELECT * FROM alerts WHERE status = 'open'";
  const [plan] = await pool.query(`EXPLAIN ${sql}`);
  res.json({ sql, plan });
}));

// Atomicity demo: resolve an alert inside a transaction (the trigger writes a risk
// snapshot too), look at the result, then ROLLBACK and show that both changes vanish.
router.post("/rollback-demo", asyncRoute(async (_req, res) => {
  const [[target]] = await pool.query(
    `SELECT a.project_id, a.vulnerability_id, v.cve_id, p.name AS project_name
     FROM alerts a
     JOIN vulnerabilities v ON v.id = a.vulnerability_id
     JOIN projects p ON p.id = a.project_id
     WHERE a.status = 'open'
     ORDER BY v.cvss_score DESC LIMIT 1`
  );
  if (!target) throw new HttpError(409, "There is no open alert to use for the demo.");

  const conn = await pool.getConnection();
  const look = async () => {
    const [[row]] = await conn.query(
      `SELECT a.status,
              (SELECT COUNT(*) FROM risk_snapshots rs WHERE rs.project_id = a.project_id) AS snapshots
       FROM alerts a WHERE a.project_id = ? AND a.vulnerability_id = ?`,
      [target.project_id, target.vulnerability_id]
    );
    return row;
  };
  try {
    const before = await look();
    await conn.beginTransaction();
    await conn.query(
      "UPDATE alerts SET status = 'resolved' WHERE project_id = ? AND vulnerability_id = ?",
      [target.project_id, target.vulnerability_id]
    );
    const inside = await look();
    await conn.rollback();
    const after = await look();
    res.json({ cve_id: target.cve_id, project_name: target.project_name, before, inside, after });
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}));

export default router;
