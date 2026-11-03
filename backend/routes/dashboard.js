import { Router } from "express";
import pool from "../config/db.js";
import { asyncRoute } from "../lib/http.js";

const router = Router();

router.get("/", asyncRoute(async (_req, res) => {
  const [[counts]] = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM projects) AS project_count,
      (SELECT COUNT(*) FROM packages) AS package_count,
      (SELECT COUNT(*) FROM vulnerabilities) AS vulnerability_count,
      (SELECT COUNT(*) FROM alerts WHERE status = 'open') AS open_alert_count,
      (SELECT COUNT(*) FROM alerts WHERE status = 'acknowledged') AS acknowledged_alert_count,
      (SELECT COUNT(*) FROM alerts WHERE status = 'resolved') AS resolved_alert_count
  `);

  // FUNCTION get_vulnerability_severity() classifies each CVE
  const [severity] = await pool.query(`
    SELECT get_vulnerability_severity(v.cvss_score) AS severity,
           COUNT(DISTINCT v.id) AS count
    FROM vulnerabilities v
    JOIN alerts a ON a.vulnerability_id = v.id
    WHERE a.status = 'open'
    GROUP BY severity
    ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Low')
  `);

  // VIEW project_risk_overview + FUNCTION get_open_alert_count() + latest RISK_SNAPSHOT
  const [projects] = await pool.query(`
    SELECT pro.project_id, pro.project_name, pro.open_vulnerability_count,
           pro.max_cvss_score, pro.avg_cvss_score,
           get_open_alert_count(pro.project_id) AS open_alert_count,
           (SELECT rs.score FROM risk_snapshots rs
             WHERE rs.project_id = pro.project_id
             ORDER BY rs.computed_at DESC LIMIT 1) AS latest_risk_score,
           (SELECT COUNT(*) FROM project_dependencies pd WHERE pd.project_id = pro.project_id) AS dependency_count
    FROM project_risk_overview pro
    ORDER BY pro.max_cvss_score DESC, pro.open_vulnerability_count DESC
    LIMIT 6
  `);

  const [recentAlerts] = await pool.query(`
    SELECT a.id, a.project_id, p.name AS project_name,
           a.vulnerability_id, v.cve_id, v.description, v.cvss_score,
           get_vulnerability_severity(v.cvss_score) AS severity,
           a.status, a.created_at
    FROM alerts a
    JOIN projects p ON p.id = a.project_id
    JOIN vulnerabilities v ON v.id = a.vulnerability_id
    ORDER BY a.created_at DESC
    LIMIT 8
  `);

  res.json({ counts, severity, projects, recentAlerts });
}));

export default router;
