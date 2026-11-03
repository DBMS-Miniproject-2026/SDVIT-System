import { Router } from "express";
import { randomUUID } from "node:crypto";
import pool from "../config/db.js";
import { asyncRoute, HttpError, requireFields } from "../lib/http.js";
import { requireRole } from "../lib/auth.js";

const router = Router();
const ECOSYSTEMS = ["npm", "pypi", "maven", "cargo", "other"];

// packages + package_versions with how many CVEs / projects touch each version
router.get("/", asyncRoute(async (_req, res) => {
  const [rows] = await pool.query(`
    SELECT pkg.id AS package_id, pkg.name, pkg.ecosystem,
           pv.id AS version_id, pv.version, pv.release_date,
           (SELECT COUNT(*) FROM vuln_affected_versions vav
             WHERE vav.package_version_id = pv.id) AS cve_count,
           (SELECT COUNT(*) FROM project_dependencies pd
             WHERE pd.package_version_id = pv.id) AS project_count
    FROM packages pkg
    LEFT JOIN package_versions pv ON pv.package_id = pkg.id
    ORDER BY pkg.name, pv.release_date DESC
  `);

  const byPackage = new Map();
  for (const r of rows) {
    if (!byPackage.has(r.package_id)) {
      byPackage.set(r.package_id, { id: r.package_id, name: r.name, ecosystem: r.ecosystem, versions: [] });
    }
    if (r.version_id) {
      byPackage.get(r.package_id).versions.push({
        id: r.version_id,
        version: r.version,
        release_date: r.release_date,
        cve_count: r.cve_count,
        project_count: r.project_count
      });
    }
  }
  res.json([...byPackage.values()]);
}));

// INSERT package (if new) + package_version in one transaction
router.post("/versions", requireRole("admin"), asyncRoute(async (req, res) => {
  requireFields(req.body, ["name", "ecosystem", "version"]);
  const name = String(req.body.name).trim();
  const version = String(req.body.version).trim();
  const { ecosystem } = req.body;
  const releaseDate = req.body.release_date || null;
  if (!ECOSYSTEMS.includes(ecosystem)) throw new HttpError(400, "Unknown ecosystem.");
  if (releaseDate && !/^\d{4}-\d{2}-\d{2}$/.test(releaseDate)) {
    throw new HttpError(400, "Release date must be YYYY-MM-DD.");
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [existing] = await conn.query(
      "SELECT id FROM packages WHERE name = ? AND ecosystem = ?",
      [name, ecosystem]
    );
    let packageId = existing[0]?.id;
    if (!packageId) {
      packageId = randomUUID();
      await conn.query("INSERT INTO packages (id, name, ecosystem) VALUES (?, ?, ?)", [packageId, name, ecosystem]);
    }
    const versionId = randomUUID();
    await conn.query(
      "INSERT INTO package_versions (id, package_id, version, release_date) VALUES (?, ?, ?, ?)",
      [versionId, packageId, version, releaseDate]
    );
    await conn.commit();
    res.status(201).json({ package_id: packageId, version_id: versionId, message: "Package version added." });
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}));

// DELETE package: its versions cascade, but versions still used by a project are
// protected by the foreign key (RESTRICT) and the delete is refused.
router.delete("/:id", requireRole("admin"), asyncRoute(async (req, res) => {
  const [[removed]] = await pool.query(
    "SELECT COUNT(*) AS versions FROM package_versions WHERE package_id = ?",
    [req.params.id]
  );
  const [result] = await pool.query("DELETE FROM packages WHERE id = ?", [req.params.id]);
  if (result.affectedRows === 0) throw new HttpError(404, "Package not found.");
  res.json({ message: "Package deleted.", cascaded: removed });
}));

export default router;
