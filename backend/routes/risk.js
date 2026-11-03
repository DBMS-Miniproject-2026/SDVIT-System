import { Router } from "express";
import pool from "../config/db.js";
import { asyncRoute } from "../lib/http.js";
import { requireRole } from "../lib/auth.js";

const router = Router();

// PROCEDURE recompute_all_project_risk (CURSOR loop). The OUT parameter is read back
// with a user variable, so both statements must share one connection.
router.post("/recompute", requireRole("admin"), asyncRoute(async (_req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.query("CALL recompute_all_project_risk(@processed)");
    const [[row]] = await conn.query("SELECT @processed AS processed");
    res.json({ message: "Risk snapshots recorded.", procedure: "recompute_all_project_risk", processed: row.processed });
  } finally {
    conn.release();
  }
}));

// PROCEDURE recompute_project_risk (returns the score it stored)
router.post("/recompute/:projectId", asyncRoute(async (req, res) => {
  const [sets] = await pool.query("CALL recompute_project_risk(?)", [req.params.projectId]);
  res.json({
    message: "Risk snapshot recorded.",
    procedure: "recompute_project_risk",
    score: sets[0]?.[0]?.computed_score ?? 0
  });
}));

export default router;
