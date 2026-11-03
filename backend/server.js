import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pool from "./config/db.js";
import { errorHandler, asyncRoute } from "./lib/http.js";
import dashboardRoutes from "./routes/dashboard.js";
import projectRoutes from "./routes/projects.js";
import packageRoutes from "./routes/packages.js";
import vulnerabilityRoutes from "./routes/vulnerabilities.js";
import alertRoutes from "./routes/alerts.js";
import riskRoutes from "./routes/risk.js";
import analyticsRoutes from "./routes/analytics.js";
import databaseRoutes from "./routes/database.js";
import authRoutes from "./routes/auth.js";
import graphRoutes from "./routes/graph.js";
import { requireAuth, requireRole } from "./lib/auth.js";
import { checkNeo4jConnection } from "./graph/client.js";

dotenv.config();

const app = express();
app.use(cors({ origin: (process.env.FRONTEND_ORIGIN || "http://localhost:3000").split(",").map((s) => s.trim()) }));
app.use("/api/graph/import-lockfile", express.json({ limit: "15mb" })); // lockfiles are large
app.use(express.json({ limit: "1mb" }));

app.get("/api/health", async (_req, res) => {
  try {
    const [rows] = await pool.query("SELECT DATABASE() AS database_name");
    const neo4jStatus = await checkNeo4jConnection();
    res.json({
      status: neo4jStatus.status === "connected" ? "ok" : "degraded",
      message: "SDVIT API is running",
      databases: { mysql: { status: "connected", database: rows[0].database_name }, neo4j: neo4jStatus }
    });
  } catch (error) {
    console.error("Health check failed:", error.message);
    res.status(500).json({ status: "error", message: "Database connection failed. Check backend/.env and MySQL." });
  }
});

// Public endpoints are limited to bootstrap and login. All application APIs below require a valid token.
app.use("/api/auth", authRoutes);
app.use("/api", requireAuth);

// users table: used for the "owner" dropdown and administrator user management
app.get("/api/users", asyncRoute(async (_req, res) => {
  const [rows] = await pool.query("SELECT id, name, email, role FROM users ORDER BY name");
  res.json(rows);
}));

app.use("/api/dashboard", dashboardRoutes);
app.use("/api/projects", projectRoutes);
app.use("/api/packages", packageRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/graph", graphRoutes);
app.use("/api/risk", riskRoutes);
app.use("/api/analytics", analyticsRoutes);
app.use("/api/database", requireRole("admin"), databaseRoutes);

app.use(errorHandler);

const port = Number(process.env.PORT || 5000);
app.listen(port, () => console.log(`SDVIT API running on http://localhost:${port}`));
