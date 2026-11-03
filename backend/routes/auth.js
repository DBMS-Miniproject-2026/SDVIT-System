import { Router } from "express";
import { randomUUID } from "node:crypto";
import pool from "../config/db.js";
import { asyncRoute, HttpError, requireFields } from "../lib/http.js";
import { createAccessToken, hashPassword, requireAuth, requireRole, verifyPassword } from "../lib/auth.js";

const router = Router();
const ADMIN_BOOTSTRAP_EMAIL = "admin@sdvit.example";
const validEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    throw new HttpError(400, "Password must contain between 12 and 128 characters.");
  }
}

// One-time setup for the seeded Admin User. It can only replace the SQL demo placeholder.
router.post("/bootstrap", asyncRoute(async (req, res) => {
  requireFields(req.body, ["email", "password"]);
  const email = String(req.body.email).trim().toLowerCase();
  if (email !== ADMIN_BOOTSTRAP_EMAIL) throw new HttpError(400, `Use the seeded administrator account ${ADMIN_BOOTSTRAP_EMAIL}.`);
  validatePassword(req.body.password);

  const [[admin]] = await pool.query(
    "SELECT id, name, email, role, password_hash FROM users WHERE email = ? AND role = 'admin'",
    [email]
  );
  if (!admin) throw new HttpError(404, "The seeded administrator was not found. Run the SQL sample-data script first.");
  if (admin.password_hash !== "hashed_pw_placeholder") {
    throw new HttpError(409, "Administrator setup has already been completed. Sign in instead.");
  }

  const passwordHash = await hashPassword(req.body.password);
  const [updated] = await pool.query("UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = 'hashed_pw_placeholder'", [passwordHash, admin.id]);
  if (!updated.affectedRows) throw new HttpError(409, "Administrator setup has already been completed. Sign in instead.");
  res.status(201).json({ message: "Administrator account initialized. You can now sign in." });
}));

router.post("/login", asyncRoute(async (req, res) => {
  requireFields(req.body, ["email", "password"]);
  const email = String(req.body.email).trim().toLowerCase();
  const [[user]] = await pool.query(
    "SELECT id, name, email, role, password_hash FROM users WHERE email = ?",
    [email]
  );
  if (!user || !(await verifyPassword(String(req.body.password), user.password_hash))) {
    throw new HttpError(401, "Invalid email or password.");
  }
  const safeUser = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ token: createAccessToken(safeUser), user: safeUser, expiresIn: 28800 });
}));

router.use(requireAuth);

router.get("/me", (req, res) => {
  res.json({ id: req.user.sub, name: req.user.name, email: req.user.email, role: req.user.role });
});

router.post("/users", requireRole("admin"), asyncRoute(async (req, res) => {
  requireFields(req.body, ["name", "email", "password", "role"]);
  const name = String(req.body.name).trim();
  const email = String(req.body.email).trim().toLowerCase();
  const role = String(req.body.role).toLowerCase();
  validatePassword(req.body.password);
  if (name.length > 120) throw new HttpError(400, "Name must be 120 characters or fewer.");
  if (!validEmail.test(email) || email.length > 255) throw new HttpError(400, "Enter a valid email address.");
  if (!new Set(["admin", "developer"]).has(role)) throw new HttpError(400, "Role must be admin or developer.");

  const id = randomUUID();
  const passwordHash = await hashPassword(req.body.password);
  await pool.query(
    "INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
    [id, name, email, passwordHash, role]
  );
  res.status(201).json({ id, name, email, role, message: "User created." });
}));

router.patch("/users/:id/role", requireRole("admin"), asyncRoute(async (req, res) => {
  const role = String(req.body.role || "").toLowerCase();
  if (!new Set(["admin", "developer"]).has(role)) throw new HttpError(400, "Role must be admin or developer.");
  if (req.params.id === req.user.sub && role !== "admin") {
    throw new HttpError(409, "You cannot remove your own administrator role.");
  }
  const [result] = await pool.query("UPDATE users SET role = ? WHERE id = ?", [role, req.params.id]);
  if (!result.affectedRows) throw new HttpError(404, "User not found.");
  res.json({ message: "User role updated." });
}));

export default router;
