import test from "node:test";
import assert from "node:assert/strict";
import { hashPassword, verifyPassword, createAccessToken, verifyAccessToken, requireAuth, requireRole } from "../lib/auth.js";

process.env.JWT_SECRET = "unit-test-secret-with-more-than-thirty-two-characters";

test("passwords are stored as salted scrypt hashes", async () => {
  const hash = await hashPassword("a sufficiently long password");
  assert.match(hash, /^scrypt\$/);
  assert.notEqual(hash, "a sufficiently long password");
  assert.equal(await verifyPassword("a sufficiently long password", hash), true);
  assert.equal(await verifyPassword("wrong password", hash), false);
});

test("access tokens verify signed identity and reject tampering", () => {
  const token = createAccessToken({ id: "test-user", name: "Test User", email: "test@example.com", role: "admin" });
  const payload = verifyAccessToken(token);
  assert.equal(payload.sub, "test-user");
  assert.equal(payload.role, "admin");
  assert.equal(verifyAccessToken(`${token}tampered`), null);
});

test("authentication middleware rejects missing bearer tokens", () => {
  let captured;
  requireAuth({ headers: {} }, {}, (error) => { captured = error; });
  assert.equal(captured.status, 401);
});

test("role middleware rejects a Developer from an Admin-only operation", () => {
  let captured;
  requireRole("admin")({ user: { role: "developer" } }, {}, (error) => { captured = error; });
  assert.equal(captured.status, 403);
});
