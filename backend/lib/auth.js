import { createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { HttpError } from "./http.js";

const scrypt = promisify(scryptCallback);
const TOKEN_TTL_SECONDS = 8 * 60 * 60;

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString("hex")}$${Buffer.from(derived).toString("hex")}`;
}

export async function verifyPassword(password, encoded) {
  if (typeof encoded !== "string" || !encoded.startsWith("scrypt$")) return false;
  const [, saltHex, hashHex] = encoded.split("$");
  if (!saltHex || !hashHex || !/^[a-f0-9]+$/i.test(saltHex) || !/^[a-f0-9]+$/i.test(hashHex)) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = Buffer.from(await scrypt(password, Buffer.from(saltHex, "hex"), expected.length));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function tokenSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32 || secret.toLowerCase().includes("replace_with")) {
    throw new Error("JWT_SECRET must be configured with at least 32 characters.");
  }
  return secret;
}

export function createAccessToken(user) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    sub: user.id,
    email: user.email,
    role: user.role,
    name: user.name,
    iat: now,
    exp: now + TOKEN_TTL_SECONDS
  })).toString("base64url");
  const unsigned = `${header}.${payload}`;
  const signature = createHmac("sha256", tokenSecret()).update(unsigned).digest("base64url");
  return `${unsigned}.${signature}`;
}

export function verifyAccessToken(token) {
  try {
    const [header, payload, signature] = String(token).split(".");
    if (!header || !payload || !signature) return null;
    const unsigned = `${header}.${payload}`;
    const expected = createHmac("sha256", tokenSecret()).update(unsigned).digest();
    const supplied = Buffer.from(signature, "base64url");
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return null;
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!decoded.sub || !decoded.exp || decoded.exp <= Math.floor(Date.now() / 1000)) return null;
    return decoded;
  } catch {
    return null;
  }
}

export function requireAuth(req, _res, next) {
  const value = req.headers.authorization || "";
  const token = value.startsWith("Bearer ") ? value.slice(7) : "";
  const user = token ? verifyAccessToken(token) : null;
  if (!user) return next(new HttpError(401, "Please sign in to continue."));
  req.user = user;
  next();
}

export function requireRole(...roles) {
  return (req, _res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return next(new HttpError(403, `This action requires one of these roles: ${roles.join(", ")}.`));
    }
    next();
  };
}
