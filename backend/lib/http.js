// Small helpers shared by all route files.

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Lets route handlers be written as plain async functions.
export const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// Translates MySQL errors into friendly HTTP responses. Showing the database's own
// constraint / SIGNAL messages in the UI is deliberate: it demonstrates that the
// rules live in the database (UNIQUE, CHECK, FOREIGN KEY, procedure SIGNALs).
export function errorHandler(err, _req, res, _next) {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ message: err.message });
  }
  if (err.errno === 1644 || err.sqlState === "45000") {
    return res.status(409).json({ message: err.sqlMessage || err.message });
  }
  switch (err.code) {
    case "ER_DUP_ENTRY":
      return res.status(409).json({ message: "That record already exists (UNIQUE constraint)." });
    case "ER_NO_REFERENCED_ROW_2":
      return res.status(400).json({ message: "A referenced record does not exist (FOREIGN KEY constraint)." });
    case "ER_ROW_IS_REFERENCED_2":
      return res.status(409).json({ message: "Cannot delete: other records still reference this one (FOREIGN KEY constraint)." });
    case "ER_CHECK_CONSTRAINT_VIOLATED":
      return res.status(400).json({ message: "A value violates a CHECK constraint (e.g. CVSS must be 0-10)." });
    default:
      console.error(err);
      return res.status(500).json({ message: "Unexpected server error." });
  }
}

export function requireFields(body, fields) {
  for (const f of fields) {
    if (body?.[f] === undefined || body[f] === null || String(body[f]).trim() === "") {
      throw new HttpError(400, `Missing required field: ${f}`);
    }
  }
}
