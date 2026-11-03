import { HttpError } from "./http.js";

// Turns an npm package-lock.json (lockfileVersion 2 or 3) into graph nodes and
// "A requires B" edges. Pure function: no database access, easy to unit test.
const MAX_PACKAGES = 20000;

const nameFromPath = (path) => path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);

// Node's resolution rule: look in <pkg>/node_modules, then walk up to the root node_modules.
function resolveInstalled(fromPath, dependency, installed) {
  let base = fromPath;
  for (;;) {
    const candidate = base ? `${base}/node_modules/${dependency}` : `node_modules/${dependency}`;
    if (installed.has(candidate)) return installed.get(candidate);
    if (!base) return null;
    const idx = base.lastIndexOf("node_modules/");
    base = idx <= 0 ? "" : base.slice(0, idx - 1);
  }
}

export function parseLockfile(lockfile) {
  if (!lockfile || typeof lockfile !== "object" || Array.isArray(lockfile)) {
    throw new HttpError(400, "The lockfile must be a JSON object.");
  }
  const packages = lockfile.packages;
  if (!packages || typeof packages !== "object") {
    throw new HttpError(400, "Only npm lockfileVersion 2 or 3 (with a 'packages' map) is supported.");
  }
  const paths = Object.keys(packages);
  if (paths.length > MAX_PACKAGES) throw new HttpError(400, `Lockfile has more than ${MAX_PACKAGES} packages.`);

  const installed = new Map();
  for (const path of paths) {
    const entry = packages[path];
    if (path === "" || !entry || entry.link || typeof entry.version !== "string") continue;
    const name = typeof entry.name === "string" && entry.name ? entry.name : nameFromPath(path);
    installed.set(path, { key: `npm:${name}@${entry.version}`, name, ecosystem: "npm", version: entry.version });
  }

  const edgeSet = new Set();
  for (const [path, node] of installed) {
    const entry = packages[path];
    const deps = { ...(entry.dependencies || {}), ...(entry.optionalDependencies || {}) };
    for (const dependency of Object.keys(deps)) {
      const target = resolveInstalled(path, dependency, installed);
      if (target && target.key !== node.key) edgeSet.add(`${node.key}\u0000${target.key}`);
    }
  }

  const nodes = [...new Map([...installed.values()].map((n) => [n.key, n])).values()];
  const edges = [...edgeSet].map((pair) => {
    const [from, to] = pair.split("\u0000");
    return { from, to };
  });
  return { nodes, edges };
}

// "npm:@babel/core@7.0.0" -> { ecosystem, name, version }
export function parsePackageKey(key) {
  const match = /^(npm|pypi|maven|cargo|other):(.+)@([^@]+)$/.exec(String(key || "").trim());
  if (!match) return null;
  return { key: `${match[1]}:${match[2]}@${match[3]}`, ecosystem: match[1], name: match[2], version: match[3] };
}
