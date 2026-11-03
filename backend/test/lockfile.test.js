import test from "node:test";
import assert from "node:assert/strict";
import { parseLockfile, parsePackageKey } from "../lib/lockfile.js";

const lock = {
  lockfileVersion: 3,
  packages: {
    "": { name: "demo", dependencies: { express: "^4.0.0" } },
    "node_modules/express": { version: "4.17.1", dependencies: { "body-parser": "1.19.0", qs: "6.7.0" } },
    "node_modules/body-parser": { version: "1.19.0", dependencies: { qs: "6.7.0" } },
    "node_modules/qs": { version: "6.7.0" },
    "node_modules/body-parser/node_modules/qs": { version: "6.5.0" },
    "node_modules/@scope/util": { version: "1.0.0", dependencies: { qs: "6.7.0" } }
  }
};

test("lockfile becomes package-version nodes and requires edges", () => {
  const { nodes, edges } = parseLockfile(lock);
  const keys = nodes.map((n) => n.key).sort();
  assert.deepEqual(keys, ["npm:@scope/util@1.0.0", "npm:body-parser@1.19.0", "npm:express@4.17.1", "npm:qs@6.5.0", "npm:qs@6.7.0"]);
  const has = (from, to) => edges.some((e) => e.from === from && e.to === to);
  assert.ok(has("npm:express@4.17.1", "npm:body-parser@1.19.0"));
  assert.ok(has("npm:express@4.17.1", "npm:qs@6.7.0"));
  // nested node_modules wins over the hoisted copy, like Node's resolution
  assert.ok(has("npm:body-parser@1.19.0", "npm:qs@6.5.0"));
  assert.ok(!has("npm:body-parser@1.19.0", "npm:qs@6.7.0"));
  assert.ok(has("npm:@scope/util@1.0.0", "npm:qs@6.7.0"));
});

test("unsupported lockfiles are rejected", () => {
  assert.throws(() => parseLockfile({ lockfileVersion: 1, dependencies: {} }), /lockfileVersion 2 or 3/);
  assert.throws(() => parseLockfile([]), /JSON object/);
});

test("package keys parse, including scoped names", () => {
  assert.deepEqual(parsePackageKey("npm:@babel/core@7.0.0"), { key: "npm:@babel/core@7.0.0", ecosystem: "npm", name: "@babel/core", version: "7.0.0" });
  assert.equal(parsePackageKey("not a key"), null);
});
