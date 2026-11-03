import neo4j from "neo4j-driver";
import { HttpError } from "../lib/http.js";

// Neo4j connection + schema bootstrap. Credentials come from environment variables only.
let driver;
let readyPromise;

const CONSTRAINTS = [
  "CREATE CONSTRAINT project_id IF NOT EXISTS FOR (n:Project) REQUIRE n.id IS UNIQUE",
  "CREATE CONSTRAINT pkgver_key IF NOT EXISTS FOR (n:PackageVersion) REQUIRE n.key IS UNIQUE",
  "CREATE CONSTRAINT pkgver_id IF NOT EXISTS FOR (n:PackageVersion) REQUIRE n.id IS UNIQUE",
  "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE",
  "CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.cve_id IS UNIQUE"
];

function sessionConfig(mode) {
  const config = { defaultAccessMode: mode };
  if (process.env.NEO4J_DATABASE) config.database = process.env.NEO4J_DATABASE;
  return config;
}

function getDriver() {
  const { NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD } = process.env;
  if (!NEO4J_URI || !NEO4J_USER || !NEO4J_PASSWORD) {
    throw new HttpError(503, "Neo4j is not configured. Set NEO4J_URI, NEO4J_USER and NEO4J_PASSWORD in backend/.env.");
  }
  // disableLosslessIntegers: counts come back as plain JS numbers instead of Integer objects.
  if (!driver) driver = neo4j.driver(NEO4J_URI, neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD), { disableLosslessIntegers: true });
  return driver;
}

async function ready() {
  const d = getDriver();
  if (!readyPromise) {
    readyPromise = (async () => {
      await d.verifyConnectivity();
      const session = d.session(sessionConfig(neo4j.session.WRITE));
      try {
        for (const statement of CONSTRAINTS) await session.run(statement);
      } finally {
        await session.close();
      }
    })().catch((error) => {
      readyPromise = null;
      throw new HttpError(503, `Neo4j connection failed: ${error.message}`);
    });
  }
  return readyPromise;
}

// Parameterized Cypher only: never build query text from user input.
export async function readQuery(cypher, params = {}) {
  await ready();
  const session = getDriver().session(sessionConfig(neo4j.session.READ));
  try {
    const result = await session.executeRead((tx) => tx.run(cypher, params));
    return result.records.map((record) => record.toObject());
  } finally {
    await session.close();
  }
}

// `work` receives a transaction; everything it runs commits or rolls back together.
export async function writeTx(work) {
  await ready();
  const session = getDriver().session(sessionConfig(neo4j.session.WRITE));
  try {
    return await session.executeWrite(work);
  } finally {
    await session.close();
  }
}

export async function checkNeo4jConnection() {
  const { NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD } = process.env;
  if (!NEO4J_URI || !NEO4J_USER || !NEO4J_PASSWORD) {
    return { status: "not_configured", message: "Set NEO4J_URI, NEO4J_USER and NEO4J_PASSWORD." };
  }
  try {
    await ready();
    return { status: "connected", database: process.env.NEO4J_DATABASE || "default" };
  } catch (error) {
    return { status: "unavailable", message: error.message };
  }
}
