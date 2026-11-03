# SDVIT — Software Dependency Vulnerability & Impact Tracking

SDVIT tracks projects, their package dependencies, known vulnerabilities (CVEs), project alerts and historical risk scores. It answers questions such as _"Which of my projects are exposed to this CVE, and through which chain of dependencies?"_

The system uses **two database paradigms**, each chosen for the shape of its data:

- **MySQL (relational)** — the system of record for users, projects, packages, versions, CVEs, alerts and risk history, with constraints, triggers, procedures, views and transactions.
- **Neo4j (graph)** — the dependency graph, including _transitive_ dependencies, so exposure through indirect packages can be found with a single traversal.

Built for the DBMS Experiential Learning Level 3 mini project.

---

## Table of contents

1. [Technology stack](#1-technology-stack)
2. [Why two databases](#2-why-two-databases)
3. [Repository structure](#3-repository-structure)
4. [Prerequisites](#4-prerequisites)
5. [Setup](#5-setup)
6. [First login and user roles](#6-first-login-and-user-roles)
7. [Loading the dependency graph](#7-loading-the-dependency-graph)
8. [Application features](#8-application-features)
9. [SQL objects](#9-sql-objects)
10. [API reference](#10-api-reference)
11. [Testing](#11-testing)
12. [Troubleshooting](#12-troubleshooting)
13. [Security notes](#13-security-notes)
14. [Limitations](#14-limitations)
15. [Documentation](#15-documentation)
16. [Team and contributions](#16-team-and-contributions)

---

## 1. Technology stack

| Layer               | Technology                                                           |
| ------------------- | -------------------------------------------------------------------- |
| Frontend            | Next.js (App Router) + React + React Router                          |
| Backend / API       | Node.js + Express                                                    |
| Relational database | MySQL 8.x (`mysql2/promise`)                                         |
| Graph database      | Neo4j (`neo4j-driver`, Cypher)                                       |
| Authentication      | Salted scrypt password hashes + signed bearer tokens (8-hour expiry) |
| Configuration       | Environment variables (`.env`, never committed)                      |

Node.js **20.19 or later** is required.

---

## 2. Why two databases

### MySQL — operational records

Users, projects, packages, package versions, project dependencies, vulnerabilities, affected versions, alerts and risk snapshots all have well-defined relationships, uniqueness rules and transactional updates. MySQL enforces them with primary/foreign keys, `UNIQUE` and `CHECK` constraints, and implements the alert and risk workflows with triggers, stored procedures, functions and views.

### Neo4j — dependency graph

Software dependencies form a graph of unknown depth: a project depends on a package, which requires other packages, which require others. Finding every project that reaches a vulnerable package — and the chain that connects them — is a variable-length traversal. In SQL this needs recursive queries and repeated self-joins; in Cypher it is a single pattern. Neo4j is used for exactly this and nothing else.

**Graph data model**

| Node label       | Properties                                                             | Loaded from                            |
| ---------------- | ---------------------------------------------------------------------- | -------------------------------------- |
| `Project`        | `id`, `name`                                                           | MySQL `projects`                       |
| `PackageVersion` | `key` (`ecosystem:name@version`), `id`, `name`, `ecosystem`, `version` | MySQL `package_versions` and lockfiles |
| `Vulnerability`  | `id`, `cve_id`, `cvss_score`                                           | MySQL `vulnerabilities`                |

| Relationship                                       | Meaning                     | Loaded from                    |
| -------------------------------------------------- | --------------------------- | ------------------------------ |
| `(Project)-[:DEPENDS_ON {type}]->(PackageVersion)` | Declared dependency         | MySQL `project_dependencies`   |
| `(Vulnerability)-[:AFFECTS]->(PackageVersion)`     | CVE applies to this version | MySQL `vuln_affected_versions` |
| `(PackageVersion)-[:REQUIRES]->(PackageVersion)`   | Transitive link             | **Neo4j only**, from lockfiles |

**Constraints / indexes** (created automatically on first connection): unique `Project.id`, `PackageVersion.key`, `PackageVersion.id`, `Vulnerability.id`, `Vulnerability.cve_id`.

**Boundary between the two databases:** MySQL is the source of truth. An administrator runs **Rebuild from MySQL**, which copies projects, package versions, CVEs, `DEPENDS_ON` and `AFFECTS` into Neo4j in a single transaction. `REQUIRES` links exist only in Neo4j and are preserved across rebuilds. Alerts, risk snapshots, users and authentication stay in MySQL.

---

## 3. Repository structure

```
sdvit_project_completed/
├── backend/
│   ├── config/db.js            MySQL connection pool
│   ├── graph/client.js         Neo4j driver, constraints, query helpers
│   ├── lib/                    auth, HTTP helpers, lockfile parser
│   ├── routes/                 REST routes (projects, packages, vulnerabilities,
│   │                           alerts, risk, analytics, database, auth, graph)
│   ├── test/                   unit tests (auth, lockfile parser)
│   ├── .env.example            backend configuration template
│   └── server.js               Express entry point
├── frontend/
│   ├── src/app/                Next.js App Router shell
│   ├── src/pages/              application screens (incl. Graph.jsx)
│   ├── src/components/         shared UI components
│   └── .env.example            frontend configuration template
├── sql/
│   ├── SDVIT_DDL_ONLY.sql                 database, tables, indexes, first view
│   ├── DBMS_REVIEW2.sql                   triggers, functions, procedures, sample data
│   └── SDVIT_REVIEW3_APP_EXTENSIONS.sql   acknowledge_alert procedure
├── docs/                       report material, ER diagram, architecture
└── README.md
```

---

## 4. Prerequisites

- **Node.js** 20.19+ and npm
- **MySQL** 8.x, with a user that can create databases, tables, views, triggers and routines
- **Neo4j** — either of:
  - **Neo4j Desktop** (local instance), or
  - **Neo4j Aura Free** (cloud)
- **Git**

---

## 5. Setup

### 5.1 Clone

```bash
git clone https://github.com/VaibhavR1936/sdvit.git
cd sdvit
```

### 5.2 Create the MySQL database

Run the three scripts **in this order** (MySQL Workbench, or the `mysql` command line):

1. `sql/SDVIT_DDL_ONLY.sql` — creates `sdvitsystem`, the nine tables, indexes and the `project_risk_overview` view.
   **This script drops and recreates the database. Back up any existing data first.**
2. `sql/DBMS_REVIEW2.sql` — triggers, functions, stored procedures, the second view, sample data and query demonstrations.
3. `sql/SDVIT_REVIEW3_APP_EXTENSIONS.sql` — the `acknowledge_alert` procedure used by the Alert Center.

Command-line example:

```bash
mysql -u root -p < sql/SDVIT_DDL_ONLY.sql
mysql -u root -p < sql/DBMS_REVIEW2.sql
mysql -u root -p < sql/SDVIT_REVIEW3_APP_EXTENSIONS.sql
```

### 5.3 Start Neo4j

**Option A — Neo4j Desktop (local)**

1. Create a local instance and set a password when asked.
2. Click **Start** and wait until it shows **RUNNING**.
3. The connection URI is normally `bolt://localhost:7687` and the username is `neo4j`.

**Option B — Neo4j Aura Free (cloud)**

1. Create a free instance at <https://console.neo4j.io> and **save the credentials file** — the password is shown only once.
2. The URI looks like `neo4j+s://<id>.databases.neo4j.io`.

### 5.4 Configure the backend

```bash
cd backend
cp .env.example .env        # on Windows PowerShell: copy .env.example .env
```

Edit `backend/.env`:

```ini
PORT=5000
FRONTEND_ORIGIN=http://localhost:3000

# MySQL
DB_HOST=localhost
DB_PORT=3306
DB_USER=root                      # prefer a dedicated application user
DB_PASSWORD=your_mysql_password
DB_NAME=sdvitsystem

# Signed tokens: random string, at least 32 characters
JWT_SECRET=replace_with_a_long_random_string

# Neo4j
NEO4J_URI=bolt://localhost:7687   # Aura: neo4j+s://<id>.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password
# NEO4J_DATABASE=neo4j            # optional; omit to use the server default
```

Generate a secret with:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

> **Use `bolt://` for a single local Neo4j instance.** `neo4j://` asks the server for a cluster routing table and can fail locally with _"No routing servers available"_. Aura requires `neo4j+s://`.

Install and start:

```bash
npm install
npm run dev
```

The API runs at <http://localhost:5000>.
Check <http://localhost:5000/api/health> — both databases should report `connected`:

```json
{
  "status": "ok",
  "databases": {
    "mysql": { "status": "connected" },
    "neo4j": { "status": "connected" }
  }
}
```

> `nodemon` does not watch `.env`. After editing it, type `rs` in the terminal (or stop and start the server).

### 5.5 Start the frontend

```bash
cd frontend
cp .env.example .env.local        # contains NEXT_PUBLIC_API_URL=http://localhost:5000/api
npm install
npm run dev
```

Open <http://localhost:3000>.

---

## 6. First login and user roles

1. Open the frontend and choose **Initialize admin**.
2. Use the seeded account `admin@sdvit.example` and set a password of **at least 12 characters**.
3. Sign in with that email and password.
4. Open **Users** in the sidebar and create at least one `developer` account (the project needs two roles).

Passwords are hashed with Node's scrypt and a random salt. The SQL sample data inserts a placeholder hash that cannot be used to log in; the one-time setup replaces it.

### Role permissions

| Capability                                                           | Admin | Developer |
| -------------------------------------------------------------------- | :---: | :-------: |
| View projects, packages, CVEs, alerts, analytics                     |  ✅   |    ✅     |
| View the dependency graph, exposure and blast radius                 |  ✅   |    ✅     |
| Create projects; add/remove project dependencies                     |  ✅   |    ✅     |
| Acknowledge an alert                                                 |  ✅   |    ✅     |
| Create CVE records; link affected versions                           |  ✅   |    ❌     |
| Add package versions                                                 |  ✅   |    ❌     |
| Resolve alerts                                                       |  ✅   |    ❌     |
| Delete projects or packages                                          |  ✅   |    ❌     |
| Recompute risk for all projects                                      |  ✅   |    ❌     |
| Rebuild the graph from MySQL; import lockfiles; add `REQUIRES` links |  ✅   |    ❌     |
| Inspect database metadata and the transaction demo                   |  ✅   |    ❌     |
| Create users and assign roles                                        |  ✅   |    ❌     |

Authorization is enforced in the Express API, not only by hiding buttons.

---

## 7. Loading the dependency graph

The **Dependency graph** page starts empty. Fill it in two steps (administrator only):

1. **Rebuild from MySQL** — copies projects, package versions, CVEs and their links into Neo4j. Run it again whenever the relational data changes.
2. **Import package-lock.json** — upload an npm lockfile (`lockfileVersion` 2 or 3) to create the transitive `REQUIRES` links.

Package versions are matched by exact `ecosystem:name@version`, so the name and version registered in MySQL must be identical to the lockfile's (for example `4.17.1`, not `v4.17.1`).

### Quick demo

1. In an empty folder, run `npm install express@4.17.1 --package-lock-only` to generate a `package-lock.json` without installing anything.
2. In SDVIT, register the package versions `express 4.17.1` and `qs 6.7.0`.
3. Create a project and add `express 4.17.1` as its dependency.
4. Add a CVE and link it to `qs 6.7.0`.
5. On the Dependency graph page: **Rebuild from MySQL**, then **Import package-lock.json** with the lockfile from step 1.
6. Click **Inspect** on the project. The CVE appears as _Transitive (1 hop)_ with the chain `express → qs`.

A single transitive link can also be added without a lockfile:

```http
POST /api/graph/requires
{"from": "npm:express@4.17.1", "to": "npm:qs@6.7.0"}
```

---

## 8. Application features

- **Overview** — project exposure, alert counts and risk summaries.
- **Projects** — create projects, inspect and manage dependencies, view project risk.
- **Packages** — packages and their versions.
- **Vulnerabilities** — record CVEs and affected versions; MySQL triggers create alerts when an affected version is in use.
- **Alert center** — acknowledge or resolve alerts. Resolving calls the `resolve_alert` procedure, and a trigger records a risk snapshot.
- **Dependency graph (Neo4j)**
  - _Exposure by project_ — distinct CVEs reachable through direct **or transitive** dependencies.
  - _Why is this project exposed?_ — shortest dependency chain from the project to each vulnerable package.
  - _Dependency graph view_ — layered diagram; dashed edges are transitive, red packages are affected by a CVE.
  - _CVE blast radius_ — every project that reaches a CVE, and how many hops away.
  - _Most depended-on packages_ — ranked by transitive dependents.
- **Analytics** — joins, grouping, aggregates and subqueries.
- **Database** (admin) — inspect tables, triggers, routines, views and indexes; run `EXPLAIN`; demonstrate transaction rollback.
- **Users** (admin) — create accounts and assign roles.

---

## 9. SQL objects

| Object                                   | Purpose                                                                   |
| ---------------------------------------- | ------------------------------------------------------------------------- |
| `trg_alert_on_new_dependency`            | Adding a dependency can create alerts for known vulnerable versions       |
| `trg_alert_on_new_vuln_affected_version` | Linking a vulnerable version creates alerts for projects already using it |
| `trg_risk_snapshot_on_alert_resolved`    | Resolving an alert records a new risk snapshot                            |
| `resolve_alert`                          | Transactional resolve with error handling                                 |
| `acknowledge_alert`                      | Transactional acknowledge                                                 |
| `recompute_project_risk`                 | Recalculate one project's risk score                                      |
| `recompute_all_project_risk`             | Cursor-based recalculation for all projects                               |
| `get_project_vulnerability_report`       | Project findings report                                                   |
| `get_vulnerability_severity`             | Maps a CVSS score to a severity label                                     |
| `get_open_alert_count`                   | Open-alert count for a project                                            |
| `project_risk_overview`                  | View: dashboard and project risk summary                                  |
| `project_vulnerability_details`          | View: project findings                                                    |

The relational schema has 9 tables, 2 views, 3 triggers, 2 functions and 5 stored procedures.

---

## 10. API reference

All routes except those marked _public_ require `Authorization: Bearer <token>`. The API returns `401` for a missing/invalid token and `403` when the role is not allowed.

**Public**

- `GET /api/health`
- `POST /api/auth/bootstrap`
- `POST /api/auth/login`

**Authenticated**

- `GET /api/auth/me`, `GET /api/users`
- Projects, packages, vulnerabilities, alerts, risk and analytics routes
- `/api/database/*` (admin)

**User administration (admin)**

- `POST /api/auth/users`
- `PATCH /api/auth/users/:id/role`

**Graph (Neo4j)**

| Method and path                      | Role  | Description                                    |
| ------------------------------------ | ----- | ---------------------------------------------- |
| `GET /api/graph/status`              | any   | Node and relationship counts                   |
| `GET /api/graph/overview`            | any   | Reachable CVEs and worst CVSS per project      |
| `GET /api/graph/exposure/:projectId` | any   | Findings with the shortest dependency chain    |
| `GET /api/graph/blast-radius/:cve`   | any   | Projects that reach a CVE, and depth           |
| `GET /api/graph/critical-packages`   | any   | Packages ranked by transitive dependents       |
| `GET /api/graph/subgraph/:projectId` | any   | Nodes and links for the diagram                |
| `POST /api/graph/rebuild`            | admin | Copy MySQL data into Neo4j (one transaction)   |
| `POST /api/graph/import-lockfile`    | admin | Load transitive links from `package-lock.json` |
| `POST /api/graph/requires`           | admin | Add one `REQUIRES` link                        |

All Cypher is parameterized; no query text is built from user input.

---

## 11. Testing

Automated unit tests (authentication, role guards, lockfile parser):

```bash
cd backend
npm test
```

Manual integration checks to run after setup:

1. `GET /api/health` reports MySQL and Neo4j as `connected`.
2. First-time admin setup succeeds once; a second attempt is rejected.
3. Admin login succeeds; a wrong password and a missing token are rejected.
4. Admin creates a Developer; the Developer can sign in.
5. Developer can view data, create a project and add a dependency.
6. Developer is denied `/api/database/*`, `POST /api/graph/rebuild` and `POST /api/graph/import-lockfile`.
7. Adding a dependency and linking a vulnerable version fires the MySQL alert triggers.
8. Resolving an alert stores a risk snapshot; the Database page rollback demo restores state.
9. After **Rebuild from MySQL** the graph counts match the MySQL row counts.
10. After importing a lockfile, a CVE on a transitive package appears for the dependent project with the correct hop count.
11. **Blast radius** for that CVE lists the same project.

Record the results and screenshots in the project report.

---

## 12. Troubleshooting

| Symptom                                                                    | Cause and fix                                                                                                                                               |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Database connection failed` / `Access denied for user 'root'@'localhost'` | `DB_PASSWORD` in `backend/.env` does not match MySQL. Verify with `mysql -u root -p`, correct it, then restart the backend. Quote passwords containing `#`. |
| Health shows `neo4j: not_configured`                                       | One of `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` is missing from `backend/.env`.                                                                          |
| `Neo4j connection failed: ... No routing servers available`                | Local single instance: use `bolt://localhost:7687` instead of `neo4j://`. Also confirm the instance is **RUNNING**.                                         |
| Neo4j authentication failure                                               | `NEO4J_PASSWORD` must be the password set when the instance was created.                                                                                    |
| Graph page loads but is empty                                              | Click **Rebuild from MySQL** first.                                                                                                                         |
| A transitive CVE is missing                                                | The package name or version in MySQL does not exactly match the lockfile.                                                                                   |
| `.env` changes have no effect                                              | Restart the backend; `nodemon` does not reload `.env`.                                                                                                      |
| Next.js warns about multiple lockfiles                                     | A stray `package-lock.json` exists in a parent folder. Delete it, or set `turbopack.root` in `frontend/next.config.mjs`.                                    |

---

## 13. Security notes

- Never commit `.env` files. `.gitignore` excludes them; only `.env.example` files are tracked.
- Use a dedicated MySQL application user rather than `root`, and a unique random `JWT_SECRET`.
- Passwords are stored as salted scrypt hashes and are never returned by the API.
- Authorization is checked server-side on every protected route.
- Neo4j queries are parameterized.
- This is an academic project, not a production-hardened deployment. A real deployment would add HTTPS, HttpOnly cookies, login rate limiting, audit logging and managed secret storage.

---

## 14. Limitations

- The graph is a **snapshot** refreshed on demand, not synchronised live with MySQL.
- Transitive links come from **npm lockfiles (v2/v3)** or manual entry; other ecosystems (PyPI, Maven, Cargo) are not parsed.
- Versions are matched by **exact string**; semantic-version ranges are not resolved.
- Vulnerability data is entered manually; there is no automatic NVD/OSV/GitHub Advisory ingestion.

---

## 15. Team and contributions

| Member                    | Responsibilities                                   |
| ------------------------- | -------------------------------------------------- |
| _Vaibhav R PES2UG24CS664_ | e.g. MySQL schema, triggers/procedures, API routes |
| _Samaresh PES2UG24CS657_  | e.g. Neo4j graph model, Next.js frontend, testing  |
