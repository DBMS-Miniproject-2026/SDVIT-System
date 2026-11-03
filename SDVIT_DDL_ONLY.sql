-- =====================================================================
-- Software Dependency Vulnerability & Impact Tracking System
-- MySQL 8.x DDL (SQL side; Neo4j graph layer stores DEPENDS_ON edges
-- separately for transitive traversal)
-- =====================================================================

-- IDs are stored as CHAR(36) UUID strings (generated with UUID() in
-- application code or via DEFAULT (UUID()) on MySQL 8.0.13+)

-- ---------------------------------------------------------------------
-- USERS  (auth + role-based access: Admin / Developer)
-- ---------------------------------------------------------------------
DROP DATABASE IF EXISTS sdvitsystem;
CREATE DATABASE sdvitsystem;
USE sdvitsystem;

CREATE TABLE users (
    id              CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name            VARCHAR(120) NOT NULL,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(20)  NOT NULL DEFAULT 'developer'
                        CHECK (role IN ('admin', 'developer')),
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- PROJECTS  (each owned by a user; the thing whose exposure we track)
-- ---------------------------------------------------------------------
CREATE TABLE projects (
    id              CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    owner_id        CHAR(36) NOT NULL,
    name            VARCHAR(150) NOT NULL,
    repo_url        VARCHAR(500),
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_owner_project (owner_id, name),
    CONSTRAINT fk_projects_owner FOREIGN KEY (owner_id) REFERENCES users(id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- PACKAGES  (distinct library/package names, per ecosystem)
-- ---------------------------------------------------------------------
CREATE TABLE packages (
    id              CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name            VARCHAR(150) NOT NULL,
    ecosystem       VARCHAR(30)  NOT NULL
                        CHECK (ecosystem IN ('npm', 'pypi', 'maven', 'cargo', 'other')),
    UNIQUE KEY uq_package_name_ecosystem (name, ecosystem)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- PACKAGE_VERSIONS  (specific released versions of a package)
-- ---------------------------------------------------------------------
CREATE TABLE package_versions (
    id              CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    package_id      CHAR(36) NOT NULL,
    version         VARCHAR(50) NOT NULL,
    release_date    DATE,
    UNIQUE KEY uq_package_version (package_id, version),
    CONSTRAINT fk_pkgver_package FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- PROJECT_DEPENDENCIES  (direct dependency declarations; transitive
-- resolution itself lives in the Neo4j graph, not here)
-- ---------------------------------------------------------------------
CREATE TABLE project_dependencies (
    id                     CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    project_id             CHAR(36) NOT NULL,
    package_version_id     CHAR(36) NOT NULL,
    dependency_type        VARCHAR(20) NOT NULL DEFAULT 'direct'
                                CHECK (dependency_type IN ('direct', 'dev', 'transitive')),
    added_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_project_pkgver (project_id, package_version_id),
    CONSTRAINT fk_pd_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT fk_pd_pkgver  FOREIGN KEY (package_version_id) REFERENCES package_versions(id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- VULNERABILITIES  (CVE records, sourced from NVD/OSV feeds)
-- ---------------------------------------------------------------------
CREATE TABLE vulnerabilities (
    id              CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    cve_id          VARCHAR(30) NOT NULL UNIQUE,
    description     TEXT NOT NULL,
    cvss_score      DECIMAL(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    published_date  DATE NOT NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- VULN_AFFECTED_VERSIONS  (which package versions a CVE applies to)
-- ---------------------------------------------------------------------
CREATE TABLE vuln_affected_versions (
    id                     CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    vulnerability_id       CHAR(36) NOT NULL,
    package_version_id     CHAR(36) NOT NULL,
    version_range          VARCHAR(100),
    UNIQUE KEY uq_vuln_pkgver (vulnerability_id, package_version_id),
    CONSTRAINT fk_vav_vuln   FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    CONSTRAINT fk_vav_pkgver FOREIGN KEY (package_version_id) REFERENCES package_versions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- ALERTS  (auto-generated when a CVE impacts a project; see trigger)
-- ---------------------------------------------------------------------
CREATE TABLE alerts (
    id                  CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    project_id          CHAR(36) NOT NULL,
    vulnerability_id    CHAR(36) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open', 'acknowledged', 'resolved')),
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_project_vuln (project_id, vulnerability_id),
    CONSTRAINT fk_alerts_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT fk_alerts_vuln    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- RISK_SNAPSHOTS  (historical aggregate risk score per project)
-- ---------------------------------------------------------------------
CREATE TABLE risk_snapshots (
    id              CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    project_id      CHAR(36) NOT NULL,
    score           DECIMAL(5,2) NOT NULL,
    computed_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_risk_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- =====================================================================
-- INDEXES (beyond the automatic ones on PK / UNIQUE constraints)
-- =====================================================================
CREATE INDEX idx_package_versions_package_id ON package_versions(package_id);
CREATE INDEX idx_project_dependencies_project_id ON project_dependencies(project_id);
CREATE INDEX idx_project_dependencies_pkg_version_id ON project_dependencies(package_version_id);
CREATE INDEX idx_vuln_affected_versions_vuln_id ON vuln_affected_versions(vulnerability_id);
CREATE INDEX idx_vuln_affected_versions_pkg_version_id ON vuln_affected_versions(package_version_id);
CREATE INDEX idx_alerts_project_id ON alerts(project_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_risk_snapshots_project_id ON risk_snapshots(project_id);
CREATE INDEX idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score);

-- =====================================================================
-- SCHEMA EVOLUTION (DDL)
-- =====================================================================
ALTER TABLE projects ADD COLUMN description VARCHAR(500);

-- =====================================================================
-- VIEW: current risk exposure per project
-- =====================================================================
DROP VIEW IF EXISTS project_risk_overview;

CREATE VIEW project_risk_overview AS
SELECT
    p.id AS project_id,
    p.name AS project_name,
    COUNT(DISTINCT CASE
        WHEN a.status = 'open' THEN v.id
    END) AS open_vulnerability_count,
    COALESCE(MAX(CASE
        WHEN a.status = 'open' THEN v.cvss_score
    END), 0) AS max_cvss_score,
    COALESCE(ROUND(AVG(CASE
        WHEN a.status = 'open' THEN v.cvss_score
    END), 2), 0) AS avg_cvss_score
FROM projects p
LEFT JOIN alerts a
    ON a.project_id = p.id
LEFT JOIN vulnerabilities v
    ON v.id = a.vulnerability_id
GROUP BY p.id, p.name;

-- =====================================================================
-- END OF DDL-ONLY FILE
-- Review 2 programmable objects, DML, dependent view, and query demos
-- are in SDVIT_REVIEW2_DML_TRIGGERS_FUNCTIONS_PROCEDURES.sql
-- =====================================================================
