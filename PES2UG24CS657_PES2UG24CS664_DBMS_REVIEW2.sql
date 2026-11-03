-- =====================================================================
-- SDVIT | DBMS Review 2 | DML + Triggers / Functions / Procedures
-- =====================================================================
USE sdvitsystem;

-- =====================================================================
-- PART A: TRIGGERS / FUNCTIONS / PROCEDURES / SUPPORTING VIEW
-- =====================================================================

-- =====================================================================
-- STORED PROCEDURE: recompute and store a project's risk score
-- (MySQL uses procedures, not functions returning a value the same
-- way Postgres does, for this kind of "do work + insert" logic)
-- =====================================================================
DROP PROCEDURE IF EXISTS recompute_project_risk;

DELIMITER $$

CREATE PROCEDURE recompute_project_risk(IN p_project_id CHAR(36))
BEGIN
    DECLARE v_score DECIMAL(5,2);

    SELECT COALESCE(SUM(cvss_score), 0)
    INTO v_score
    FROM (
        SELECT DISTINCT
            v.id,
            v.cvss_score
        FROM alerts a
        JOIN vulnerabilities v
            ON v.id = a.vulnerability_id
        WHERE a.project_id = p_project_id
          AND a.status = 'open'
    ) AS open_vulns;

    INSERT INTO risk_snapshots
        (project_id, score, computed_at)
    VALUES
        (p_project_id, v_score, NOW());

    SELECT v_score AS computed_score;
END$$

DELIMITER ;

-- =====================================================================
-- TRIGGER: when a new CVE is linked to an affected package version,
-- auto-create alerts for every project depending on that version
-- (only for CVSS >= 7.0 -- "high" severity threshold)
-- =====================================================================
DELIMITER $$

CREATE TRIGGER trg_alert_on_new_vuln_affected_version
AFTER INSERT ON vuln_affected_versions
FOR EACH ROW
BEGIN
    DECLARE v_score DECIMAL(3,1);

    SELECT cvss_score INTO v_score
    FROM vulnerabilities WHERE id = NEW.vulnerability_id;

    IF v_score >= 7.0 THEN
        INSERT IGNORE INTO alerts (id, project_id, vulnerability_id, status)
        SELECT UUID(), pd.project_id, NEW.vulnerability_id, 'open'
        FROM project_dependencies pd
        WHERE pd.package_version_id = NEW.package_version_id;
    END IF;
END$$

DELIMITER ;

-- FUNCTION

DROP FUNCTION IF EXISTS get_vulnerability_severity;

DELIMITER $$

CREATE FUNCTION get_vulnerability_severity(
    p_cvss_score DECIMAL(3,1)
)
RETURNS VARCHAR(20)
DETERMINISTIC
BEGIN
    IF p_cvss_score >= 9.0 THEN
        RETURN 'Critical';
    ELSEIF p_cvss_score >= 7.0 THEN
        RETURN 'High';
    ELSEIF p_cvss_score >= 4.0 THEN
        RETURN 'Medium';
    ELSE
        RETURN 'Low';
    END IF;
END$$

DELIMITER ;

-- PROCEDURE

DROP PROCEDURE IF EXISTS get_project_vulnerability_report;

DELIMITER $$

CREATE PROCEDURE get_project_vulnerability_report(
    IN p_project_id CHAR(36)
)
BEGIN
    SELECT
        p.name AS project_name,
        v.cve_id,
        v.description,
        v.cvss_score,
        get_vulnerability_severity(v.cvss_score) AS severity,
        a.status AS alert_status,
        a.created_at AS alert_created_at
    FROM projects p
    JOIN alerts a
        ON a.project_id = p.id
    JOIN vulnerabilities v
        ON v.id = a.vulnerability_id
    WHERE p.id = p_project_id
    ORDER BY v.cvss_score DESC, a.created_at DESC;
END$$

DELIMITER ;

-- alert resolution trigger

DROP TRIGGER IF EXISTS trg_risk_snapshot_on_alert_resolved;

DELIMITER $$

CREATE TRIGGER trg_risk_snapshot_on_alert_resolved
AFTER UPDATE ON alerts
FOR EACH ROW
BEGIN
    DECLARE v_score DECIMAL(5,2);

    IF OLD.status <> 'resolved'
       AND NEW.status = 'resolved' THEN

        SELECT COALESCE(SUM(cvss_score), 0)
        INTO v_score
        FROM (
            SELECT DISTINCT
                v.id,
                v.cvss_score
            FROM alerts a
            JOIN vulnerabilities v
                ON v.id = a.vulnerability_id
            WHERE a.project_id = NEW.project_id
              AND a.status = 'open'
        ) AS open_vulns;

        INSERT INTO risk_snapshots
            (project_id, score, computed_at)
        VALUES
            (NEW.project_id, v_score, NOW());

    END IF;
END$$

DELIMITER ;

-- =====================================================================
-- PART A: NEW PROGRAMMABLE OBJECTS
-- =====================================================================
DELIMITER $$

-- A1. TRIGGER: alert when a project ADDS a dependency that is already
--     known to be vulnerable (covers the gap in trg_alert_on_new_vuln_affected_version)
DROP TRIGGER IF EXISTS trg_alert_on_new_dependency$$
CREATE TRIGGER trg_alert_on_new_dependency
AFTER INSERT ON project_dependencies
FOR EACH ROW
BEGIN
    INSERT IGNORE INTO alerts (id, project_id, vulnerability_id, status)
    SELECT UUID(), NEW.project_id, v.id, 'open'
    FROM vuln_affected_versions vav
    JOIN vulnerabilities v ON v.id = vav.vulnerability_id
    WHERE vav.package_version_id = NEW.package_version_id
      AND v.cvss_score >= 7.0;
END$$

-- A2. FUNCTION: number of open alerts for a project
DROP FUNCTION IF EXISTS get_open_alert_count$$
CREATE FUNCTION get_open_alert_count(p_project_id CHAR(36))
RETURNS INT
NOT DETERMINISTIC
READS SQL DATA
BEGIN
    DECLARE v_count INT DEFAULT 0;
    SELECT COUNT(*) INTO v_count
    FROM alerts
    WHERE project_id = p_project_id AND status = 'open';
    RETURN v_count;
END$$

-- A3. PROCEDURE with CURSOR: snapshot the risk score of every project
DROP PROCEDURE IF EXISTS recompute_all_project_risk$$
CREATE PROCEDURE recompute_all_project_risk(OUT p_projects_processed INT)
BEGIN
    DECLARE done INT DEFAULT 0;
    DECLARE v_pid CHAR(36);
    DECLARE v_score DECIMAL(5,2);
    DECLARE cur CURSOR FOR SELECT id FROM projects;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = 1;

    SET p_projects_processed = 0;
    OPEN cur;
    read_loop: LOOP
        FETCH cur INTO v_pid;
        IF done = 1 THEN
            LEAVE read_loop;
        END IF;

        SELECT COALESCE(SUM(cvss_score), 0) INTO v_score
        FROM (
            SELECT DISTINCT v.id, v.cvss_score
            FROM alerts a
            JOIN vulnerabilities v ON v.id = a.vulnerability_id
            WHERE a.project_id = v_pid AND a.status = 'open'
        ) AS open_vulns;

        INSERT INTO risk_snapshots (project_id, score) VALUES (v_pid, v_score);
        SET p_projects_processed = p_projects_processed + 1;
    END LOOP;
    CLOSE cur;
END$$

-- A4. PROCEDURE with TRANSACTION + ERROR HANDLING: resolve an alert
--     (status change + the snapshot written by trg_risk_snapshot_on_alert_resolved
--      commit together, or roll back together)
DROP PROCEDURE IF EXISTS resolve_alert$$
CREATE PROCEDURE resolve_alert(IN p_project_id CHAR(36), IN p_vulnerability_id CHAR(36))
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;

    IF NOT EXISTS (SELECT 1 FROM alerts
                   WHERE project_id = p_project_id
                     AND vulnerability_id = p_vulnerability_id
                     AND status <> 'resolved') THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'No open or acknowledged alert found for this project and CVE';
    END IF;

    UPDATE alerts
    SET status = 'resolved'
    WHERE project_id = p_project_id AND vulnerability_id = p_vulnerability_id;

    COMMIT;
END$$

DELIMITER ;

-- =====================================================================
-- VIEW: detailed project vulnerability information
-- Created after get_vulnerability_severity() because the view uses it.
-- =====================================================================
DROP VIEW IF EXISTS project_vulnerability_details;

CREATE VIEW project_vulnerability_details AS
SELECT
    p.id AS project_id,
    p.name AS project_name,
    pkg.name AS package_name,
    pkg.ecosystem,
    pv.version AS package_version,
    v.cve_id,
    v.description,
    v.cvss_score,
    get_vulnerability_severity(v.cvss_score) AS severity,
    a.status AS alert_status,
    a.created_at AS alert_created_at
FROM projects p
JOIN project_dependencies pd
    ON pd.project_id = p.id
JOIN package_versions pv
    ON pv.id = pd.package_version_id
JOIN packages pkg
    ON pkg.id = pv.package_id
JOIN vuln_affected_versions vav
    ON vav.package_version_id = pv.id
JOIN vulnerabilities v
    ON v.id = vav.vulnerability_id
JOIN alerts a
    ON a.project_id = p.id
   AND a.vulnerability_id = v.id;

-- =====================================================================
-- PART B: DML - SAMPLE DATA (INSERT)
-- Sample data for Review 2.
-- =====================================================================

-- B1. USERS
INSERT INTO users (id, name, email, password_hash, role) VALUES
('a0000000-0000-0000-0000-000000000001', 'Admin User', 'admin@sdvit.example',   'hashed_pw_placeholder', 'admin'),
('a0000000-0000-0000-0000-000000000002', 'Samaresh',   'samaresh@sdvit.example','hashed_pw_placeholder', 'developer'),
('a0000000-0000-0000-0000-000000000003', 'Asha Rao',   'asha@sdvit.example',    'hashed_pw_placeholder', 'developer');

-- B2. PROJECTS
INSERT INTO projects (id, owner_id, name, repo_url) VALUES
('b0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000002', 'payment-service', 'https://github.com/example/payment-service'),
('b0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000002', 'analytics-api',   'https://github.com/example/analytics-api'),
('b0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000003', 'mobile-backend',  'https://github.com/example/mobile-backend');

-- B3. PACKAGES
INSERT INTO packages (id, name, ecosystem) VALUES
('c0000000-0000-0000-0000-000000000001', 'lodash',     'npm'),
('c0000000-0000-0000-0000-000000000002', 'express',    'npm'),
('c0000000-0000-0000-0000-000000000003', 'requests',   'pypi'),
('c0000000-0000-0000-0000-000000000004', 'log4j-core', 'maven'),
('c0000000-0000-0000-0000-000000000005', 'django',     'pypi'),
('c0000000-0000-0000-0000-000000000006', 'serde',      'cargo');

-- B4. PACKAGE_VERSIONS  (release dates are sample values)
INSERT INTO package_versions (id, package_id, version, release_date) VALUES
('d0000000-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000001', '4.17.15', '2019-07-08'),
('d0000000-0000-0000-0000-000000000002', 'c0000000-0000-0000-0000-000000000001', '4.17.21', '2021-02-20'),
('d0000000-0000-0000-0000-000000000003', 'c0000000-0000-0000-0000-000000000002', '4.17.1',  '2019-05-25'),
('d0000000-0000-0000-0000-000000000004', 'c0000000-0000-0000-0000-000000000002', '4.18.2',  '2022-10-08'),
('d0000000-0000-0000-0000-000000000005', 'c0000000-0000-0000-0000-000000000003', '2.19.0',  '2018-06-12'),
('d0000000-0000-0000-0000-000000000006', 'c0000000-0000-0000-0000-000000000003', '2.31.0',  '2023-05-22'),
('d0000000-0000-0000-0000-000000000007', 'c0000000-0000-0000-0000-000000000004', '2.14.1',  '2021-03-06'),
('d0000000-0000-0000-0000-000000000008', 'c0000000-0000-0000-0000-000000000004', '2.17.1',  '2021-12-28'),
('d0000000-0000-0000-0000-000000000009', 'c0000000-0000-0000-0000-000000000005', '3.2.0',   '2021-04-06'),
('d0000000-0000-0000-0000-000000000010', 'c0000000-0000-0000-0000-000000000006', '1.0.130', '2021-09-09');

-- B5. PROJECT_DEPENDENCIES  (inserted BEFORE the CVEs so the
--     vuln_affected_versions trigger can find dependent projects)
INSERT INTO project_dependencies (project_id, package_version_id, dependency_type) VALUES
('b0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000007', 'direct'),      -- payment-service -> log4j-core 2.14.1
('b0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001', 'direct'),      -- payment-service -> lodash 4.17.15
('b0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000003', 'direct'),      -- payment-service -> express 4.17.1
('b0000000-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000005', 'direct'),      -- analytics-api   -> requests 2.19.0
('b0000000-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000009', 'direct'),      -- analytics-api   -> django 3.2.0
('b0000000-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000002', 'direct'),      -- analytics-api   -> lodash 4.17.21
('b0000000-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000004', 'direct'),      -- mobile-backend  -> express 4.18.2
('b0000000-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000006', 'direct'),      -- mobile-backend  -> requests 2.31.0
('b0000000-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000008', 'transitive'),  -- mobile-backend  -> log4j-core 2.17.1
('b0000000-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000010', 'dev');         -- mobile-backend  -> serde 1.0.130

-- B6. VULNERABILITIES  (real CVE ids, shortened descriptions)
INSERT INTO vulnerabilities (id, cve_id, description, cvss_score, published_date) VALUES
('f0000000-0000-0000-0000-000000000001', 'CVE-2021-44228', 'Log4Shell: remote code execution via JNDI lookups in log4j-core',            10.0, '2021-12-10'),
('f0000000-0000-0000-0000-000000000002', 'CVE-2020-8203',  'lodash prototype pollution in zipObjectDeep',                               7.4, '2020-07-15'),
('f0000000-0000-0000-0000-000000000003', 'CVE-2018-18074', 'requests sends Authorization header to a different host on redirect',       9.8, '2018-10-09'),
('f0000000-0000-0000-0000-000000000004', 'CVE-2024-29041', 'express open redirect via malformed URLs',                                  6.1, '2024-03-25'),
('f0000000-0000-0000-0000-000000000005', 'CVE-2021-35042', 'Django SQL injection through QuerySet.order_by',                            9.8, '2021-07-02');

-- B7. VULN_AFFECTED_VERSIONS  -> fires trg_alert_on_new_vuln_affected_version
--     (alerts are auto-created only where CVSS >= 7.0)
INSERT INTO vuln_affected_versions (vulnerability_id, package_version_id, version_range) VALUES
('f0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000007', '>=2.0-beta9 <2.15.0'),
('f0000000-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000001', '<4.17.19'),
('f0000000-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000005', '<2.20.0'),
('f0000000-0000-0000-0000-000000000004', 'd0000000-0000-0000-0000-000000000003', '<4.19.2'),
('f0000000-0000-0000-0000-000000000004', 'd0000000-0000-0000-0000-000000000004', '<4.19.2'),
('f0000000-0000-0000-0000-000000000005', 'd0000000-0000-0000-0000-000000000009', '>=3.2 <3.2.5');

-- =====================================================================
-- PART C: TRIGGER DEMOS (before / after)
-- =====================================================================

-- C1. trg_alert_on_new_vuln_affected_version
--     Alerts were created automatically when the CVEs were linked to versions.
--     Expect 4 rows; CVE-2024-29041 (CVSS 6.1) correctly produced NO alert.
SELECT p.name AS project, v.cve_id, v.cvss_score, a.status
FROM alerts a
JOIN projects p ON p.id = a.project_id
JOIN vulnerabilities v ON v.id = a.vulnerability_id
ORDER BY p.name, v.cvss_score DESC;

-- C2. trg_alert_on_new_dependency
--     BEFORE: mobile-backend has no alerts (empty set)
SELECT p.name AS project, v.cve_id, a.status
FROM alerts a
JOIN projects p ON p.id = a.project_id
JOIN vulnerabilities v ON v.id = a.vulnerability_id
WHERE p.name = 'mobile-backend';

--     ACTION: mobile-backend adds the known-vulnerable lodash 4.17.15
INSERT INTO project_dependencies (project_id, package_version_id, dependency_type)
VALUES ('b0000000-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000001', 'direct');

--     AFTER: the alert now exists (created by the trigger, not by hand)
SELECT p.name AS project, v.cve_id, a.status
FROM alerts a
JOIN projects p ON p.id = a.project_id
JOIN vulnerabilities v ON v.id = a.vulnerability_id
WHERE p.name = 'mobile-backend';

-- =====================================================================
-- PART D: FUNCTION, PROCEDURE AND TRANSACTION DEMOS
-- =====================================================================

-- D1. Cursor procedure: one snapshot per project
--     expected scores: payment-service 17.40, analytics-api 19.60, mobile-backend 7.40
CALL recompute_all_project_risk(@projects_processed);
SELECT @projects_processed AS projects_processed;

-- D2. Single-project procedure (payment-service: 10.0 + 7.4 = 17.40)
CALL recompute_project_risk('b0000000-0000-0000-0000-000000000001');

-- D3. Transactional procedure: resolve the lodash alert on payment-service.
--     The trigger writes a new snapshot (10.00) inside the same transaction.
--     SLEEP(1) makes sure this snapshot has a later timestamp than the ones above.
DO SLEEP(1);
CALL resolve_alert('b0000000-0000-0000-0000-000000000001', 'f0000000-0000-0000-0000-000000000002');

-- D4. Latest risk snapshot for payment-service (expect 10.00)
SELECT p.name, rs.score, rs.computed_at
FROM risk_snapshots rs
JOIN projects p ON p.id = rs.project_id
WHERE p.name = 'payment-service'
ORDER BY rs.computed_at DESC
LIMIT 1;

-- D5. Error handling: run this line BY ITSELF (it fails on purpose and would
--     stop a script run) - the alert is already resolved, so the handler rolls back.
-- CALL resolve_alert('b0000000-0000-0000-0000-000000000001', 'f0000000-0000-0000-0000-000000000002');
-- Expected: ERROR 1644 (45000): No open or acknowledged alert found for this project and CVE

-- D6. Report procedure
CALL get_project_vulnerability_report('b0000000-0000-0000-0000-000000000002');

-- D7. Functions
SELECT cve_id, cvss_score, get_vulnerability_severity(cvss_score) AS severity
FROM vulnerabilities
ORDER BY cvss_score DESC;

SELECT name AS project, get_open_alert_count(id) AS open_alerts
FROM projects
ORDER BY open_alerts DESC;

-- D8. Explicit transaction with ROLLBACK (atomicity demo)
--     Resolving the Log4Shell alert fires the snapshot trigger; ROLLBACK undoes BOTH.
START TRANSACTION;

UPDATE alerts
SET status = 'resolved'
WHERE project_id = 'b0000000-0000-0000-0000-000000000001'
  AND vulnerability_id = 'f0000000-0000-0000-0000-000000000001';

SELECT status AS status_inside_transaction
FROM alerts
WHERE project_id = 'b0000000-0000-0000-0000-000000000001'
  AND vulnerability_id = 'f0000000-0000-0000-0000-000000000001';      -- resolved

SELECT COUNT(*) AS snapshots_inside_transaction
FROM risk_snapshots
WHERE project_id = 'b0000000-0000-0000-0000-000000000001';             -- one more

ROLLBACK;

SELECT status AS status_after_rollback
FROM alerts
WHERE project_id = 'b0000000-0000-0000-0000-000000000001'
  AND vulnerability_id = 'f0000000-0000-0000-0000-000000000001';      -- open again

SELECT COUNT(*) AS snapshots_after_rollback
FROM risk_snapshots
WHERE project_id = 'b0000000-0000-0000-0000-000000000001';             -- back to the earlier count

-- =====================================================================
-- PART E: UPDATE / DELETE
-- =====================================================================

-- E1. UPDATE: acknowledge the requests alert on analytics-api
UPDATE alerts
SET status = 'acknowledged'
WHERE project_id = 'b0000000-0000-0000-0000-000000000002'
  AND vulnerability_id = 'f0000000-0000-0000-0000-000000000003';

SELECT status, COUNT(*) AS alerts
FROM alerts
GROUP BY status;                                   -- acknowledged 1, open 3, resolved 1

-- E2. DELETE: remove a dev dependency
DELETE FROM project_dependencies
WHERE project_id = 'b0000000-0000-0000-0000-000000000003'
  AND package_version_id = 'd0000000-0000-0000-0000-000000000010';

-- E3. DELETE with ON DELETE CASCADE: removing a package removes its versions
INSERT INTO packages (id, name, ecosystem) VALUES ('c0000000-0000-0000-0000-000000000099', 'temp-pkg', 'other');
INSERT INTO package_versions (package_id, version) VALUES ('c0000000-0000-0000-0000-000000000099', '0.0.1');
DELETE FROM packages WHERE id = 'c0000000-0000-0000-0000-000000000099';

SELECT COUNT(*) AS leftover_versions
FROM package_versions
WHERE package_id = 'c0000000-0000-0000-0000-000000000099';   -- expect 0

-- =====================================================================
-- PART F: QUERIES
-- =====================================================================

-- F1. Basic SELECT
SELECT * FROM users;
SELECT * FROM projects;

-- F2. WHERE
SELECT cve_id, cvss_score, published_date
FROM vulnerabilities
WHERE cvss_score >= 7.0;

-- F3. ORDER BY
SELECT cve_id, cvss_score, published_date
FROM vulnerabilities
ORDER BY published_date DESC;

-- F4. JOIN: project vulnerabilities and alert status
SELECT p.name AS project, v.cve_id, v.cvss_score, a.status
FROM alerts a
JOIN projects p ON p.id = a.project_id
JOIN vulnerabilities v ON v.id = a.vulnerability_id
ORDER BY p.name, v.cvss_score DESC;

-- F5. VIEW: detailed project vulnerability information
SELECT project_name, package_name, ecosystem, package_version, cve_id, severity, alert_status
FROM project_vulnerability_details
ORDER BY project_name, cvss_score DESC;

-- F6. GROUP BY + COUNT + HAVING + ORDER BY
SELECT p.name, COUNT(a.id) AS open_high_alerts
FROM projects p
JOIN alerts a ON a.project_id = p.id
JOIN vulnerabilities v ON v.id = a.vulnerability_id
WHERE a.status = 'open'
  AND v.cvss_score >= 7.0
GROUP BY p.name
HAVING COUNT(a.id) >= 1
ORDER BY open_high_alerts DESC;

-- F7. Aggregates: COUNT, AVG, MIN, MAX per ecosystem
SELECT pkg.ecosystem,
       COUNT(DISTINCT v.id)        AS cve_count,
       ROUND(AVG(v.cvss_score), 2) AS avg_cvss,
       MIN(v.cvss_score)           AS min_cvss,
       MAX(v.cvss_score)           AS max_cvss
FROM packages pkg
JOIN package_versions pv ON pv.package_id = pkg.id
JOIN vuln_affected_versions vav ON vav.package_version_id = pv.id
JOIN vulnerabilities v ON v.id = vav.vulnerability_id
GROUP BY pkg.ecosystem
ORDER BY avg_cvss DESC;

-- F8. LEFT JOIN: dependency count per project
SELECT p.name AS project, COUNT(pd.id) AS dependency_count
FROM projects p
LEFT JOIN project_dependencies pd ON pd.project_id = p.id
GROUP BY p.id, p.name
ORDER BY p.name;

-- F9. UNION ALL: severity classification
SELECT cve_id, cvss_score, 'Critical' AS bucket
FROM vulnerabilities
WHERE cvss_score >= 9.0
UNION ALL
SELECT cve_id, cvss_score, 'High' AS bucket
FROM vulnerabilities
WHERE cvss_score >= 7.0 AND cvss_score < 9.0
ORDER BY cvss_score DESC;

-- F10. Nested query: CVEs scoring above the average
SELECT cve_id, cvss_score
FROM vulnerabilities
WHERE cvss_score > (SELECT AVG(cvss_score) FROM vulnerabilities)
ORDER BY cvss_score DESC;

-- F11. NOT EXISTS: package versions with no known CVE
SELECT pkg.name, pv.version
FROM package_versions pv
JOIN packages pkg ON pkg.id = pv.package_id
WHERE NOT EXISTS (SELECT 1
                  FROM vuln_affected_versions vav
                  WHERE vav.package_version_id = pv.id)
ORDER BY pkg.name, pv.version;

-- F12. Risk view
SELECT * FROM project_risk_overview;

-- =====================================================================
-- PART G: SCHEMA, INDEX AND OBJECT VERIFICATION
-- =====================================================================

-- G1. ALTER TABLE result (the ALTER itself is in SDVIT_DDL_ONLY.sql)
DESC projects;

-- G2. Indexes
SHOW INDEX FROM projects;
SHOW INDEX FROM alerts;
SHOW INDEX FROM package_versions;

-- G3. An index in use (look at the "key" column of the plan)
EXPLAIN SELECT * FROM alerts WHERE status = 'open';

-- G4. Row counts
SELECT 'users' AS table_name, COUNT(*) AS row_count FROM users
UNION ALL SELECT 'projects', COUNT(*) FROM projects
UNION ALL SELECT 'packages', COUNT(*) FROM packages
UNION ALL SELECT 'package_versions', COUNT(*) FROM package_versions
UNION ALL SELECT 'project_dependencies', COUNT(*) FROM project_dependencies
UNION ALL SELECT 'vulnerabilities', COUNT(*) FROM vulnerabilities
UNION ALL SELECT 'vuln_affected_versions', COUNT(*) FROM vuln_affected_versions
UNION ALL SELECT 'alerts', COUNT(*) FROM alerts
UNION ALL SELECT 'risk_snapshots', COUNT(*) FROM risk_snapshots;

-- G5. Inventories: 3 triggers, 2 functions, 4 procedures, 2 views
SELECT TRIGGER_NAME, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, ACTION_TIMING
FROM information_schema.TRIGGERS
WHERE TRIGGER_SCHEMA = 'sdvitsystem';

SELECT ROUTINE_NAME, ROUTINE_TYPE
FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA = 'sdvitsystem'
ORDER BY ROUTINE_TYPE, ROUTINE_NAME;

SHOW FULL TABLES WHERE Table_type = 'VIEW';
