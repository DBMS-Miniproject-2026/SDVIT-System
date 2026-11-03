-- =====================================================================
-- SDVIT | App extension | one extra procedure used by the web app
-- Run AFTER SDVIT_DDL_ONLY.sql and the Review 2 script.
-- =====================================================================
USE sdvitsystem;

-- Mirrors resolve_alert(): a transaction with error handling that moves an
-- open alert to 'acknowledged'. Used by the "Acknowledge" button.
DROP PROCEDURE IF EXISTS acknowledge_alert;

DELIMITER $$

CREATE PROCEDURE acknowledge_alert(IN p_project_id CHAR(36), IN p_vulnerability_id CHAR(36))
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
                   AND status = 'open') THEN
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'No open alert found for this project and CVE';
  END IF;

  UPDATE alerts
  SET status = 'acknowledged'
  WHERE project_id = p_project_id AND vulnerability_id = p_vulnerability_id;

  COMMIT;
END$$

DELIMITER ;
