-- =====================================================================
-- Threat-hunting queries over authentication and firewall logs
-- Written for SQLite / MySQL-style SQL. Load the sample CSVs with
-- `python sql/load_to_sqlite.py` and run with: sqlite3 logs.db < sql/hunting_queries.sql
-- =====================================================================

.headers on
.mode column

-- 1. Which source IPs generate the most failed Windows logons? ---------
--    (Event 4625, ATT&CK T1110)
SELECT IpAddress            AS source_ip,
       COUNT(*)             AS failures,
       COUNT(DISTINCT TargetUserName) AS accounts_targeted,
       MIN(TimeCreated)     AS first_seen,
       MAX(TimeCreated)     AS last_seen
FROM   windows_security
WHERE  EventID = 4625
GROUP  BY IpAddress
HAVING COUNT(*) >= 5
ORDER  BY failures DESC;

-- 2. Password spray signature: many accounts, few attempts each ---------
SELECT IpAddress AS source_ip,
       COUNT(DISTINCT TargetUserName)                       AS accounts,
       ROUND(1.0 * COUNT(*) / COUNT(DISTINCT TargetUserName), 1) AS attempts_per_account
FROM   windows_security
WHERE  EventID = 4625
GROUP  BY IpAddress
HAVING COUNT(DISTINCT TargetUserName) >= 5
   AND 1.0 * COUNT(*) / COUNT(DISTINCT TargetUserName) <= 2;

-- 3. Failures followed by a success from the same IP (possible compromise)
SELECT f.IpAddress           AS source_ip,
       COUNT(DISTINCT f.rowid) AS failures_before,
       s.TargetUserName      AS account_logged_in,
       s.TimeCreated         AS success_time
FROM   windows_security f
JOIN   windows_security s
       ON  s.IpAddress = f.IpAddress
       AND s.EventID   = 4624
       AND s.TimeCreated > f.TimeCreated
WHERE  f.EventID = 4625
GROUP  BY f.IpAddress, s.TargetUserName, s.TimeCreated
HAVING COUNT(DISTINCT f.rowid) >= 5;

-- 4. Account lockouts (status 0xC0000234) --------------------------------
SELECT TargetUserName, IpAddress, COUNT(*) AS lockout_events, MIN(TimeCreated) AS first_lockout
FROM   windows_security
WHERE  EventID = 4625 AND Status = '0xC0000234'
GROUP  BY TargetUserName, IpAddress;

-- 5. Hosts touching many ports on one target (vertical scan, T1046) ------
SELECT src_ip, dst_ip,
       COUNT(DISTINCT dst_port) AS distinct_ports,
       SUM(CASE WHEN action = 'DENY' THEN 1 ELSE 0 END) AS denied,
       MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
FROM   firewall
GROUP  BY src_ip, dst_ip
HAVING COUNT(DISTINCT dst_port) >= 20
ORDER  BY distinct_ports DESC;

-- 6. One port probed across many hosts (horizontal sweep) ---------------
SELECT src_ip, dst_port, COUNT(DISTINCT dst_ip) AS hosts_probed
FROM   firewall
GROUP  BY src_ip, dst_port
HAVING COUNT(DISTINCT dst_ip) >= 10
ORDER  BY hosts_probed DESC;

-- 7. Logons outside business hours (07:00-19:00) ------------------------
SELECT TargetUserName, IpAddress, TimeCreated
FROM   windows_security
WHERE  EventID = 4624
  AND  (CAST(strftime('%H', TimeCreated) AS INTEGER) < 7
     OR CAST(strftime('%H', TimeCreated) AS INTEGER) >= 19)
ORDER  BY TimeCreated;
