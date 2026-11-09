# 🔎 Log Analysis Toolkit for SOC Triage

Python and SQL detections for three of the most common alerts a Tier-1 SOC analyst triages, each mapped to MITRE ATT&CK and tested against reproducible sample logs.

I built this to bring my 4+ years of SQL and Python data-analysis experience to security operations: the same skills (grouping, windowing, spotting outliers) power SIEM searches and threat hunting.

| Detection | Log source | ATT&CK | What it catches |
|---|---|---|---|
| [`ssh_bruteforce.py`](detections/ssh_bruteforce.py) | Linux `auth.log` | T1110.001 | Bursts of failed SSH logins per IP in a sliding window; **escalates to HIGH if the same IP then logs in successfully** |
| [`windows_failed_logons.py`](detections/windows_failed_logons.py) | Windows Security log (4624/4625) | T1110.001, T1110.003 | Separates **brute force** (one account, many tries) from **password spraying** (many accounts, few tries), decodes status codes, flags successful logons afterwards |
| [`port_scan.py`](detections/port_scan.py) | Firewall / connection logs | T1046 | **Vertical** scans (many ports, one host) and **horizontal** sweeps (one port, many hosts), and lists which ports answered |
| [`hunting_queries.sql`](sql/hunting_queries.sql) | Same data in SQLite | T1110, T1046 | 7 hunting queries: top failing IPs, spray signature, fail-then-succeed, lockouts, scans, off-hours logons |

## Example output

```text
$ python detections/ssh_bruteforce.py sample_logs/auth.log --year 2026
[HIGH] SSH brute force from 203.0.113.45: 12 failures between 10:05:00 and 10:06:17; users tried: admin, guest, labadmin, root, test, ubuntu
         !! Successful login as 'labadmin' at 10:06:27 from the same IP - investigate immediately
[MEDIUM] SSH brute force from 203.0.113.200: 8 failures between 12:12:00 and 12:12:35; users tried: oracle

$ python detections/windows_failed_logons.py sample_logs/windows_security.csv
[HIGH] Password spraying (T1110.003) from 10.0.2.99
         10 failures across 10 account(s): j.smith, a.khan, m.jones, s.patel, r.brown
         2026-11-03 13:00:00 -> 13:03:00 | wrong password=8, unknown user=2
         !! Successful logon afterwards: s.patel at 13:05:00 - investigate immediately
[MEDIUM] Brute force (T1110.001) from 198.51.100.23
         14 failures across 1 account(s): administrator
         2026-11-03 14:00:00 -> 14:00:39 | wrong password=10, account locked=4

$ python detections/port_scan.py sample_logs/firewall.csv
[ALERT] Vertical port scan from 10.0.2.66 -> 10.0.2.10: 28 ports in 8s (deny ratio 0.75)
        Ports that answered (ALLOW): [53, 88, 135, 139, 389, 445, 3389]
[ALERT] Horizontal sweep from 10.0.2.66 -> port 445: 15 hosts in 28s (deny ratio 0.94)
```

## Design choices (and how I'd triage each alert)

- **Sliding time windows, not daily totals.** 50 failures spread over a day is a forgetful user; 12 in 77 seconds is a tool. The window and threshold are command-line options so they can be tuned to an environment's baseline.
- **Fail → success correlation.** A brute-force alert with no success is noise to log and block; one followed by a successful logon is a potential compromise. That's the difference between MEDIUM and HIGH, and it's the first thing I'd check in the SIEM.
- **Spraying vs brute force.** Spraying stays under lockout thresholds, so per-account rules miss it. Grouping by source IP and counting *distinct* accounts catches it.
- **Benign cases are in the sample data on purpose:** an admin's single typo and a slow 4-attempt attacker below threshold. The tests check these do **not** alert, which keeps false positives in check.

**Triage checklist for a HIGH alert:**
1. Is the source IP internal or external? Known scanner, VPN, or threat-intel hit?
2. What did the account do after logging in (process creation, new services, lateral movement)?
3. Contain: disable/reset the account, block the IP, isolate the host if needed.
4. Document the timeline and escalate per the playbook.

## Run it

```bash
pip install -r requirements.txt
python sample_logs/generate_samples.py      # regenerate the synthetic logs
python -m pytest -q                         # 4 tests
python detections/ssh_bruteforce.py sample_logs/auth.log --year 2026
python sql/load_to_sqlite.py && sqlite3 logs.db < sql/hunting_queries.sql
```

## Using it on real lab data

- **Linux:** copy `/var/log/auth.log` from the Ubuntu VM (use `--year` for syslog timestamps).
- **Windows:** export from PowerShell:
  ```powershell
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} |
    Select TimeCreated, Id, @{n='TargetUserName';e={$_.Properties[5].Value}},
           @{n='IpAddress';e={$_.Properties[19].Value}}, @{n='LogonType';e={$_.Properties[10].Value}},
           @{n='Status';e={'0x{0:X}' -f $_.Properties[7].Value}} |
    Export-Csv security.csv -NoTypeInformation
  ```
  then rename the `Id` column to `EventID`.
- **Wazuh:** the same logic can be expressed as Wazuh rules with `frequency` / `timeframe`. See my [soc-home-lab](https://github.com/chahat-24/soc-home-lab) repo.

## About the sample data

All logs in `sample_logs/` are **synthetic**, produced by [`generate_samples.py`](sample_logs/generate_samples.py) with a fixed seed. External IPs use the RFC 5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24), and all hosts and users are fictional.
