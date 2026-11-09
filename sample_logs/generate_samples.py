"""
Generate SYNTHETIC sample logs for testing the detections.

All IPs, hosts and users are fictional. 203.0.113.0/24 and 198.51.100.0/24 are
RFC 5737 documentation ranges, so nothing here points at a real system.

    python sample_logs/generate_samples.py
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
OUT = Path(__file__).parent
BASE = datetime(2026, 11, 3, 9, 0, 0)


def auth_log() -> None:
    lines = []

    def add(ts: datetime, msg: str) -> None:
        lines.append((ts, f"{ts:%b %e %H:%M:%S} lab-ubuntu sshd[{random.randint(1000, 9999)}]: {msg}"))

    # Normal admin activity
    for i in range(6):
        t = BASE + timedelta(minutes=17 * i)
        add(t, f"Accepted publickey for analyst from 10.0.2.15 port {random.randint(40000, 60000)} ssh2")
    # A user mistyping once - should NOT alert
    add(BASE + timedelta(minutes=40), "Failed password for analyst from 10.0.2.15 port 51234 ssh2")

    # Attacker 1: fast guessing against common users, then SUCCESS (HIGH)
    t = BASE + timedelta(hours=1, minutes=5)
    for i, user in enumerate(["root", "admin", "root", "ubuntu", "test", "root", "admin", "guest", "root", "labadmin", "labadmin", "labadmin"]):
        prefix = "invalid user " if user in {"admin", "test", "guest", "ubuntu"} else ""
        add(t + timedelta(seconds=7 * i), f"Failed password for {prefix}{user} from 203.0.113.45 port {50000 + i} ssh2")
    add(t + timedelta(seconds=7 * 12 + 3), "Accepted password for labadmin from 203.0.113.45 port 50013 ssh2")

    # Attacker 2: slow and low, 4 tries - below threshold, should NOT alert
    t = BASE + timedelta(hours=2)
    for i in range(4):
        add(t + timedelta(minutes=10 * i), f"Failed password for root from 198.51.100.77 port {41000 + i} ssh2")

    # Attacker 3: burst of 8, no success (MEDIUM)
    t = BASE + timedelta(hours=3, minutes=12)
    for i in range(8):
        add(t + timedelta(seconds=5 * i), f"Failed password for invalid user oracle from 203.0.113.200 port {42000 + i} ssh2")

    lines.sort()
    (OUT / "auth.log").write_text("\n".join(l for _, l in lines) + "\n")


def windows_security() -> None:
    rows = []

    def add(ts, eid, user, ip, ltype="3", status=""):
        rows.append([ts.isoformat(sep=" "), eid, user, ip, ltype, status])

    users = ["j.smith", "a.khan", "m.jones", "s.patel", "r.brown", "l.wilson", "administrator", "svc_backup"]
    # Normal day
    for i in range(30):
        u = random.choice(users[:6])
        add(BASE + timedelta(minutes=9 * i), 4624, u, f"10.0.2.{random.randint(20, 40)}", "2")
    add(BASE + timedelta(minutes=33), 4625, "m.jones", "10.0.2.31", "2", "0xC000006A")
    # Off-hours interactive logon by a service account - worth a look (hunting query 7)
    add(BASE - timedelta(hours=6, minutes=46), 4624, "svc_backup", "10.0.2.57", "10")

    # Password spray: one password tried against every account from one host
    t = BASE + timedelta(hours=4)
    for i, u in enumerate(users + ["guest", "helpdesk"]):
        status = "0xC0000064" if u in {"guest", "helpdesk"} else "0xC000006A"
        add(t + timedelta(seconds=20 * i), 4625, u, "10.0.2.99", "3", status)
    add(t + timedelta(minutes=5), 4624, "s.patel", "10.0.2.99", "3")

    # Brute force against administrator until lockout
    t = BASE + timedelta(hours=5)
    for i in range(14):
        status = "0xC0000234" if i >= 10 else "0xC000006A"
        add(t + timedelta(seconds=3 * i), 4625, "administrator", "198.51.100.23", "10", status)

    rows.sort()
    with open(OUT / "windows_security.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["TimeCreated", "EventID", "TargetUserName", "IpAddress", "LogonType", "Status"])
        w.writerows(rows)


def firewall() -> None:
    rows = []
    # Normal traffic
    for i in range(80):
        rows.append([BASE + timedelta(seconds=37 * i), f"10.0.2.{random.randint(20, 40)}",
                     random.choice(["10.0.2.10", "10.0.2.11"]), random.choice([53, 80, 443, 445]), "ALLOW"])
    # Vertical scan (nmap top ports) from Kali against the Windows server
    t = BASE + timedelta(hours=6)
    open_ports = {53, 88, 135, 139, 389, 445, 3389}
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 465, 587,
                              636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 8080, 8443]):
        rows.append([t + timedelta(milliseconds=300 * i), "10.0.2.66", "10.0.2.10", port,
                     "ALLOW" if port in open_ports else "DENY"])
    # Horizontal sweep for SMB across the subnet
    t = BASE + timedelta(hours=6, minutes=30)
    for i in range(15):
        rows.append([t + timedelta(seconds=2 * i), "10.0.2.66", f"10.0.2.{100 + i}", 445, "DENY"])

    rows.sort()
    with open(OUT / "firewall.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "action"])
        for r in rows:
            w.writerow([r[0].isoformat(sep=" ", timespec="milliseconds"), *r[1:]])


if __name__ == "__main__":
    auth_log()
    windows_security()
    firewall()
    print("Wrote auth.log, windows_security.csv, firewall.csv")
