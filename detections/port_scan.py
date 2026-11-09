"""
Detect port scans in firewall / connection logs.

MITRE ATT&CK: T1046 - Network Service Discovery

Input
-----
CSV with columns: timestamp, src_ip, dst_ip, dst_port, action
(action is ALLOW or DENY). Exports from pfSense, Windows Firewall logs,
Zeek conn.log or a SIEM search can be reshaped into this format.

Logic
-----
* Vertical scan   - one source hits >= --ports distinct ports on ONE host
                    within --window seconds (classic `nmap -p-` against a target).
* Horizontal scan - one source hits the SAME port on >= --hosts distinct hosts
                    (sweeping a subnet for e.g. SMB/445 or RDP/3389).
* A high DENY ratio is typical of scanning and is reported for context.

Usage
-----
    python detections/port_scan.py sample_logs/firewall.csv
"""

from __future__ import annotations

import argparse

import pandas as pd


def load(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp")


def _max_distinct_in_window(times: pd.Series, values: pd.Series, window: pd.Timedelta) -> tuple[int, pd.Timestamp, pd.Timestamp]:
    t = times.to_list()
    v = values.to_list()
    best = (0, t[0], t[0])
    start = 0
    for end in range(len(t)):
        while t[end] - t[start] > window:
            start += 1
        n = len(set(v[start : end + 1]))
        if n > best[0]:
            best = (n, t[start], t[end])
    return best


def detect(df: pd.DataFrame, ports: int = 20, hosts: int = 10, window_s: int = 60) -> list[dict]:
    window = pd.Timedelta(seconds=window_s)
    findings: list[dict] = []

    for (src, dst), grp in df.groupby(["src_ip", "dst_ip"]):
        n, first, last = _max_distinct_in_window(grp["timestamp"], grp["dst_port"], window)
        if n >= ports:
            findings.append(
                {
                    "type": "Vertical port scan",
                    "src_ip": src,
                    "target": dst,
                    "distinct": n,
                    "first_seen": first,
                    "last_seen": last,
                    "deny_ratio": round((grp["action"].str.upper() == "DENY").mean(), 2),
                    "open_ports": sorted(grp.loc[grp["action"].str.upper() == "ALLOW", "dst_port"].unique().tolist()),
                }
            )

    for (src, port), grp in df.groupby(["src_ip", "dst_port"]):
        n, first, last = _max_distinct_in_window(grp["timestamp"], grp["dst_ip"], window)
        if n >= hosts:
            findings.append(
                {
                    "type": "Horizontal sweep",
                    "src_ip": src,
                    "target": f"port {port}",
                    "distinct": n,
                    "first_seen": first,
                    "last_seen": last,
                    "deny_ratio": round((grp["action"].str.upper() == "DENY").mean(), 2),
                    "open_ports": [],
                }
            )

    return sorted(findings, key=lambda f: -f["distinct"])


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv")
    p.add_argument("--ports", type=int, default=20, help="distinct ports on one host to alert")
    p.add_argument("--hosts", type=int, default=10, help="distinct hosts on one port to alert")
    p.add_argument("--window", type=int, default=60, help="window in seconds")
    args = p.parse_args()

    findings = detect(load(args.csv), args.ports, args.hosts, args.window)
    if not findings:
        print("No scanning activity found.")
    for f in findings:
        unit = "ports" if f["type"].startswith("Vertical") else "hosts"
        print(
            f"[ALERT] {f['type']} from {f['src_ip']} -> {f['target']}: {f['distinct']} {unit} "
            f"in {(f['last_seen'] - f['first_seen']).total_seconds():.0f}s (deny ratio {f['deny_ratio']})"
        )
        if f["open_ports"]:
            print(f"        Ports that answered (ALLOW): {f['open_ports']}")


if __name__ == "__main__":
    main()
