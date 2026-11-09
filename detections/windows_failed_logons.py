"""
Detect password spraying and brute force in Windows Security logs (Event ID 4625).

MITRE ATT&CK: T1110.003 - Password Spraying, T1110.001 - Password Guessing

Input
-----
A CSV export of Security events (e.g. from Event Viewer, `Get-WinEvent | Export-Csv`,
or a Wazuh/SIEM search) with at least these columns:

    TimeCreated, EventID, TargetUserName, IpAddress, LogonType, Status

Logic
-----
* Brute force   - one source IP, ONE account, many failures   (>= --bf-threshold)
* Password spray - one source IP, MANY accounts, few tries each (>= --spray-accounts)
* Any 4624 (success) from a flagged IP afterwards escalates the finding.

Status codes worth knowing:
    0xC000006A  wrong password (account exists)
    0xC0000064  user name does not exist
    0xC0000234  account locked out

Usage
-----
    python detections/windows_failed_logons.py sample_logs/windows_security.csv
"""

from __future__ import annotations

import argparse

import pandas as pd

STATUS_MEANING = {
    "0xC000006A": "wrong password",
    "0xC0000064": "unknown user",
    "0xC0000234": "account locked",
    "0xC0000072": "account disabled",
}


def load(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str)
    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"])
    df["EventID"] = df["EventID"].astype(int)
    return df.sort_values("TimeCreated")


def detect(df: pd.DataFrame, bf_threshold: int = 10, spray_accounts: int = 5) -> list[dict]:
    fails = df[df["EventID"] == 4625]
    wins = df[df["EventID"] == 4624]
    findings: list[dict] = []

    for ip, grp in fails.groupby("IpAddress"):
        per_user = grp["TargetUserName"].value_counts()
        n_users = per_user.size
        kind = None
        if n_users >= spray_accounts:
            kind = "Password spraying (T1110.003)"
        elif per_user.max() >= bf_threshold:
            kind = "Brute force (T1110.001)"
        if not kind:
            continue

        later_success = wins[(wins["IpAddress"] == ip) & (wins["TimeCreated"] >= grp["TimeCreated"].min())]
        findings.append(
            {
                "source_ip": ip,
                "type": kind,
                "failures": len(grp),
                "accounts_targeted": n_users,
                "top_accounts": ", ".join(per_user.head(5).index),
                "first_seen": grp["TimeCreated"].min(),
                "last_seen": grp["TimeCreated"].max(),
                "status_breakdown": ", ".join(
                    f"{STATUS_MEANING.get(s, s)}={c}" for s, c in grp["Status"].value_counts().items()
                ),
                "successful_logon_after": (
                    f"{later_success.iloc[0]['TargetUserName']} at {later_success.iloc[0]['TimeCreated']:%H:%M:%S}"
                    if not later_success.empty
                    else None
                ),
                "severity": "HIGH" if not later_success.empty else "MEDIUM",
            }
        )

    return sorted(findings, key=lambda f: (f["severity"] != "HIGH", -f["failures"]))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv")
    p.add_argument("--bf-threshold", type=int, default=10)
    p.add_argument("--spray-accounts", type=int, default=5)
    args = p.parse_args()

    findings = detect(load(args.csv), args.bf_threshold, args.spray_accounts)
    if not findings:
        print("No brute-force or spraying activity found.")
    for f in findings:
        print(f"[{f['severity']}] {f['type']} from {f['source_ip']}")
        print(f"         {f['failures']} failures across {f['accounts_targeted']} account(s): {f['top_accounts']}")
        print(f"         {f['first_seen']:%Y-%m-%d %H:%M:%S} -> {f['last_seen']:%H:%M:%S} | {f['status_breakdown']}")
        if f["successful_logon_after"]:
            print(f"         !! Successful logon afterwards: {f['successful_logon_after']} - investigate immediately")


if __name__ == "__main__":
    main()
