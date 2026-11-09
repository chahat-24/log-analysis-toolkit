"""
Detect SSH brute-force attempts in a Linux auth.log.

MITRE ATT&CK: T1110.001 - Brute Force: Password Guessing

Logic
-----
1. Parse every "Failed password" line (sshd) and pull out timestamp, user and source IP.
2. For each source IP, slide a time window over its failures.
3. Raise an alert when an IP has >= THRESHOLD failures inside WINDOW_MINUTES.
4. Escalate the alert if the same IP later has an "Accepted password" line
   (possible successful compromise after guessing).

Usage
-----
    python detections/ssh_bruteforce.py sample_logs/auth.log
    python detections/ssh_bruteforce.py sample_logs/auth.log --threshold 5 --window 2 --year 2026
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: "
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: "
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)


@dataclass
class Alert:
    source_ip: str
    failures: int
    first_seen: datetime
    last_seen: datetime
    users_tried: set[str] = field(default_factory=set)
    success_after: datetime | None = None
    success_user: str | None = None

    @property
    def severity(self) -> str:
        return "HIGH" if self.success_after else "MEDIUM"

    def __str__(self) -> str:
        line = (
            f"[{self.severity}] SSH brute force from {self.source_ip}: "
            f"{self.failures} failures between {self.first_seen:%H:%M:%S} and "
            f"{self.last_seen:%H:%M:%S}; users tried: {', '.join(sorted(self.users_tried))}"
        )
        if self.success_after:
            line += (
                f"\n         !! Successful login as '{self.success_user}' at "
                f"{self.success_after:%H:%M:%S} from the same IP - investigate immediately"
            )
        return line


def _parse_ts(raw: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


def detect(lines, threshold: int = 5, window_minutes: int = 2, year: int | None = None) -> list[Alert]:
    year = year or datetime.now().year
    window = timedelta(minutes=window_minutes)
    failures: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    successes: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    for line in lines:
        if m := FAILED_RE.match(line):
            failures[m["ip"]].append((_parse_ts(m["ts"], year), m["user"]))
        elif m := ACCEPTED_RE.match(line):
            successes[m["ip"]].append((_parse_ts(m["ts"], year), m["user"]))

    alerts: list[Alert] = []
    for ip, events in failures.items():
        events.sort()
        start = 0
        best = None
        for end in range(len(events)):
            while events[end][0] - events[start][0] > window:
                start += 1
            count = end - start + 1
            if count >= threshold and (best is None or count > best[2]):
                best = (start, end, count)
        if best is None:
            continue
        s, e, count = best
        alert = Alert(
            source_ip=ip,
            failures=count,
            first_seen=events[s][0],
            last_seen=events[e][0],
            users_tried={u for _, u in events[s : e + 1]},
        )
        for ts, user in sorted(successes.get(ip, [])):
            if ts >= alert.first_seen:
                alert.success_after, alert.success_user = ts, user
                break
        alerts.append(alert)

    return sorted(alerts, key=lambda a: (a.severity != "HIGH", -a.failures))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("logfile")
    p.add_argument("--threshold", type=int, default=5, help="failures needed to alert (default 5)")
    p.add_argument("--window", type=int, default=2, help="window in minutes (default 2)")
    p.add_argument("--year", type=int, help="year for syslog timestamps (default: current year)")
    args = p.parse_args()

    with open(args.logfile, encoding="utf-8", errors="replace") as fh:
        alerts = detect(fh, args.threshold, args.window, args.year)

    if not alerts:
        print("No SSH brute-force activity found.")
    for a in alerts:
        print(a)


if __name__ == "__main__":
    main()
