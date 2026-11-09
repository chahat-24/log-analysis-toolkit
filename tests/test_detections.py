"""Tests run against the synthetic sample logs. Run with:  python -m pytest -q"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detections"))
LOGS = ROOT / "sample_logs"

import port_scan  # noqa: E402
import ssh_bruteforce  # noqa: E402
import windows_failed_logons  # noqa: E402


def test_ssh_flags_attackers_not_admin():
    alerts = ssh_bruteforce.detect(open(LOGS / "auth.log"), threshold=5, window_minutes=2, year=2026)
    ips = {a.source_ip for a in alerts}
    assert ips == {"203.0.113.45", "203.0.113.200"}          # slow attacker + admin typo ignored


def test_ssh_escalates_success_after_guessing():
    alerts = ssh_bruteforce.detect(open(LOGS / "auth.log"), year=2026)
    top = alerts[0]
    assert top.source_ip == "203.0.113.45"
    assert top.severity == "HIGH" and top.success_user == "labadmin"


def test_windows_spray_and_bruteforce():
    findings = windows_failed_logons.detect(windows_failed_logons.load(LOGS / "windows_security.csv"))
    by_ip = {f["source_ip"]: f for f in findings}
    assert by_ip["10.0.2.99"]["type"].startswith("Password spraying")
    assert by_ip["10.0.2.99"]["severity"] == "HIGH"           # s.patel logged on afterwards
    assert by_ip["198.51.100.23"]["type"].startswith("Brute force")
    assert "10.0.2.31" not in by_ip                           # single typo is not an attack


def test_port_scan_vertical_and_horizontal():
    findings = port_scan.detect(port_scan.load(LOGS / "firewall.csv"))
    types = {(f["type"], f["src_ip"]) for f in findings}
    assert ("Vertical port scan", "10.0.2.66") in types
    assert ("Horizontal sweep", "10.0.2.66") in types
    vertical = next(f for f in findings if f["type"] == "Vertical port scan")
    assert 3389 in vertical["open_ports"] and 445 in vertical["open_ports"]
