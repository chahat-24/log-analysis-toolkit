"""Load the sample CSV logs into a SQLite database (logs.db) for the hunting queries."""

import sqlite3
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "logs.db"

with sqlite3.connect(DB) as con:
    pd.read_csv(ROOT / "sample_logs" / "windows_security.csv").to_sql("windows_security", con, if_exists="replace", index=False)
    pd.read_csv(ROOT / "sample_logs" / "firewall.csv").to_sql("firewall", con, if_exists="replace", index=False)

print(f"Loaded sample logs into {DB}")
