"""
log_to_excel.py
---------------
Parses a Linux syslog file into structured spreadsheet columns so the data can
be sorted, filtered, and pivoted. Each line follows the syslog convention:

    Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; ...
    |----------- timestamp ----| host |-- service --|  |---- message ----|

Two extra columns - User and Source - are extracted from the message body so
the targeted account and the attacking host can be counted directly.

Part of: Linux Log File Analysis, Automation, and SIEM Visualization
Dataset:  Linux_2k.log (LogHub - https://github.com/logpai/loghub)

Requires: pip install pandas openpyxl
"""

import re
import sys

try:
    import pandas as pd
except ImportError:
    sys.exit("pandas is required. Install it with: pip install pandas openpyxl")

LOG_FILE = "Linux_2k.log"
OUT_FILE = "Linux_2k.xlsx"

USER_RE = re.compile(r"user=(\S+)")
RHOST_RE = re.compile(r"rhost=(\S+)")

records = []

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        parts = line.strip().split(maxsplit=5)
        if len(parts) < 6:
            continue

        month, day, time, host, service, message = parts

        user = USER_RE.search(message)
        rhost = RHOST_RE.search(message)

        records.append([
            month,
            day,
            time,
            host,
            service,
            message,
            user.group(1) if user else ("Unknown" if "user unknown" in message else ""),
            rhost.group(1) if rhost else "",
        ])

df = pd.DataFrame(records, columns=[
    "Month", "Day", "Time", "Host", "Service", "Message", "User", "Source",
])

df.to_excel(OUT_FILE, index=False)
print(f"Parsed {len(df)} log lines into {OUT_FILE}")
