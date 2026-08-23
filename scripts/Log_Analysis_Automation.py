"""
Log_Analysis_Automation.py
--------------------------
Scans a Linux authentication log for indicators of brute-force activity and
unauthorised access attempts, classifies each match, prints a summary, and
exports the results to CSV.

Part of: Linux Log File Analysis, Automation, and SIEM Visualization
Dataset:  Linux_2k.log (LogHub - https://github.com/logpai/loghub)

Usage:
    python Log_Analysis_Automation.py                 # analyse the whole file
    python Log_Analysis_Automation.py --start 200 --end 500
"""

import argparse
import csv
import os
import sys
from collections import Counter

# Detection patterns, ordered most specific first.
# NOTE: "Failed password" is the OpenSSH message format. This dataset
# authenticates through PAM, which writes "authentication failure" instead,
# so that pattern matches zero events here. See the README's Secondary
# Finding - it is kept deliberately to document the coverage gap.
PATTERNS = [
    ("Failed Login", ("Failed password",)),
    ("Auth Failure", ("authentication failure",)),
    ("Unknown User", ("user unknown", "invalid user")),
]


def classify(line):
    """Return the event type for a log line, or None if it is not suspicious."""
    for label, keywords in PATTERNS:
        if any(k in line for k in keywords):
            return label
    return None


def analyse(path, start, end):
    """Read the log and return a list of (event_type, log_line) tuples."""
    if not os.path.exists(path):
        sys.exit(f"Log file not found: {path}")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        logs = f.readlines()

    subset = logs[start:end] if end else logs[start:]

    findings = []
    for line in subset:
        event_type = classify(line)
        if event_type:
            findings.append((event_type, line.strip()))
    return findings, len(logs), len(subset)


def export_csv(findings, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Log Entry"])
        writer.writerows(findings)


def main():
    parser = argparse.ArgumentParser(description="Scan a Linux auth log for suspicious activity.")
    parser.add_argument("--log", default="Linux_2k.log", help="path to the log file")
    parser.add_argument("--start", type=int, default=0, help="first line to analyse (0-based)")
    parser.add_argument("--end", type=int, default=None, help="last line to analyse (exclusive)")
    parser.add_argument("--out", default="Full_suspicious_logs.csv", help="CSV output path")
    args = parser.parse_args()

    findings, total_lines, scanned = analyse(args.log, args.start, args.end)

    print(f"=== Suspicious Log Entries ({args.log}) ===")
    for event_type, entry in findings:
        print(f"[{event_type}] {entry}")

    counts = Counter(t for t, _ in findings)
    print(f"\nLines in file      : {total_lines}")
    print(f"Lines scanned      : {scanned}")
    print(f"Suspicious entries : {len(findings)}")
    for label, _ in PATTERNS:
        print(f"  {label:<14}: {counts.get(label, 0)}")

    export_csv(findings, args.out)
    print(f"\nResults saved to {args.out}")


if __name__ == "__main__":
    main()
