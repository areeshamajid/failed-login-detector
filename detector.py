import re
from collections import defaultdict
from datetime import datetime

# --- Configuration ---
LOG_FILE = "sample_auth.log"
REPORT_FILE = "report.txt"
THRESHOLD = 5  # Number of failed logins before flagging an IP

# --- Regex pattern to match failed login lines ---
PATTERN = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for .+ from (\d+\.\d+\.\d+\.\d+)"
)

def parse_log(filepath):
    """Read log file and extract failed login attempts."""
    failed_attempts = defaultdict(list)

    try:
        with open(filepath, "r") as f:
            for line in f:
                match = PATTERN.search(line)
                if match:
                    timestamp_str, ip = match.groups()
                    failed_attempts[ip].append(timestamp_str)
    except FileNotFoundError:
        print(f"[ERROR] Log file '{filepath}' not found.")
        exit(1)

    return failed_attempts

def assign_severity(count):
    """Assign severity level based on number of failed attempts."""
    if count >= 20:
        return "CRITICAL"
    elif count >= 10:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    else:
        return "LOW"

def generate_report(failed_attempts):
    """Analyse attempts and generate alert report."""
    flagged = {
        ip: attempts
        for ip, attempts in failed_attempts.items()
        if len(attempts) >= THRESHOLD
    }

    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append("        FAILED LOGIN DETECTOR — ALERT REPORT")
    report_lines.append(f"        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("=" * 60)

    if not flagged:
        report_lines.append("\n[INFO] No suspicious IPs detected.")
    else:
        report_lines.append(f"\n[!] {len(flagged)} suspicious IP(s) detected above threshold ({THRESHOLD} attempts)\n")
        report_lines.append("-" * 60)

        for ip, attempts in sorted(flagged.items(), key=lambda x: len(x[1]), reverse=True):
            count = len(attempts)
            severity = assign_severity(count)
            first_seen = attempts[0]
            last_seen = attempts[-1]

            report_lines.append(f"  IP Address  : {ip}")
            report_lines.append(f"  Attempts    : {count}")
            report_lines.append(f"  Severity    : {severity}")
            report_lines.append(f"  First Seen  : {first_seen}")
            report_lines.append(f"  Last Seen   : {last_seen}")
            report_lines.append("-" * 60)

    report_lines.append("\n[SUMMARY]")
    report_lines.append(f"  Total IPs analysed : {len(failed_attempts)}")
    report_lines.append(f"  Flagged IPs        : {len(flagged)}")
    report_lines.append(f"  Threshold used     : {THRESHOLD} failed attempts")
    report_lines.append("=" * 60)

    return "\n".join(report_lines)

def main():
    print("[*] Starting Failed Login Detector...")
    failed_attempts = parse_log(LOG_FILE)

    report = generate_report(failed_attempts)

    # Print to console
    print(report)

    # Save to file
    with open(REPORT_FILE, "w") as f:
        f.write(report)

    print(f"\n[*] Report saved to '{REPORT_FILE}'")

if __name__ == "__main__":
    main()