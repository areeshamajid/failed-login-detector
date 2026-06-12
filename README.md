# Failed Login Detector
A Python-based log analysis tool that parses Linux auth.log files, detects brute force SSH login attempts, and generates a structured alert report. 
## Overview
When attackers attempt to brute force SSH access, they generate repeated failed login entries in a server's `auth.log`. Manually scanning these logs is slow and error-prone, especially at scale.

This tool automates that triage process. It reads an `auth.log` file, extracts failed login attempts using regex, groups them by source IP, and flags any IP exceeding a configurable threshold. Outputs a structured alert report to both the console and a `.txt` file.

This mirrors the kind of alert triage a SOC Level 1 analyst performs daily using a SIEM.

## Features
- Parses standard Linux `auth.log` format
- Extracts source IP addresses and timestamps using regex
- Counts failed attempts per IP
- Flags IPs exceeding a configurable threshold (default: 5)
- Assigns severity levels: `MEDIUM`, `HIGH`, `CRITICAL`
- Reports first seen and last seen timestamps per flagged IP
- Outputs report to console and saves to `report.txt`

## Installation 
```
git clone https://github.com/yourusername/failed-login-detector
cd failed-login-detector
```
No dependencies to install; uses Python standard library only. 

## Usage
1. Place your `auth.log` file in the project directory(or use the included `sample_auth.log)
2. Run the script:
   ```
   python detector.py
   ```
3. Review the console output or open `report.txt`
To adjust the detection threshold, edit line 8 in `detector.py`:
```
THRESHOLD=5 #Change this to your desired sensitivity
```
## Example Output
```
============================================================
        FAILED LOGIN DETECTOR — ALERT REPORT
        Generated: 2026-06-12 14:32:01
============================================================

[!] 3 suspicious IP(s) detected above threshold (5 attempts)

------------------------------------------------------------
  IP Address  : 203.0.113.42
  Attempts    : 21
  Severity    : CRITICAL
  First Seen  : Jun 12 01:20:03
  Last Seen   : Jun 12 01:21:03
------------------------------------------------------------
  IP Address  : 10.0.0.9
  Attempts    : 11
  Severity    : HIGH
  First Seen  : Jun 12 02:05:10
  Last Seen   : Jun 12 02:05:40
------------------------------------------------------------
  IP Address  : 192.168.1.105
  Attempts    : 10
  Severity    : HIGH
  First Seen  : Jun 12 01:12:01
  Last Seen   : Jun 12 01:12:28
------------------------------------------------------------

[SUMMARY]
  Total IPs analysed : 5
  Flagged IPs        : 3
  Threshold used     : 5 failed attempts
============================================================
```

## Project Structure
```
failed-login-detector/
├── detector.py        # Main detection script
├── sample_auth.log    # Sample log file for testing
├── report.txt         # Generated alert report (auto-created)
└── README.md          # Documentation
```
## SOC Relevance 
This project simulates a core SOC L1 workflow:
| SOC Task | This Tool |
|---|---|
| Log ingestion | Reads `auth.log` line by line |
| Alert triage | Flags IPs above threshold |
| Severity classification | MEDIUM / HIGH / CRITICAL labels |
| Incident documentation | Structured report with timestamps

## Future Improvements
- Add AbuseIPDB API integration to check flagged IPs against threat intelligence feeds
- Export report to JSON or CSV for SIEM ingestion
- Add CLI arguments for custom log path and threshold
- Email alerting when critical IPs are detected
- Support for Windows Event Log format

## Disclaimer 
This tool is intended for educational and defensive security purposes only. Only use it on systems and log files you have explicit permission to analyse.

##Author
**Areesha Majid**
GitHub: [@areeshamajid](https://github.com/areeshamajid)
