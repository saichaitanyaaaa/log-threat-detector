# Linux Log Monitoring & Threat Detection Tool

A Python-based SOC simulation tool that parses Linux `auth.log` files to detect brute-force attacks, flag malicious IPs, and map findings to the MITRE ATT&CK framework.

---

## Overview

This project simulates a core SOC analyst workflow — ingesting system logs, detecting anomalous behavior, and generating actionable threat reports. Built to demonstrate hands-on understanding of log analysis, threat detection, and incident triage.

---

## Features

- Parses Linux SSH authentication logs (`auth.log`)
- Detects brute-force attacks using configurable failed-login thresholds
- Identifies IPs that succeeded after repeated failures (potential compromise)
- Assigns severity levels: `CRITICAL` and `HIGH`
- Maps attack patterns to **MITRE ATT&CK T1110 — Brute Force**
- Generates a structured threat report with recommended actions

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |

---

## Project Structure

```
log-threat-detector/
├── generate_logs.py      # Generates a realistic simulated auth.log
├── threat_detector.py    # Main detection engine + report generator
├── auth.log              # Generated sample log file (created at runtime)
└── README.md
```

---

## How to Run

**Step 1 — Generate sample log data:**
```bash
python generate_logs.py
```

**Step 2 — Run the threat detector:**
```bash
python threat_detector.py
```

---

## Sample Output

```
=================================================================
  THREAT DETECTION REPORT
  Generated: 2026-03-23 14:00:00
=================================================================

[SUMMARY]
  Total IPs with failed logins     : 5
  Threats detected                 : 2

[THREATS DETECTED]
-----------------------------------------------------------------
  Threat #1
  IP Address     : 203.0.113.47
  Severity       : CRITICAL
  Attack Type    : Brute Force
  Failed Attempts: 18
  Targeted Users : root, admin, deploy
  Login Succeeded: YES - COMPROMISED

  MITRE ATT&CK Mapping:
    Tactic     : Credential Access
    Technique  : T1110 - Brute Force
-----------------------------------------------------------------
```

---

## Skills Demonstrated

- Linux log analysis and parsing
- Python scripting (regex, file I/O, data structures)
- SOC alert triage logic
- MITRE ATT&CK framework mapping
- Threat reporting and documentation

---

## Author

**Malla Sai Chaitanya**  
B.Tech Computer Science & Cyber Security — Raghu Engineering College  
[LinkedIn](https://linkedin.com/in/malla-sai-chaitanya)
