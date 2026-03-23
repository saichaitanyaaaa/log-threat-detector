import re
import sys
from collections import defaultdict
from datetime import datetime

# ============================================================
# Linux Log Monitoring & Threat Detection Tool
# Author: Malla Sai Chaitanya
# Description: Parses auth.log to detect brute-force attacks,
#              flags suspicious IPs, and maps to MITRE ATT&CK
# MITRE ATT&CK: T1110 - Brute Force
# ============================================================

BRUTE_FORCE_THRESHOLD = 5  # failed attempts before flagging

MITRE_MAPPING = {
    "brute_force": {
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "description": "Adversary attempts to gain access by guessing credentials"
    }
}

def parse_log(filepath):
    failed_attempts = defaultdict(list)
    successful_logins = defaultdict(list)
    pattern_failed = re.compile(r"Failed password for (\S+) from (\S+) port")
    pattern_success = re.compile(r"Accepted password for (\S+) from (\S+) port")

    try:
        with open(filepath, "r") as f:
            for line in f:
                match_fail = pattern_failed.search(line)
                match_success = pattern_success.search(line)
                if match_fail:
                    user, ip = match_fail.group(1), match_fail.group(2)
                    failed_attempts[ip].append(user)
                elif match_success:
                    user, ip = match_success.group(1), match_success.group(2)
                    successful_logins[ip].append(user)
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")
        sys.exit(1)

    return failed_attempts, successful_logins

def detect_threats(failed_attempts, successful_logins):
    threats = []
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            # Check if attacker eventually succeeded
            success_after_fail = ip in successful_logins
            severity = "CRITICAL" if success_after_fail else "HIGH"
            threats.append({
                "ip": ip,
                "failed_count": len(attempts),
                "targeted_users": list(set(attempts)),
                "successful_login": success_after_fail,
                "severity": severity,
                "attack_type": "Brute Force",
                "mitre": MITRE_MAPPING["brute_force"]
            })

    threats.sort(key=lambda x: x["failed_count"], reverse=True)
    return threats

def generate_report(threats, failed_attempts, successful_logins):
    print("=" * 65)
    print("  THREAT DETECTION REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)
    print(f"\n[SUMMARY]")
    print(f"  Total IPs with failed logins : {len(failed_attempts)}")
    print(f"  Total IPs with successful logins : {len(successful_logins)}")
    print(f"  Threats detected             : {len(threats)}")

    if not threats:
        print("\n[+] No threats detected above threshold.")
        return

    print(f"\n[THREATS DETECTED]")
    print("-" * 65)
    for i, t in enumerate(threats, 1):
        print(f"\n  Threat #{i}")
        print(f"  IP Address     : {t['ip']}")
        print(f"  Severity       : {t['severity']}")
        print(f"  Attack Type    : {t['attack_type']}")
        print(f"  Failed Attempts: {t['failed_count']}")
        print(f"  Targeted Users : {', '.join(t['targeted_users'])}")
        print(f"  Login Succeeded: {'YES - COMPROMISED' if t['successful_login'] else 'No'}")
        print(f"\n  MITRE ATT&CK Mapping:")
        print(f"    Tactic     : {t['mitre']['tactic']}")
        print(f"    Technique  : {t['mitre']['technique']}")
        print(f"    Description: {t['mitre']['description']}")
        print("-" * 65)

    print("\n[RECOMMENDED ACTIONS]")
    for t in threats:
        if t["severity"] == "CRITICAL":
            print(f"  [!] CRITICAL: Block {t['ip']} immediately. Investigate compromised accounts: {', '.join(t['targeted_users'])}")
        else:
            print(f"  [!] HIGH: Block {t['ip']} at firewall. Monitor for lateral movement.")

    print("\n[+] Report complete. Document findings and escalate per SOC playbook.")
    print("=" * 65)

def main():
    log_file = "auth.log"
    print(f"[*] Parsing log file: {log_file}")
    failed, success = parse_log(log_file)
    print(f"[*] Running threat detection (threshold: {BRUTE_FORCE_THRESHOLD} failed attempts)...")
    threats = detect_threats(failed, success)
    generate_report(threats, failed, success)

if __name__ == "__main__":
    main()
