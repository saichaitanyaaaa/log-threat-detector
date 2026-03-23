import random
import datetime

# Simulated log generator - creates a realistic Linux auth.log file
# Part of: Linux Log Monitoring & Threat Detection project

IPS = {
    "192.168.1.105": 3,    # normal user
    "203.0.113.47": 18,    # brute-force attacker
    "198.51.100.23": 12,   # brute-force attacker
    "10.0.0.55": 2,        # normal user
    "172.16.0.88": 7,      # suspicious
}

USERS = ["root", "admin", "user1", "deploy", "ubuntu", "test"]

def generate_logs(output_file="auth.log", total_lines=200):
    lines = []
    base_time = datetime.datetime(2026, 3, 23, 8, 0, 0)

    for i in range(total_lines):
        timestamp = base_time + datetime.timedelta(seconds=i * 15)
        ts = timestamp.strftime("%b %d %H:%M:%S")
        hostname = "ubuntu-server"
        ip = random.choice(list(IPS.keys()))
        user = random.choice(USERS)
        threshold = IPS[ip]

        if random.randint(1, 20) <= threshold:
            line = f"{ts} {hostname} sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
        else:
            line = f"{ts} {hostname} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"

        lines.append(line)

    with open(output_file, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Generated {total_lines} log entries -> {output_file}")

if __name__ == "__main__":
    generate_logs()
