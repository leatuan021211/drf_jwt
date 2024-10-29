import re

def analyze_logs():
    # Read logs and analyze patterns (this is a simplified version)
    with open('user_requests.log') as f:
        logs = f.readlines()
    ip_counts = {}
    for log in logs:
        ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log)
        if ip:
            ip_counts[ip.group(1)] = ip_counts.get(ip.group(1), 0) + 1