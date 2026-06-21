"""
Send a batch of simulated Wazuh alerts to the local webhook server.
Usage: python test_webhook.py [--url http://localhost:8001] [--count 5]
"""
import json, random, argparse, urllib.request, datetime, uuid

SAMPLE_RULES = [
    (5501, "User login attempt failed", 10, "authentication_failed"),
    (31100, "Web attack detected - SQL injection", 14, "web_attack"),
    (5710, "SSH brute force - Multiple failed logins", 12, "brute_force"),
    (87901, "Possible ransomware detected", 15, "ransomware"),
    (18101, "Lateral movement detected", 13, "lateral_movement"),
    (80792, "MITRE T1003 - Credential dumping", 12, "credential_access"),
    (2932, "Syscheck: File modified", 5, "file_integrity"),
    (5503, "User successfully logged in", 3, "authentication_success"),
]

AGENTS = ["web-srv-01", "dc-01", "workstation-cfo", "db-srv-02", "linux-app-01"]

def make_wazuh_alert(rule_id, rule_desc, level, tactic, agent_name):
    return {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "rule": {
            "id": str(rule_id),
            "description": rule_desc,
            "level": level,
            "groups": [tactic],
            "mitre": {
                "id": ["T1078", "T1110"] if "auth" in tactic else ["T1059"],
                "tactic": [tactic.replace("_", " ").title()],
            },
        },
        "agent": {"id": "001", "name": agent_name, "ip": f"10.0.{random.randint(0,5)}.{random.randint(1,254)}"},
        "data": {
            "srcip": f"185.{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dstip": f"10.0.0.{random.randint(1,50)}",
        },
        "location": f"/var/log/auth.log",
        "full_log": f"[demo] {rule_desc} on {agent_name}",
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8001/webhook/wazuh")
    p.add_argument("--count", type=int, default=5)
    args = p.parse_args()

    alerts = []
    for _ in range(args.count):
        rule_id, rule_desc, level, tactic = random.choice(SAMPLE_RULES)
        agent = random.choice(AGENTS)
        alerts.append(make_wazuh_alert(rule_id, rule_desc, level, tactic, agent))

    payload = json.dumps(alerts).encode()
    req = urllib.request.Request(
        args.url, data=payload,
        headers={"Content-Type": "application/json", "X-Wazuh-Token": "test"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        print(json.dumps(json.loads(r.read()), indent=2))

if __name__ == "__main__":
    main()
