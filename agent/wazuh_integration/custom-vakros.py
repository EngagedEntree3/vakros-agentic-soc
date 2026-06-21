#!/usr/bin/env python3
"""
Wazuh → Vakros custom integration.
Install as /var/ossec/integrations/custom-vakros (no .py extension on Wazuh)
chmod 750, chown root:wazuh

ossec.conf block:
  <integration>
    <name>custom-vakros</name>
    <hook_url>http://VAKROS_SERVER:8001/webhook/wazuh</hook_url>
    <api_key>YOUR_WEBHOOK_SECRET</api_key>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
"""
import json, sys, urllib.request, urllib.error

def main():
    if len(sys.argv) < 3:
        sys.exit(1)
    alert_file, api_key = sys.argv[1], sys.argv[2]
    hook_url = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:8001/webhook/wazuh"

    with open(alert_file) as f:
        alert = json.load(f)

    req = urllib.request.Request(
        hook_url, data=json.dumps(alert).encode(),
        headers={"Content-Type": "application/json", "X-Wazuh-Token": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"Vakros: {r.read().decode()}")
    except urllib.error.URLError as e:
        print(f"Vakros error: {e}", file=sys.stderr); sys.exit(1)

if __name__ == "__main__":
    main()
