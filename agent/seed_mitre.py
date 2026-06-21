"""
Vakros MITRE ATT&CK Seeder
===========================
Downloads the MITRE ATT&CK Enterprise matrix from STIX and loads
the top techniques into the mitre_techniques table in Supabase.

No API key required — pulls from the public MITRE GitHub.

Usage:
    python seed_mitre.py
    python seed_mitre.py --limit 100   # seed top 100 techniques
"""

import os
import sys
import json
import httpx
import argparse
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

from supabase import create_client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
_sb = create_client(SUPABASE_URL, SUPABASE_KEY)

# MITRE ATT&CK Enterprise STIX bundle (latest)
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# High-priority techniques to seed (covers 80% of real-world alerts)
PRIORITY_TECHNIQUES = {
    "T1110", "T1110.001", "T1110.003",  # Brute Force
    "T1078", "T1078.001", "T1078.004",  # Valid Accounts
    "T1566", "T1566.001", "T1566.002",  # Phishing
    "T1059", "T1059.001", "T1059.003",  # Command & Scripting
    "T1055", "T1055.001",               # Process Injection
    "T1003", "T1003.001",               # Credential Dumping
    "T1021", "T1021.001", "T1021.002",  # Remote Services
    "T1486",                             # Data Encrypted for Impact (Ransomware)
    "T1490",                             # Inhibit System Recovery
    "T1027",                             # Obfuscated Files
    "T1036", "T1036.003",               # Masquerading
    "T1071", "T1071.001",               # Application Layer Protocol (C2)
    "T1105",                             # Ingress Tool Transfer
    "T1140",                             # Deobfuscate/Decode
    "T1218", "T1218.011",               # Signed Binary Proxy Execution
    "T1053", "T1053.005",               # Scheduled Task
    "T1547", "T1547.001",               # Boot/Logon Autostart
    "T1562", "T1562.001",               # Impair Defenses
    "T1070", "T1070.001",               # Indicator Removal
    "T1083",                             # File & Directory Discovery
    "T1082",                             # System Information Discovery
    "T1057",                             # Process Discovery
    "T1016",                             # System Network Config Discovery
    "T1018",                             # Remote System Discovery
    "T1046",                             # Network Service Scanning
    "T1041",                             # Exfiltration Over C2
    "T1048",                             # Exfiltration Over Alt Protocol
    "T1567",                             # Exfiltration Over Web Service
    "T1190",                             # Exploit Public-Facing Application
    "T1133",                             # External Remote Services
    "T1199",                             # Trusted Relationship
    "T1195",                             # Supply Chain Compromise
    "T1098",                             # Account Manipulation
    "T1136",                             # Create Account
    "T1484",                             # Domain Policy Modification
    "T1207",                             # Rogue Domain Controller
    "T1040",                             # Network Sniffing
    "T1557",                             # Adversary-in-the-Middle
}


def fetch_mitre_stix(url: str) -> dict:
    print(f"Downloading MITRE ATT&CK STIX bundle...")
    print(f"  URL: {url}")
    r = httpx.get(url, timeout=120, follow_redirects=True)
    r.raise_for_status()
    print(f"  Downloaded {len(r.content) / 1024 / 1024:.1f} MB")
    return r.json()


def parse_techniques(bundle: dict, limit: int | None = None) -> list[dict]:
    """Extract attack-pattern objects from STIX bundle."""
    techniques = []
    priority_found = set()

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = None
        url = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break

        if not technique_id:
            continue

        is_sub = "." in technique_id
        parent_id = technique_id.split(".")[0] if is_sub else None

        # Extract kill chain phases (tactics)
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        # Extract platforms
        platforms = obj.get("x_mitre_platforms", [])

        # Detection guidance
        detection = obj.get("x_mitre_detection", "")

        # Check if this is a priority technique
        is_priority = technique_id in PRIORITY_TECHNIQUES

        techniques.append({
            "technique_id":   technique_id,
            "name":           obj.get("name", ""),
            "tactic":         tactics,
            "description":    obj.get("description", "")[:2000],  # Truncate for DB
            "detection":      detection[:1000] if detection else "",
            "mitigations":    [],
            "platforms":      platforms,
            "url":            url or "",
            "is_subtechnique": is_sub,
            "parent_id":      parent_id,
            "_is_priority":   is_priority,
        })

        if is_priority:
            priority_found.add(technique_id)

    # Sort: priority first, then alphabetical
    techniques.sort(key=lambda t: (not t["_is_priority"], t["technique_id"]))

    missing = PRIORITY_TECHNIQUES - priority_found
    if missing:
        print(f"  Note: {len(missing)} priority techniques not found in bundle: {sorted(missing)[:5]}...")

    if limit:
        # Always include all priority techniques + fill up to limit
        priority = [t for t in techniques if t["_is_priority"]]
        rest = [t for t in techniques if not t["_is_priority"]]
        techniques = priority + rest[:max(0, limit - len(priority))]

    return techniques


def upsert_techniques(techniques: list[dict]) -> None:
    print(f"\nUpserting {len(techniques)} techniques to Supabase...")
    batch_size = 50
    total_upserted = 0

    for i in range(0, len(techniques), batch_size):
        batch = techniques[i:i + batch_size]
        rows = [
            {k: v for k, v in t.items() if k != "_is_priority"}
            for t in batch
        ]
        _sb.table("mitre_techniques").upsert(rows).execute()
        total_upserted += len(batch)
        print(f"  Upserted {total_upserted}/{len(techniques)}...", end="\r")

    print(f"\n  Done. {total_upserted} techniques in DB.")


def verify_seed() -> None:
    result = _sb.table("mitre_techniques").select("technique_id", count="exact").execute()
    count = result.count or len(result.data)
    print(f"\nVerification: {count} techniques in mitre_techniques table")

    # Spot-check
    checks = ["T1566", "T1110", "T1486"]
    for tid in checks:
        r = _sb.table("mitre_techniques").select("technique_id,name").eq("technique_id", tid).execute()
        if r.data:
            print(f"  ✓ {r.data[0]['technique_id']}: {r.data[0]['name']}")
        else:
            print(f"  ✗ {tid}: NOT FOUND")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed MITRE ATT&CK techniques into Supabase")
    parser.add_argument("--limit", type=int, default=None, help="Max techniques to seed (default: all)")
    parser.add_argument("--priority-only", action="store_true", help="Only seed priority techniques")
    args = parser.parse_args()

    limit = len(PRIORITY_TECHNIQUES) if args.priority_only else args.limit

    try:
        bundle = fetch_mitre_stix(MITRE_URL)
        techniques = parse_techniques(bundle, limit=limit)

        priority_count = sum(1 for t in techniques if t["_is_priority"])
        print(f"\nParsed {len(techniques)} techniques ({priority_count} priority)")

        upsert_techniques(techniques)
        verify_seed()
        print("\n✅ MITRE ATT&CK seeding complete.")

    except httpx.HTTPError as e:
        print(f"ERROR downloading MITRE data: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
