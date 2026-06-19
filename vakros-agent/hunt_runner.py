"""
Vakros Threat Hunt Runner
Usage:
  python hunt_runner.py --hypothesis lateral_movement --hours 48
  python hunt_runner.py --hypothesis ioc_spread
  python hunt_runner.py --hypothesis custom --query "Find evidence of data exfiltration from DB servers"
  python hunt_runner.py --all           # run all hypotheses sequentially
"""
import argparse
import json
import os
import sys
from datetime import datetime

# Load .env if present
if os.path.exists(".env"):
    for line in open(".env"):
        if "=" in line and not line.startswith("#"):
            k, _, v = line.strip().partition("=")
            os.environ.setdefault(k, v)

from agent.hunt_agent import run_hunt_agent, HYPOTHESIS_PROMPTS

ALL_HYPOTHESES = list(HYPOTHESIS_PROMPTS.keys())

def main():
    p = argparse.ArgumentParser(description="Vakros Threat Hunt Runner")
    p.add_argument("--hypothesis", choices=ALL_HYPOTHESES + ["custom"], default="lateral_movement")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--query", help="Custom hunt query (use with --hypothesis custom)")
    p.add_argument("--all", action="store_true", help="Run all built-in hypotheses")
    p.add_argument("--json", action="store_true", help="Output raw JSON")
    args = p.parse_args()

    hypotheses = ALL_HYPOTHESES if args.all else [args.hypothesis]

    for hyp in hypotheses:
        print(f"\n{'='*60}")
        print(f"  HUNT: {hyp.upper()}  ({args.hours}h lookback)")
        print(f"{'='*60}")

        result = run_hunt_agent(
            hypothesis=hyp,
            lookback_hours=args.hours,
            custom_query=args.query if hyp == "custom" else None,
        )

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Findings: {result['findings_count']}")
            print(f"Tool calls: {result['tool_calls_made']} | Iterations: {result['iterations']}")
            print(f"\nSummary:\n{result['summary']}")
            if result["findings"]:
                print(f"\n{'─'*40}")
                for i, f in enumerate(result["findings"], 1):
                    print(f"  [{i}] {f.get('title','?')}  sev={f.get('severity')}  conf={f.get('confidence')}")
                    print(f"      Hosts: {', '.join(f.get('affected_hosts',[]))}")
                    print(f"      {f.get('summary','')[:200]}")


if __name__ == "__main__":
    main()
