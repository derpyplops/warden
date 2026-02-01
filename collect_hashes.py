#!/usr/bin/env python3
"""Collect payload hashes from client output and build JSON file."""

import json
import sys
from datetime import datetime, timezone

def main():
    if len(sys.argv) < 2:
        print("Usage: collect_hashes.py <output_json>", file=sys.stderr)
        sys.exit(1)

    output_file = sys.argv[1]

    # Read trial data from stdin (JSON lines)
    trials = []
    for line in sys.stdin:
        line = line.strip()
        if line.startswith('{') and line.endswith('}'):
            try:
                trials.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # Build output structure
    now_utc = datetime.now(timezone.utc)
    output = {
        "timestamp": now_utc.isoformat().replace('+00:00', 'Z'),
        "run_start": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "trials": trials
    }

    # Write to file
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Saved {len(trials)} trial hashes to {output_file}")

if __name__ == "__main__":
    main()
