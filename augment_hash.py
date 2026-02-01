#!/usr/bin/env python3
"""Augment hash JSON line with metadata and write to file."""

import json
import sys

def main():
    if len(sys.argv) < 7:
        print("Usage: augment_hash.py <json_line> <trial> <scenario> <protocol> <variant> <capture_file>", file=sys.stderr)
        sys.exit(1)

    json_line = sys.argv[1]
    trial = int(sys.argv[2])
    scenario = int(sys.argv[3])
    protocol = sys.argv[4]
    variant = sys.argv[5]
    capture_file = sys.argv[6]

    try:
        data = json.loads(json_line)
        data.update({
            "trial": trial,
            "scenario": scenario,
            "protocol": protocol,
            "variant": variant,
            "capture_file": capture_file
        })
        print(json.dumps(data))
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
