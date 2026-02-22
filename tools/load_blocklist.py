#!/usr/bin/env python3
"""Load stage2_blocklist.yml rules into a running edr-graph agent via API."""

import json
import sys
import urllib.error
import urllib.request

import yaml


def load_rules(yaml_path: str, api_base: str = "http://127.0.0.1:9200") -> None:
    with open(yaml_path) as fh:
        doc = yaml.safe_load(fh)

    rules = doc.get("rules", [])
    if not rules:
        print("No rules found in YAML.")
        return

    # Check existing rules to avoid duplicates
    req = urllib.request.Request(f"{api_base}/api/response/blocklist")
    with urllib.request.urlopen(req) as resp:
        existing = json.loads(resp.read())
    existing_keys = {
        (r["rule_type"], r["pattern"], r.get("chain_filter", ""))
        for r in existing.get("rules", [])
    }

    loaded = 0
    skipped = 0
    for r in rules:
        key = (r["rule_type"], r["pattern"], r.get("chain_filter", ""))
        if key in existing_keys:
            skipped += 1
            continue
        body = json.dumps({
            "rule_type": r["rule_type"],
            "pattern": r["pattern"],
            "description": r.get("description", ""),
            "chain_filter": r.get("chain_filter", ""),
        }).encode()
        req = urllib.request.Request(
            f"{api_base}/api/response/blocklist",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            json.loads(resp.read())
        loaded += 1

    print(f"Loaded {loaded} rules, skipped {skipped} duplicates. "
          f"Total in blocklist: {loaded + skipped + len(existing_keys)}")


if __name__ == "__main__":
    yaml_path = sys.argv[1] if len(sys.argv) > 1 else "rules/defaults/stage2_blocklist.yml"
    api_base = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:9200"
    load_rules(yaml_path, api_base)
