#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from web3guard.sota_tools import capability_dicts

p=argparse.ArgumentParser(description="Print Web3Guard scanner/tool capability matrix")
p.add_argument("--json", type=Path, dest="json_out")
p.add_argument("--require-foundry", action="store_true")
a=p.parse_args()
items=capability_dicts()
print("Web3Guard capability matrix")
for x in items:
    print(f"{x['name']:<16} {'READY' if x['installed'] else 'missing':<8} {x['mode']:<10} {x['role']}")
if a.json_out:
    a.json_out.parent.mkdir(parents=True, exist_ok=True)
    a.json_out.write_text(json.dumps(items, indent=2)+"\n", encoding="utf-8")
if a.require_foundry and not any(x["name"]=="forge" and x["installed"] for x in items):
    raise SystemExit(2)
