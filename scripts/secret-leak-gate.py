#!/usr/bin/env python3
"""Fail CI if generated reports contain recognizable credential material."""
from __future__ import annotations
import re, sys
from pathlib import Path

PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    "gitlab_pat": re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    "hf_token": re.compile(r"hf_[A-Za-z0-9]{20,}"),
    "openai_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "stripe_secret": re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),
    "stripe_webhook": re.compile(r"whsec_[A-Za-z0-9]{20,}"),
    "telegram_token": re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "alchemy_rpc": re.compile(r"https://[^\s/]+alchemy[^\s/]*/v2/[A-Za-z0-9_-]{20,}"),
    "infura_rpc": re.compile(r"https://[^\s/]+infura[^\s/]*/v3/[A-Za-z0-9_-]{20,}"),
}
root=Path(sys.argv[1]) if len(sys.argv)>1 else Path("reports")
violations=[]
for fp in root.rglob("*"):
    if not fp.is_file() or fp.stat().st_size > 16*1024*1024: continue
    try: data=fp.read_text(errors="ignore")
    except Exception: continue
    for kind, rx in PATTERNS.items():
        if rx.search(data): violations.append((str(fp),kind))
if violations:
    print("SECRET LEAK GATE FAILED")
    for fp,kind in violations: print(f"  {kind}: {fp}")
    raise SystemExit(1)
print("SECRET LEAK GATE PASSED")
