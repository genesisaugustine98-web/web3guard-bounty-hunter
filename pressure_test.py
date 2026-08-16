"""Pressure test: exercise the full scanner pipeline with a fake AI client.

Simulates realistic LLM responses for analysis, exploit generation, and
self-critique to exercise every code path without network calls.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from web3guard.ai.cost import CostTracker
from web3guard.ai.provider import ChatResponse
from web3guard.scanner import Scanner, load_config

PROJECT_ROOT = Path(__file__).resolve().parent


class FakeAI:
    """Replay scripted responses per role."""

    def __init__(self) -> None:
        self._cost = CostTracker()
        self.calls: list[tuple[str, str, str]] = []  # (role, system, user)

    def chat(self, system, user, *, max_tokens=1500, temperature=0.0, role="analysis", **kwargs):
        self.calls.append((role, system, user))
        if role == "analysis":
            content = json.dumps({
                "status": "vulnerable",
                "category": "access-control",
                "severity": "HIGH",
                "confidence": 0.9,
                "function": "withdraw",
                "swc_id": "SWC-105",
                "description": "Missing access control allows anyone to become owner.",
                "reasoning": "setOwner has no modifier and no owner check.",
                "line_hint": "17",
            })
        elif role == "exploit":
            content = (
                "```solidity\n"
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.0;\n"
                "import \"forge-std/Test.sol\";\n"
                "contract ExploitTest is Test {\n"
                "    function test_autonomous_exploit() public {\n"
                "        uint256 before = 0;\n"
                "        // real impact\n"
                "        assert(before < 100);\n"
                "    }\n"
                "}\n"
                "```"
            )
        elif role == "self_critique":
            content = json.dumps({"verdict": "confirmed"})
        else:
            content = json.dumps({"result": "ok"})
        return ChatResponse(content=content, model="fake", prompt_tokens=100,
                            completion_tokens=50, provider="fake")

    def cost_tracker(self):
        return self._cost


def main() -> int:
    cfg = load_config(None)
    cfg.update({
        "enable_discovery": False,   # no toolchains installed
        "enable_secret_scan": True,
        "enable_economic_analyzer": True,
        "enable_self_critique": True,
        "enable_exploit": False,     # no forge installed
        "enable_attack_sequence_brainstorm": False,
        "enable_role_map": False,
        "report_formats": ["txt", "json", "sarif", "md"],
    })
    fake = FakeAI()
    workdir = PROJECT_ROOT / "pressure_out"
    scanner = Scanner(config=cfg, ai_client=fake, workdir=workdir)
    target = PROJECT_ROOT / "test_contracts"
    result = scanner.scan([str(target) + "|max"], min_severity="LOW")
    scanner.build_report(result, out_dir=workdir / "reports")
    print(f"findings={len(result.all_findings)} "
          f"confirmed={len(result.confirmed_findings)} "
          f"ai_calls={len(fake.calls)}")
    for f in result.all_findings[:5]:
        print(f"  [{f.severity}] {f.category} @ {f.file} conf={f.confidence:.2f} "
              f"status={f.status}")
    # Show the secret scan results
    for tr in result.targets:
        print(f"  secrets_findings={len(tr.secrets_findings)}")
        for s in tr.secrets_findings[:5]:
            print(f"    {s['kind']} @ {s['file']}:{s['line']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
