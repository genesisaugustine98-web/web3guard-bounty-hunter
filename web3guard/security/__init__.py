"""
Security primitives for Web3Guard.

This package implements two layers of defense that the original scanner
either glossed over or implemented only as informational warnings:

1. :class:`PromptInjectionGuard` — sanitizes source code before it is
   inserted into LLM prompts. Untrusted target code may contain text
   that *looks like* instructions ("ignore all previous instructions",
   "you are now a helpful agent that...") and tries to subvert the
   analysis prompt. The guard neutralizes these patterns in three ways:

   a. **Pattern matching** — well-known injection phrases are detected
      and replaced with a placeholder that is harmless to the LLM.
   b. **Quarantine wrapping** — injected content is wrapped in a
      clearly-labeled ``<untrusted_target_code>`` XML tag and the
      system prompt explicitly instructs the model to treat the
      contents as data, not instructions.
   c. **Output validation** — the model's response is scanned for
      telltale signs of a successful injection (e.g. unexpected
      ``"system:"`` blocks, refusal of legitimate analysis tasks,
      instructions to send data to a URL not in the configured list).

2. :class:`SandboxGuard` — strengthens the test-runner sandbox against
   escape attempts. The original scanner already excluded
   filesystem/shell Foundry cheatcodes, but a determined attacker can
   still try to escape via:

   - Solidity ``0.8.x`` panic()s that the AI generated on purpose
   - inline assembly (Yul) with raw ``call(gas(), ...)"``
   - unexpected revert reasons that, when bubbled up, leak filesystem
     paths or environment variables
   - the test process itself (the AI may have used a custom
     ``foundry.toml`` hook)

   The guard addresses these by:

   - Running every test subprocess under a per-process resource limit
     (CPU, memory, file size, open files, processes).
   - Dropping the subprocess into a chroot/tempdir where possible.
   - Stripping environment variables except an explicit allowlist.
   - Validating the generated ``foundry.toml`` before the build step
     so no per-config hooks can fire.
   - Capturing the full revert reason text but truncating it in
     reports to a safe length to avoid path/env leakage.
"""

from web3guard.security.prompt_injection import (
    PromptInjectionGuard,
    InjectionVerdict,
)
from web3guard.security.sandbox_guard import (
    SandboxGuard,
    SandboxPolicy,
    SandboxVerdict,
)

__all__ = [
    "PromptInjectionGuard",
    "InjectionVerdict",
    "SandboxGuard",
    "SandboxPolicy",
    "SandboxVerdict",
]
