"""Graph-based incremental analysis.

v3.5: rescan everything, every time, is the expensive status quo. This
module builds a content-addressed dependency graph of the target's
source files and computes the *minimal* set of chunks to re-analyze:

- **Hash-addressed nodes** — a file node keyed by content hash, so any
  change is detected exactly; identical trees produce identical graphs.
- **Import edges** — cheap regex import/inheritance edges across all 8
  supported language families, cross-file.
- **Reverse-reachability** — a changed file marks every file that
  imports it dirty transitively (a changed interface can change every
  caller). This is the correctness half; without it, incremental scans
  silently miss cross-file impact.
- **Chunk-level skip** — unchanged files contribute no new chunks.
"""

from web3guard.graph.analyzer import DependencyGraph, IncrementalAnalyzer, hash_content

__all__ = ["DependencyGraph", "IncrementalAnalyzer", "hash_content"]