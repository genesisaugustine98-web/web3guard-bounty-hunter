"""Intelligent multi-model routing for Web3Guard.

v3.5: model selection is no longer static per-role config. The router
scores candidate models per call from live reliability signals —
latency, error rate, circuit state — and can degrade to the cheapest
healthy model when a budget controller asks it to. Static
``models:``/``role_models`` overrides always win when present, so the
feature is fully backward compatible.
"""

from web3guard.routing.router import ModelRouter, RouteDecision

__all__ = ["ModelRouter", "RouteDecision"]