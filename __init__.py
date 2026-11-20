"""Hermes entrypoint for the HybridOps recovery plugin."""

from __future__ import annotations

from .hybridops_recovery.plugin import register

__all__ = ["register"]
