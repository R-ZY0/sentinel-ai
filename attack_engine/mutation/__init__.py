"""Opt-in, deterministic attack-variant generation for authorized tests."""

from .mutator import VariantGenerator
from .schema import AttackVariant, MutationError

__all__ = ["AttackVariant", "MutationError", "VariantGenerator"]
