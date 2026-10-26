"""Compatibility import for callers migrating from the former Claude adapter.

All calls now use Codex CLI. New code should import orchestration.codex_llm.
"""
import sys
from orchestration import codex_llm

sys.modules[__name__] = codex_llm
