"""Safe shared foundations and installed provider-specific adapters."""

from types import MappingProxyType

from .base_cli import CliCommandRunner
from .codex import CodexDriver, codex_adapter_factory
from .claude import ClaudeDriver, claude_adapter_factory

ADAPTER_FACTORIES = MappingProxyType(
    {"codex": codex_adapter_factory, "claude": claude_adapter_factory}
)

__all__ = [
    "ADAPTER_FACTORIES",
    "CliCommandRunner",
    "CodexDriver",
    "ClaudeDriver",
    "claude_adapter_factory",
    "codex_adapter_factory",
]
