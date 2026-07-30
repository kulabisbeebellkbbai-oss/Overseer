"""Safe shared foundations and installed provider-specific adapters."""

from types import MappingProxyType

from .base_cli import CliCommandRunner
from .codex import CodexDriver, codex_adapter_factory
from .claude import ClaudeDriver, claude_adapter_factory
from .antigravity import AntigravityDriver, antigravity_adapter_factory
from .mistral_vibe import MistralVibeDriver, mistral_vibe_adapter_factory
from .qwen_code import QwenCodeDriver, qwen_code_adapter_factory

ADAPTER_FACTORIES = MappingProxyType(
    {
        "codex": codex_adapter_factory,
        "claude": claude_adapter_factory,
        "qwen_code": qwen_code_adapter_factory,
        "mistral_vibe": mistral_vibe_adapter_factory,
        "antigravity": antigravity_adapter_factory,
    }
)

__all__ = [
    "ADAPTER_FACTORIES",
    "CliCommandRunner",
    "CodexDriver",
    "ClaudeDriver",
    "AntigravityDriver",
    "MistralVibeDriver",
    "QwenCodeDriver",
    "antigravity_adapter_factory",
    "claude_adapter_factory",
    "codex_adapter_factory",
    "mistral_vibe_adapter_factory",
    "qwen_code_adapter_factory",
]
