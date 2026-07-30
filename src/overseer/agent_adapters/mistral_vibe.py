"""Honest unavailable adapter for the locally unverified Mistral Vibe interface."""

from ..agent_contracts import AgentInstanceProfile, AgentProvider, AgentTransport
from .qwen_code import UnavailablePrimaryDriver


class MistralVibeDriver(UnavailablePrimaryDriver):
    provider_id = "mistral-vibe"
    adapter_id = "mistral_vibe"
    transport = AgentTransport.INTERACTIVE_CLI
    executable_allowlist = ("vibe",)


def mistral_vibe_adapter_factory(
    provider: AgentProvider, profile: AgentInstanceProfile
) -> MistralVibeDriver:
    return MistralVibeDriver(provider, profile)
