"""Honest unavailable adapter for the locally unverified Antigravity interface."""

from ..agent_contracts import AgentInstanceProfile, AgentProvider, AgentTransport
from .qwen_code import UnavailablePrimaryDriver


class AntigravityDriver(UnavailablePrimaryDriver):
    provider_id = "antigravity"
    adapter_id = "antigravity"
    transport = AgentTransport.GATEWAY
    executable_allowlist = ()


def antigravity_adapter_factory(
    provider: AgentProvider, profile: AgentInstanceProfile
) -> AntigravityDriver:
    return AntigravityDriver(provider, profile)
