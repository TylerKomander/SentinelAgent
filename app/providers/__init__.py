from ..config import provider_name
from . import agent_provider, sdk_provider


def get_provider():
    if provider_name() == "claude_agent":
        return agent_provider
    return sdk_provider
