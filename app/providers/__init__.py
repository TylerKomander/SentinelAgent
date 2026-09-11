from ..config import provider_name
from . import agent_provider, local_provider, sdk_provider


def get_provider():
    name = provider_name()
    if name == "claude_agent":
        return agent_provider
    if name == "local":
        return local_provider
    return sdk_provider
