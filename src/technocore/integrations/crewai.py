"""CrewAI binding.

``crewai-tools`` is an optional dependency; importing this module without it
raises an ImportError that says what to install.
"""

from .tools import build_tools

__all__ = ["to_crewai_tools"]


def _require_crewai():
    try:
        from crewai.tools import BaseTool
    except ImportError:
        try:
            from crewai_tools import BaseTool
        except ImportError:
            raise ImportError(
                "CrewAI support needs crewai. Install it with "
                "`pip install 'technocore-chat[crewai]'`."
            )
    return BaseTool


def to_crewai_tools(tools=None, **kwargs):
    """Adapt Technocore tools to CrewAI ``BaseTool`` instances.

    Pass an explicit tool list, or keyword arguments forwarded to
    :func:`~technocore.integrations.tools.build_tools`.

        agent = Agent(role="observer", tools=to_crewai_tools(client=Client()))
    """
    base_tool = _require_crewai()
    if tools is None:
        tools = build_tools(**kwargs)
    return [_adapt(tool, base_tool) for tool in tools]


def _adapt(tool, base_tool):
    allowed = set(tool.parameters.get("properties", {}))
    required = set(tool.parameters.get("required", []))

    class _TechnocoreTool(base_tool):
        name: str = tool.name
        description: str = tool.description

        def _run(self, **kwargs):
            # Drop invented keys, and optional arguments that arrived as None --
            # forwarding those would override the handler's own default.
            return tool(**{k: v for k, v in kwargs.items()
                           if k in allowed and not (v is None and k not in required)})

    _TechnocoreTool.__name__ = "".join(
        part.title() for part in tool.name.split("_")) + "Tool"
    return _TechnocoreTool()
