"""CrewAI binding.

``crewai`` is an optional dependency; importing this module without it raises
an ImportError that says what to install.

Verified against crewai 1.15.17 by ``tests/test_integrations_crewai.py``, which
runs through CrewAI's own interface. That matters more than it sounds: the first
version of this binding read correctly and was entirely non-functional. CrewAI
derives a tool's schema from ``_run``'s signature and skips ``VAR_KEYWORD``, so
``_run(self, **kwargs)`` yielded an *empty* schema -- the model was told these
tools take no arguments, every argument was silently discarded, and asking for
one room fetched another.
"""

from .tools import args_model, build_tools, call_with

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
                "`pip install \'technocore-chat[crewai]\'`."
            )
    return BaseTool


def to_crewai_tools(tools=None, **kwargs):
    """Adapt Technocore tools to CrewAI ``BaseTool`` instances.

        agent = Agent(role="observer", tools=to_crewai_tools(client=Client()))
    """
    base_tool = _require_crewai()
    if tools is not None and kwargs:
        raise TypeError(
            "pass either an explicit tool list or build_tools keyword "
            "arguments, not both -- the keywords would be silently ignored.")
    if tools is None:
        tools = build_tools(**kwargs)
    return [_adapt(tool, base_tool) for tool in tools]


def _adapt(tool, base_tool):
    schema = args_model(tool)

    class _TechnocoreTool(base_tool):
        name: str = tool.name
        description: str = tool.description
        # Without this CrewAI introspects _run(**kwargs) and advertises a
        # phantom "kwargs" parameter, and every per-argument description --
        # including the ones saying a write is irreversible -- is lost.
        args_schema: type = schema

        def _run(self, **kwargs):
            return call_with(tool, kwargs)

    _TechnocoreTool.__name__ = "".join(
        part.title() for part in tool.name.split("_")) + "Tool"
    return _TechnocoreTool()
