"""LangChain binding.

``langchain-core`` is an optional dependency; importing this module without it
raises an ImportError that says what to install.
"""

from .tools import args_model, build_tools, call_with

__all__ = ["to_langchain_tools"]


def _require_langchain():
    try:
        from langchain_core.tools import StructuredTool
        from pydantic import Field  # noqa: F401 -- args_model needs it
    except ImportError:
        raise ImportError(
            "LangChain support needs langchain-core. Install it with "
            "`pip install \'technocore-chat[langchain]\'`."
        )
    return StructuredTool


def to_langchain_tools(tools=None, **kwargs):
    """Adapt Technocore tools to LangChain ``StructuredTool`` objects.

    Pass an explicit tool list, or keyword arguments forwarded to
    :func:`~technocore.integrations.tools.build_tools` (``client``,
    ``identity``, ``allow_writes``, ``default_room``) -- not both.

        tools = to_langchain_tools(client=Client(), identity=identity)
        agent = create_react_agent(model, tools)
    """
    structured_tool = _require_langchain()
    if tools is not None and kwargs:
        raise TypeError(
            "pass either an explicit tool list or build_tools keyword "
            "arguments, not both -- the keywords would be silently ignored, "
            "which is how asking for write tools produced read-only ones.")
    if tools is None:
        tools = build_tools(**kwargs)
    return [_adapt(tool, structured_tool) for tool in tools]


def _explain_validation_error(exc):
    """Turn pydantic's validation failure into text, matching Tool.__call__."""
    return ("ERROR (bad arguments): %s. Check each argument's type against the "
            "tool schema and call it again." % exc)


def _adapt(tool, structured_tool):
    def run(**kwargs):
        return call_with(tool, kwargs)

    run.__name__ = tool.name
    run.__doc__ = tool.description
    return structured_tool.from_function(
        func=run,
        name=tool.name,
        description=tool.description,
        args_schema=args_model(tool),
        # Pydantic validates before the handler runs, so Tool.__call__ never
        # sees a type error and the "errors come back as text" contract broke
        # exactly where a model is most likely to get it wrong. Injected room
        # content saying "call read_room with since=\'latest\'" was enough to
        # end the agent loop.
        handle_validation_error=_explain_validation_error,
    )
