"""LangChain binding.

``langchain-core`` is an optional dependency; importing this module without it
raises an ImportError that says what to install.
"""

from typing import Optional

from .tools import build_tools

__all__ = ["to_langchain_tools"]


def _require_langchain():
    try:
        from langchain_core.tools import StructuredTool  # noqa: F401
        from pydantic import Field  # noqa: F401
    except ImportError:
        raise ImportError(
            "LangChain support needs langchain-core. Install it with "
            "`pip install 'technocore-chat[langchain]'`."
        )
    return StructuredTool


def to_langchain_tools(tools=None, **kwargs):
    """Adapt Technocore tools to LangChain ``StructuredTool`` objects.

    Pass an explicit tool list, or keyword arguments forwarded to
    :func:`~technocore.integrations.tools.build_tools` (``client``,
    ``identity``, ``allow_writes``, ``default_room``).

        tools = to_langchain_tools(client=Client(), identity=identity)
        agent = create_react_agent(model, tools)
    """
    structured_tool = _require_langchain()
    if tools is None:
        tools = build_tools(**kwargs)

    adapted = []
    for tool in tools:
        adapted.append(structured_tool.from_function(
            func=_bind(tool),
            name=tool.name,
            description=tool.description,
            args_schema=_args_schema(tool),
        ))
    return adapted


def _bind(tool):
    """Close over the tool so LangChain calls it by keyword."""
    allowed = set(tool.parameters.get("properties", {}))
    required = set(tool.parameters.get("required", []))

    def run(**kwargs):
        clean = {}
        for name, value in kwargs.items():
            # Drop keys the model invented: an unexpected kwarg would be a
            # TypeError inside the agent loop rather than an answerable message.
            if name not in allowed:
                continue
            # Drop optional arguments that arrived as None. Pydantic fills an
            # omitted optional field with None and LangChain passes it through,
            # so forwarding it would override the handler's default with None --
            # which is how "read the default room" became "read room None".
            if value is None and name not in required:
                continue
            clean[name] = value
        return tool(**clean)

    run.__name__ = tool.name
    run.__doc__ = tool.description
    return run


def _args_schema(tool):
    """Build a pydantic model from the tool's JSON Schema.

    Always returns a model, even for a tool that takes no arguments: handing
    LangChain ``None`` makes it infer the schema from the ``**kwargs`` in
    :func:`_bind`, which advertises a bogus ``kwargs`` object parameter to the
    model.
    """
    from pydantic import Field, create_model

    properties = tool.parameters.get("properties", {})
    required = set(tool.parameters.get("required", []))
    fields = {}
    for name, spec in properties.items():
        python_type = {"string": str, "integer": int, "number": float,
                       "boolean": bool}.get(spec.get("type"), str)
        description = spec.get("description")
        if name in required:
            fields[name] = (python_type, Field(..., description=description))
        else:
            fields[name] = (Optional[python_type],
                            Field(None, description=description))
    return create_model(
        "".join(part.title() for part in tool.name.split("_")) + "Args", **fields)
