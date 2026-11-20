"""HybridOps recovery plugin registration."""

from __future__ import annotations

from .service import (
    EXPORT_SCHEMA,
    IMPORT_SCHEMA,
    INSPECT_SCHEMA,
    TOOL_EXPORT,
    TOOL_IMPORT,
    TOOL_INSPECT,
    HybridOpsRecoveryService,
)


def register(ctx) -> None:
    service = HybridOpsRecoveryService(ctx.get_config)
    ctx.register_tool(
        name=TOOL_INSPECT,
        toolset="hybridops",
        schema=INSPECT_SCHEMA,
        handler=service.inspect,
    )
    ctx.register_tool(
        name=TOOL_EXPORT,
        toolset="hybridops",
        schema=EXPORT_SCHEMA,
        handler=service.export,
    )
    ctx.register_tool(
        name=TOOL_IMPORT,
        toolset="hybridops",
        schema=IMPORT_SCHEMA,
        handler=service.import_,
    )
    ctx.register_hook("pre_tool_call", service.pre_tool_call)
