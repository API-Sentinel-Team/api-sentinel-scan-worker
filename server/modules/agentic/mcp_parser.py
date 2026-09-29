"""MCP (JSON-RPC 2.0) request/response parser."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
import json


def _safe_json(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return {}
    return {}


def parse_mcp_invocation(
    request_body: Any,
    response_body: Any,
    headers: Optional[Dict[str, str]] = None,
    path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Parse MCP JSON-RPC request/response into a normalized invocation dict."""
    req = _safe_json(request_body)
    if req.get("jsonrpc") != "2.0" or "method" not in req:
        return None

    method = str(req.get("method"))
    params = req.get("params") or {}
    if isinstance(params, str):
        params = {"value": params}

    tool_name = method
    if method in ("tools/call", "tool.call", "tool.invoke") and isinstance(params, dict):
        tool_name = params.get("name") or params.get("tool") or tool_name

    resp = _safe_json(response_body)
    result = resp.get("result")
    result_text = ""
    if isinstance(result, dict):
        result_text = str(result.get("content") or result.get("text") or result)
    elif result is not None:
        result_text = str(result)

    headers = headers or {}
    agent_id = headers.get("x-agent-id") or headers.get("x-mcp-agent-id") or params.get("agent_id")
    declared_scope = _split_scope(headers.get("x-agent-scope") or headers.get("x-declared-scope"))
    effective_scope = _split_scope(headers.get("x-effective-scope"))
    parent_agent_id = headers.get("x-parent-agent-id") or params.get("parent_agent_id")
    human_principal = headers.get("x-human-principal") or params.get("human_principal")

    return {
        "agent_id": str(agent_id or "unknown"),
        "tool_name": str(tool_name),
        "parameters": params if isinstance(params, dict) else {},
        "result_text": result_text,
        "declared_scope": declared_scope,
        "effective_scope": effective_scope,
        "parent_agent_id": parent_agent_id,
        "human_principal": human_principal,
        "path": path,
    }


def _split_scope(value: Optional[str]) -> list:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]
