# Real-capture fixture for rule: mcp-authz-scope-from-request-header-py
#
# From audit: real FastMCP servers read X-Forwarded-For for logging/analytics
# ONLY, not for authorization. The hardened rule must NOT fire on this pattern
# — it's the SILENT half of the two-way canary.
#
# SILENT: X-Forwarded-For read ONLY for logging, no authz decision.

from fastmcp.server.dependencies import get_http_headers


def log_request_for_analytics():
    # ok: mcp-authz-scope-from-request-header-py
    headers = get_http_headers()
    client_ip = headers.get("x-forwarded-for")
    logger.info("tool call", extra={"client_ip": client_ip, "event": "tool_call"})


def log_request_with_x_real_ip():
    # ok: mcp-authz-scope-from-request-header-py
    headers = get_http_headers()
    client_ip = headers.get("x-real-ip")
    logger.info("tool call", extra={"client_ip": client_ip, "event": "tool_call"})


def log_request_with_x_client_ip():
    # ok: mcp-authz-scope-from-request-header-py
    headers = get_http_headers()
    client_ip = headers.get("x-client-ip")
    logger.info("tool call", extra={"client_ip": client_ip, "event": "tool_call"})