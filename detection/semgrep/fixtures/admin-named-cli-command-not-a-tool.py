# Negative fixture for rule: mcp-admin-named-tool-missing-role-check-py
#
# A CLI command named "admin" is not an MCP tool. The typer decorator registers
# a local command; no MCP call reaches it, so a missing role check here is not
# a tool-authorization finding. Real-capture FP (2026-10-28): a loopback-only
# admin panel command shipped inside an MCP server repository.
import typer

app = typer.Typer()


@app.command()
# ok: mcp-admin-named-tool-missing-role-check-py
def admin(host: str = "127.0.0.1"):
    print(host)


@app.command()
# ok: mcp-admin-named-tool-missing-role-check-py
async def reset_admin_password(user: str):
    print(user)
