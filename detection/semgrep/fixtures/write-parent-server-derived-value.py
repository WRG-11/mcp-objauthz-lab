# Real-capture false-positive fixture for: mcp-write-parent-from-client-argument-py
#
# The Python sibling of write-parent-server-derived-value.js. The tenant kwarg is a
# server-side helper call (get_tenant_id()), not a caller argument. Must stay SILENT.
#
# Hardening: a tenant-key kwarg whose value is a call expression is excluded. The
# plain create(tenant_id=tenant_id) true positive (bare arg) is unaffected.


def make_context(req, user_id):
    # ok: mcp-write-parent-from-client-argument-py
    return identity_store.create_context(tenant_id=get_tenant_id(), user_id=user_id)
