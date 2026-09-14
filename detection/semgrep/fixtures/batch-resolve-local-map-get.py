# Real-capture false-positive fixture for: mcp-batch-resolve-missing-per-item-scope-filter-py
#
# The Python sibling of batch-resolve-local-map-get.js. `[d.get(i) for i in ids]`
# over a local dict/cache already built from a scoped query is not a batch store
# fetch. A bare `.get` is dict access; a domain store method is suffixed
# (`store.get_note`). Must stay SILENT.
#
# Hardening: $METHOD must be a suffixed accessor (`^(get|find)[A-Za-z0-9_]+$`).


def batch_over_local_dict(ids, resolved_by_id):
    # ok: mcp-batch-resolve-missing-per-item-scope-filter-py
    return [resolved_by_id.get(i) for i in ids]
