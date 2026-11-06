from pathlib import Path
from uuid import uuid4


def save_requested_document(document_id: str, save_path: str, content: bytes) -> str:
    output_file = f"{save_path}/{document_id}.pdf"
    # ruleid: mcp-client-id-path-write-py
    with open(output_file, "wb") as handle:
        handle.write(content)
    return output_file


def save_generated_document(save_path: str, content: bytes) -> str:
    generated_name = uuid4().hex
    output_file = str(Path(save_path) / f"{generated_name}.pdf")
    # ok: mcp-client-id-path-write-py
    with open(output_file, "wb") as handle:
        handle.write(content)
    return output_file


def run_requested_code(code: str) -> None:
    # ruleid: mcp-dynamic-code-exec-py
    exec(code, {}, {})


def run_trusted_code() -> None:
    trusted_source = "result = 1"
    # ok: mcp-dynamic-code-exec-py
    exec(trusted_source, {}, {})


def fetch_requested_document(identifier: str, session, base_url: str):
    target_url = f"{base_url}/{identifier}"
    # ruleid: mcp-caller-url-http-request-py
    return session.get(target_url, timeout=5)


def fetch_health(session):
    # ok: mcp-caller-url-http-request-py
    return session.get("https://example.invalid/health", timeout=5)
