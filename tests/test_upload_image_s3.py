"""Wire-level tests for the upload_image_s3 tool."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import httpx
import pytest
from krutrim_client import KrutrimClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.server import Settings as FastMCPSettings

REGION = "In-Bangalore-1"
URL = "https://bucket.example.test/images/ubuntu.qcow2?X-Amz-Signature=abc"


@pytest.fixture
def wire(monkeypatch):
    images = importlib.import_module("krutrim_mcp_server.tools.compute.images")
    state = SimpleNamespace(requests=[], read_only=False)

    def handler(request: httpx.Request) -> httpx.Response:
        state.requests.append(request)
        return httpx.Response(202, json={"image_id": "img-1", "status": "queued"})

    client = KrutrimClient(
        api_key="mcp-token-not-for-custom-headers",
        base_url="https://cloud.example.test",
        max_retries=0,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    session = SimpleNamespace(get_client=lambda: client)
    monkeypatch.setattr(images, "get_session", lambda: session)
    monkeypatch.setattr(images, "settings", lambda: state)
    FastMCPSettings.model_rebuild()
    server = FastMCP("image-test")
    images.register(server)
    state.call = lambda **kwargs: server._tool_manager.get_tool("upload_image_s3").fn(**kwargs)
    yield state
    client.close()


def test_upload_image_s3_wire(wire):
    result = wire.call(image_url=URL, disk_format="qcow2", region=REGION, confirm=True)
    assert result.ok is True
    assert result.data == {"image_id": "img-1", "status": "queued"}
    assert len(wire.requests) == 1
    request = wire.requests[0]
    assert request.method == "POST"
    assert request.url.path.endswith(f"/vm/v1/image/bucket/{REGION}")
    assert request.headers["content-type"].startswith("multipart/form-data; boundary=")
    body = request.content.decode()
    assert 'name="diskFormat"' in body and "qcow2" in body
    assert 'name="image"' in body and URL in body


def test_upload_image_s3_normalizes_disk_format_case(wire):
    wire.call(image_url=URL, disk_format="QCOW2", region=REGION, confirm=True)
    assert "qcow2" in wire.requests[0].content.decode()


def test_upload_image_s3_requires_confirm(wire):
    with pytest.raises(ToolError, match="confirm=true"):
        wire.call(image_url=URL, disk_format="qcow2", region=REGION, confirm=False)
    assert wire.requests == []


def test_upload_image_s3_blocked_in_read_only_mode(wire):
    wire.read_only = True
    with pytest.raises(ToolError, match="KRUTRIM_MCP_READ_ONLY"):
        wire.call(image_url=URL, disk_format="qcow2", region=REGION, confirm=True)
    assert wire.requests == []


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        (dict(image_url="ftp://host/a.qcow2", disk_format="qcow2"), "http"),
        (dict(image_url="file:///etc/passwd", disk_format="raw"), "http"),
        (dict(image_url="  ", disk_format="qcow2"), "image_url"),
        (dict(image_url="https://host/a b.qcow2", disk_format="qcow2"), "whitespace"),
        (dict(image_url=URL, disk_format="exe"), "disk_format"),
        (dict(image_url=URL, disk_format="qcow2", region="Mars-1"), "unknown region"),
    ],
)
def test_upload_image_s3_rejects_bad_input_before_any_request(wire, kwargs, match):
    kwargs.setdefault("region", REGION)
    with pytest.raises(ToolError, match=match):
        wire.call(confirm=True, **kwargs)
    assert wire.requests == []
