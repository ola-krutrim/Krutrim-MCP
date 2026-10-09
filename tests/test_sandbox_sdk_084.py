"""Sandbox features adopted from krutrim-client 0.8.x: image_uri, labels, 4xx detail."""

import json
from base64 import b64encode

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from tests.test_sandbox_lifecycle import CREATE, PREFIX, REGION, prepare_create
from tests.test_sandbox_lifecycle import harness as harness  # noqa: F401  (pytest fixture)


def _post(harness):
    posts = [r for r in harness.requests if r.method == "POST"]
    assert len(posts) == 1
    return json.loads(posts[0].content)


def test_create_sends_image_uri_and_labels(harness):
    prepare_create(harness)
    harness.call(
        "create_sandbox",
        **CREATE,
        image_uri="registry.example.com/team/app:1.2",
        labels={"team": "qa", "env": "stage"},
    )
    body = _post(harness)
    assert body["imageUri"] == "registry.example.com/team/app:1.2"
    assert body["labels"] == {"team": "qa", "env": "stage"}


def test_create_omits_image_uri_and_labels_when_not_given(harness):
    prepare_create(harness)
    harness.call("create_sandbox", **CREATE)
    body = _post(harness)
    assert "imageUri" not in body
    assert "labels" not in body


@pytest.mark.parametrize(
    "overrides",
    [
        {"labels": {f"k{i}": "v" for i in range(17)}},
        {"labels": {"": "v"}},
        {"labels": {"a=b": "v"}},
        {"labels": {"a,b": "v"}},
        {"labels": {"k" * 64: "v"}},
        {"labels": {"k": "v" * 256}},
        {"labels": {"k": "a,b"}},
        {"labels": {"k": 1}},
        {"image_uri": ""},
        {"image_uri": "has space:1"},
        {"image_uri": 17},
    ],
)
def test_create_rejects_invalid_labels_or_image_before_any_request(harness, overrides):
    with pytest.raises(ToolError):
        harness.call("create_sandbox", **CREATE, **overrides)
    assert harness.requests == []


def test_list_sends_label_selector(harness):
    harness.replies[("GET", f"{PREFIX}/sandbox")] = (
        200,
        {"status": 200, "data": {"rows": [], "total": 0}},
    )
    harness.call("list_sandboxes", region=REGION, labels={"team": "qa", "env": "stage"})
    (request,) = harness.requests
    assert request.url.params["labels"] == "team=qa,env=stage"


def test_list_omits_label_selector_by_default(harness):
    harness.replies[("GET", f"{PREFIX}/sandbox")] = (
        200,
        {"status": 200, "data": {"rows": [], "total": 0}},
    )
    harness.call("list_sandboxes", region=REGION)
    (request,) = harness.requests
    assert "labels" not in request.url.params


@pytest.mark.parametrize("labels", [{"a=b": "v"}, {"k": "a,b"}, {f"k{i}": "v" for i in range(17)}])
def test_list_rejects_invalid_label_filter_before_request(harness, labels):
    with pytest.raises(ToolError):
        harness.call("list_sandboxes", region=REGION, labels=labels)
    assert harness.requests == []


@pytest.mark.parametrize("status", [400, 422])
def test_validation_error_text_is_surfaced(harness, status):
    prepare_create(harness)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (
        status,
        {"error": 'invalid request payload: json: unknown field "templateId"'},
    )
    with pytest.raises(ToolError) as error:
        harness.call("create_sandbox", **CREATE)
    text = str(error.value)
    assert f"HTTP {status}" in text
    assert 'unknown field "templateId"' in text
    assert "withheld" not in text


@pytest.mark.parametrize("status", [401, 403, 404, 409, 500])
def test_non_validation_errors_stay_withheld(harness, status):
    prepare_create(harness)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (status, {"error": "private-detail"})
    with pytest.raises(ToolError) as error:
        harness.call("create_sandbox", **CREATE)
    assert "private-detail" not in str(error.value)
    assert "withheld" in str(error.value)


def test_validation_message_field_other_than_error_stays_withheld(harness):
    prepare_create(harness)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (400, {"message": "private-detail"})
    with pytest.raises(ToolError) as error:
        harness.call("create_sandbox", **CREATE)
    assert "private-detail" not in str(error.value)


def test_surfaced_error_redacts_env_values_plain_and_base64(harness):
    secret = "s3cr3t-value-123"
    encoded = b64encode(secret.encode()).decode()
    prepare_create(harness)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (
        400,
        {"error": f"bad value {secret} / {encoded} Bearer abc.def.ghi"},
    )
    with pytest.raises(ToolError) as error:
        harness.call("create_sandbox", **CREATE, environment_variables={"TOKEN": secret})
    text = str(error.value)
    assert secret not in text
    assert encoded not in text
    assert "abc.def.ghi" not in text
    assert "***REDACTED***" in text


def test_surfaced_error_is_bounded(harness):
    prepare_create(harness)
    harness.replies[("POST", f"{PREFIX}/sandbox")] = (400, {"error": "x" * 5000})
    with pytest.raises(ToolError) as error:
        harness.call("create_sandbox", **CREATE)
    assert len(str(error.value)) < 400


def test_template_catalog_still_fetched_raw_on_sdk_08(harness):
    harness.replies[("GET", f"{PREFIX}/template")] = httpx.Response(
        200,
        content=json.dumps([{"ID": 4, "template_name": "python"}]),
        headers={"content-type": "text/plain"},
    )
    result = harness.call("list_sandbox_templates")
    assert result is not None
    (request,) = harness.requests
    assert request.url.path == f"{PREFIX}/template"


BYOC_URL = (
    "https://docs.cloud.olakrutrim.com/basics/core-infrastructure/sandbox/"
    "bring-your-own-container-byoc"
)


def test_custom_image_guidance_points_agents_to_byoc_steps():
    from krutrim_mcp_server.config import Settings
    from krutrim_mcp_server.server import create_server

    server = create_server(Settings(
            api_key="test-key",
            base_url="https://example.invalid",
            default_region="In-Bangalore-1",
            read_only=False,
            log_level="WARNING",
            client_max_retries=0,
            tool_profile="admin",
        ))
    tool = server._tool_manager.get_tool("create_sandbox")
    image_doc = tool.parameters["properties"]["image_uri"]["description"]
    assert BYOC_URL in image_doc
    assert "sandbox-agent" in image_doc
    assert BYOC_URL in tool.description
    assert BYOC_URL in server.instructions
    assert "list_sandbox_templates; require explicit flavor and template" not in server.instructions
