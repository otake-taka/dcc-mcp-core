"""Python E2E guard for native async status across the Core gateway REST seam."""

from __future__ import annotations

# Import built-in modules
import contextlib
import json
import time
from typing import Any
import urllib.error
import urllib.request

# Import third-party modules
import pytest

from conftest import allocate_gateway_port
from conftest import wait_tcp_reachable

# Import local modules
from dcc_mcp_core import McpHttpConfig
from dcc_mcp_core import McpHttpServer
from dcc_mcp_core import ToolRegistry


def _post_json(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


@pytest.fixture()
def async_gateway(tmp_path: Any) -> tuple[str, dict[str, Any]]:
    """Start one Blender sidecar that owns an async tool and the elected gateway."""
    gateway_port = allocate_gateway_port()
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir()

    registry = ToolRegistry()
    registry.register(
        "bake_preview",
        description="Bake a Blender preview asynchronously",
        dcc="blender",
        version="1.0.0",
        execution="async",
        thread_affinity="any",
    )
    config = McpHttpConfig(port=0, server_name="blender-async-status-test")
    config.gateway_port = gateway_port
    config.registry_dir = str(registry_dir)
    config.dcc_type = "blender"
    config.heartbeat_secs = 1
    config.stale_timeout_secs = 10

    server = McpHttpServer(registry, config)
    server.register_handler(
        "bake_preview",
        lambda params: (time.sleep(0.2), {"baked": params.get("scene", "preview")})[1],
    )
    handle = server.start()
    gateway_base = f"http://127.0.0.1:{gateway_port}"
    try:
        assert wait_tcp_reachable("127.0.0.1", handle.port), "sidecar port must be reachable"
        if not handle.is_gateway:
            pytest.skip(f"another process holds gateway port {gateway_port}")
        assert wait_tcp_reachable("127.0.0.1", gateway_port), "gateway port must be reachable"

        deadline = time.monotonic() + 10
        last_search: dict[str, Any] = {}
        while time.monotonic() < deadline:
            status, last_search = _post_json(
                f"{gateway_base}/v1/search",
                {"query": "bake preview", "dcc_type": "blender", "loaded_only": True},
            )
            hits = last_search.get("hits", [])
            match = next((hit for hit in hits if hit.get("backend_tool") == "bake_preview"), None)
            if status == 200 and match is not None:
                yield gateway_base, match
                return
            time.sleep(0.1)
        raise AssertionError(f"gateway did not discover the Blender async tool: {last_search}")
    finally:
        with contextlib.suppress(Exception):
            handle.shutdown()


def test_gateway_single_call_routes_return_native_accepted_status(
    async_gateway: tuple[str, dict[str, Any]],
) -> None:
    gateway_base, hit = async_gateway

    canonical_status, canonical_body = _post_json(
        f"{gateway_base}/v1/call",
        {"tool_slug": hit["tool_slug"], "arguments": {"scene": "canonical"}},
    )
    assert canonical_status == 202
    assert canonical_body["output"]["status"] == "pending"
    assert canonical_body["output"]["job_id"]

    instance_status, instance_body = _post_json(
        f"{gateway_base}/v1/dcc/blender/instances/{hit['instance_id']}/call",
        {"backend_tool": "bake_preview", "arguments": {"scene": "instance"}},
    )
    assert instance_status == 202
    assert instance_body["output"]["status"] == "pending"
    assert instance_body["output"]["job_id"]
