"""Import-light sidecar dispatch readiness helpers."""

# ruff: noqa: UP006, UP045

# Import future modules
from __future__ import annotations

# Import built-in modules
import time
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
import urllib.error
import urllib.request
import uuid

ROLE_PER_DCC_SIDECAR = "per-dcc-sidecar"
DISPATCH_STATUS_BOOTING = "booting"
DISPATCH_STATUS_UNAVAILABLE = "unavailable"
DISPATCH_STATUS_AMBIGUOUS = "ambiguous"
RETRYABLE_HOST_RPC_SCHEMES = {"commandport", "qtserver", "ws", "wss"}
RETRYABLE_FAILURE_STAGES = {"host-rpc-connect"}
_PROBE_RESPONSE_MAX_BYTES = 1024 * 1024
_PROBE_TRANSPORT_DESYNC = object()


def sidecar_readiness_status(
    registry_dir: Optional[Any] = None,
    *,
    dcc_type: Optional[str] = None,
    instance_id: Optional[str] = None,
    host_rpc: Optional[str] = None,
    include_dead: bool = True,
    probe_tool: Optional[str] = None,
    probe_arguments: Optional[Dict[str, Any]] = None,
    probe_timeout_secs: float = 3.0,
) -> Dict[str, Any]:
    """Return a one-shot, import-light sidecar dispatch-readiness verdict."""
    state = _query_runtime_state(
        registry_dir,
        dcc_type=dcc_type,
        role=ROLE_PER_DCC_SIDECAR,
        include_dead=include_dead,
    )
    entries = _filter_sidecar_readiness_entries(
        state.get("entries", []),
        instance_id=instance_id,
        host_rpc=host_rpc,
    )
    selector = {
        "dcc_type": dcc_type,
        "instance_id": instance_id,
        "host_rpc": host_rpc,
    }

    if not entries:
        return {
            "success": False,
            "status": "missing",
            "ready": False,
            "selector": selector,
            "entries": [],
            "message": "No matching per-DCC sidecar is registered.",
            "recommended_next_action": "Launch the sidecar from the DCC startup hook, then check readiness again.",
        }

    ambiguity = _selector_ambiguity(entries, instance_id=instance_id, host_rpc=host_rpc)
    if ambiguity:
        return {
            "success": False,
            "status": DISPATCH_STATUS_AMBIGUOUS,
            "ready": False,
            "selector": selector,
            "entries": entries,
            "message": ambiguity["message"],
            "recommended_next_action": ambiguity["recommended_next_action"],
        }

    ready = [entry for entry in entries if entry.get("dispatch_ready") is True]
    if ready:
        probe = _maybe_probe_ready_entry(
            ready[0],
            probe_tool=probe_tool,
            probe_arguments=probe_arguments,
            probe_timeout_secs=probe_timeout_secs,
        )
        if probe and not probe.get("success"):
            transport_desync = probe.get("status") == "probe_transport_desync"
            return {
                "success": False,
                "status": probe.get("status", "probe_failed"),
                "ready": False,
                "selector": selector,
                "entry": ready[0],
                "entries": entries,
                "probe": probe,
                "message": (
                    "Sidecar dispatch metadata is ready, but the probe transport desynchronized."
                    if transport_desync
                    else "Sidecar dispatch metadata is ready, but the probe tool failed."
                ),
                "recommended_next_action": (
                    "Restart the sidecar or fix request-id correlation before checking readiness again."
                    if transport_desync
                    else (
                        "Fix the adapter dispatcher, loaded skills, or probe tool configuration, "
                        "then check readiness again."
                    )
                ),
            }
        return {
            "success": True,
            "status": "ready",
            "ready": True,
            "selector": selector,
            "entry": ready[0],
            "entries": entries,
            **({"probe": probe} if probe else {}),
            "message": "Sidecar dispatch is ready.",
            "recommended_next_action": "Use the shared gateway URL or the entry mcp_url for tool calls.",
        }

    unavailable = [entry for entry in entries if entry.get("dispatch_status") == DISPATCH_STATUS_UNAVAILABLE]
    if unavailable:
        entry = unavailable[0]
        return {
            "success": False,
            "status": "unavailable",
            "ready": False,
            "selector": selector,
            "entry": entry,
            "entries": entries,
            "failure_stage": entry.get("failure_stage"),
            "failure_reason": entry.get("failure_reason"),
            "message": "Sidecar registered, but host dispatch is unavailable.",
            "recommended_next_action": (
                "Fix the adapter host RPC bridge or dispatcher, restart the sidecar, then check readiness again."
            ),
        }

    alive = [entry for entry in entries if entry.get("runtime_alive") is not False]
    if alive:
        status = alive[0].get("dispatch_status") or DISPATCH_STATUS_BOOTING
        return {
            "success": False,
            "status": status,
            "ready": False,
            "selector": selector,
            "entry": alive[0],
            "entries": entries,
            "message": "Sidecar is registered but dispatch is not ready yet.",
            "recommended_next_action": (
                "Keep polling dispatch readiness or inspect failure metadata if it becomes unavailable."
            ),
        }

    return {
        "success": False,
        "status": "dead",
        "ready": False,
        "selector": selector,
        "entry": entries[0],
        "entries": entries,
        "message": "Matching sidecar rows are stale or their runtime process is not alive.",
        "recommended_next_action": "Restart the sidecar from the live DCC process.",
    }


def wait_for_sidecar_ready(
    registry_dir: Optional[Any] = None,
    *,
    dcc_type: Optional[str] = None,
    instance_id: Optional[str] = None,
    host_rpc: Optional[str] = None,
    timeout_secs: float = 10.0,
    poll_interval_secs: float = 0.25,
    probe_tool: Optional[str] = None,
    probe_arguments: Optional[Dict[str, Any]] = None,
    probe_timeout_secs: float = 3.0,
) -> Dict[str, Any]:
    """Poll sidecar readiness without importing native core code."""
    timeout = max(0.0, float(timeout_secs))
    poll_interval = max(0.05, float(poll_interval_secs))
    started = time.monotonic()
    deadline = started + timeout
    last = sidecar_readiness_status(
        registry_dir,
        dcc_type=dcc_type,
        instance_id=instance_id,
        host_rpc=host_rpc,
        include_dead=True,
        probe_tool=probe_tool,
        probe_arguments=probe_arguments,
        probe_timeout_secs=probe_timeout_secs,
    )

    while True:
        status = last.get("status")
        if (
            last.get("success")
            or status == DISPATCH_STATUS_AMBIGUOUS
            or (status == DISPATCH_STATUS_UNAVAILABLE and not _is_retryable_unavailable(last))
        ):
            last["elapsed_secs"] = round(time.monotonic() - started, 3)
            return last
        if time.monotonic() >= deadline:
            return {
                **last,
                "success": False,
                "ready": False,
                "status": "timeout",
                "last_status": status,
                "elapsed_secs": round(time.monotonic() - started, 3),
                "message": "Timed out waiting for sidecar dispatch readiness.",
                "recommended_next_action": (
                    "Check the sidecar registry row, host RPC endpoint, and adapter dispatcher logs."
                ),
            }
        time.sleep(poll_interval)
        last = sidecar_readiness_status(
            registry_dir,
            dcc_type=dcc_type,
            instance_id=instance_id,
            host_rpc=host_rpc,
            include_dead=True,
            probe_tool=probe_tool,
            probe_arguments=probe_arguments,
            probe_timeout_secs=probe_timeout_secs,
        )


def probe_sidecar_tool(
    mcp_url: str,
    tool_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    *,
    timeout_secs: float = 3.0,
) -> Dict[str, Any]:
    """Dispatch one ``tools/call`` readiness probe; this is not a general MCP client."""
    url = str(mcp_url or "").strip()
    name = str(tool_name or "").strip()
    if not url:
        return _probe_result(False, "probe_missing_url", "Sidecar entry has no mcp_url.", tool_name=name)
    if not name:
        return _probe_result(False, "probe_missing_tool", "No probe tool name was provided.", mcp_url=url)
    request_id = "sidecar-ready-probe-" + uuid.uuid4().hex
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments or {},
        },
    }
    body = _json_dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=max(0.1, float(timeout_secs))) as response:
            status_code = int(getattr(response, "status", 200))
            content_length = _probe_content_length(response)
            response_body = _read_probe_response(response)
            if response_body is None:
                return _probe_response_too_large(url, name, request_id, status_code)
            if content_length is not None and len(response_body) != content_length:
                return _probe_bad_response(url, name, request_id, status_code)
            parsed = _parse_probe_response(response, response_body, request_id)
            if parsed is _PROBE_TRANSPORT_DESYNC:
                return _probe_transport_desync(url, name, request_id, status_code)
    except urllib.error.HTTPError as exc:
        content_length = _probe_content_length(exc)
        response_body = _read_probe_response(exc)
        if response_body is None:
            return _probe_response_too_large(url, name, request_id, exc.code)
        if content_length is not None and len(response_body) != content_length:
            return _probe_bad_response(url, name, request_id, exc.code)
        parsed = _parse_probe_response(exc, response_body, request_id)
        if parsed is _PROBE_TRANSPORT_DESYNC:
            return _probe_transport_desync(url, name, request_id, exc.code)
        if not isinstance(parsed, dict):
            return _probe_bad_response(url, name, request_id, exc.code)
        return _probe_result(
            False,
            "probe_http_error",
            "Probe tool returned an HTTP error.",
            mcp_url=url,
            tool_name=name,
            request_id=request_id,
            http_status=exc.code,
            response=parsed,
        )
    except (OSError, ValueError) as exc:
        return _probe_result(
            False,
            "probe_unreachable",
            "Probe tool could not reach the sidecar MCP URL.",
            mcp_url=url,
            tool_name=name,
            request_id=request_id,
            error=str(exc),
        )

    if not isinstance(parsed, dict):
        return _probe_bad_response(url, name, request_id, status_code)
    if "error" in parsed:
        raw_error = parsed["error"]
        error: Dict[str, Any] = raw_error if isinstance(raw_error, dict) else {"message": raw_error}
        return _probe_result(
            False,
            "probe_failed",
            str(error.get("message") or "Probe tool returned a JSON-RPC error."),
            mcp_url=url,
            tool_name=name,
            request_id=request_id,
            http_status=status_code,
            error=error,
        )
    result: Dict[str, Any] = parsed["result"]
    if result.get("success") is False:
        return _probe_result(
            False,
            "probe_failed",
            str(result.get("message") or result.get("error") or "Probe tool returned success=false."),
            mcp_url=url,
            tool_name=name,
            request_id=request_id,
            http_status=status_code,
            result=result,
        )
    if result.get("isError") is True:
        return _probe_result(
            False,
            "probe_failed",
            str(result.get("message") or result.get("error") or "Probe tool returned isError=true."),
            mcp_url=url,
            tool_name=name,
            request_id=request_id,
            http_status=status_code,
            result=result,
        )
    return _probe_result(
        True,
        "probe_ok",
        "Probe tool succeeded.",
        mcp_url=url,
        tool_name=name,
        request_id=request_id,
        http_status=status_code,
        result=result,
    )


def _read_probe_response(response: Any) -> Optional[bytes]:
    body = response.read(_PROBE_RESPONSE_MAX_BYTES + 1)
    if len(body) > _PROBE_RESPONSE_MAX_BYTES:
        return None
    return body


def _probe_content_length(response: Any) -> Optional[int]:
    raw_value = getattr(response, "headers", {}).get("Content-Length")
    if raw_value is None:
        return None
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _parse_probe_response(response: Any, body: bytes, request_id: str) -> Any:
    content_type = str(getattr(response, "headers", {}).get("Content-Type", ""))
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        return None
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    parsed = _json_loads(decoded)
    if not isinstance(parsed, dict):
        return None
    if parsed.get("jsonrpc") != "2.0":
        return None
    if parsed.get("id") != request_id:
        return _PROBE_TRANSPORT_DESYNC
    has_result = "result" in parsed
    has_error = "error" in parsed
    if has_result == has_error:
        return None
    if has_result and not isinstance(parsed["result"], dict):
        return None
    if has_error and not isinstance(parsed["error"], dict):
        return None
    if has_error:
        error = parsed["error"]
        code = error.get("code")
        if not isinstance(code, int) or isinstance(code, bool) or not isinstance(error.get("message"), str):
            return None
    return parsed


def _probe_response_too_large(url: str, name: str, request_id: str, status_code: int) -> Dict[str, Any]:
    return _probe_result(
        False,
        "probe_response_too_large",
        "Probe tool response exceeded the 1 MiB limit.",
        mcp_url=url,
        tool_name=name,
        request_id=request_id,
        http_status=status_code,
    )


def _probe_bad_response(url: str, name: str, request_id: str, status_code: int) -> Dict[str, Any]:
    return _probe_result(
        False,
        "probe_bad_response",
        "Probe tool returned a non-JSON-RPC response.",
        mcp_url=url,
        tool_name=name,
        request_id=request_id,
        http_status=status_code,
    )


def _probe_transport_desync(url: str, name: str, request_id: str, status_code: int) -> Dict[str, Any]:
    return _probe_result(
        False,
        "probe_transport_desync",
        "Probe tool response did not echo the request id; transport desync.",
        mcp_url=url,
        tool_name=name,
        request_id=request_id,
        http_status=status_code,
    )


def _is_retryable_unavailable(result: Dict[str, Any]) -> bool:
    entry = result.get("entry") if isinstance(result.get("entry"), dict) else {}
    failure_stage = result.get("failure_stage") or entry.get("failure_stage")
    if failure_stage not in RETRYABLE_FAILURE_STAGES:
        return False
    scheme = entry.get("host_rpc_scheme") or _uri_scheme(entry.get("host_rpc_uri"))
    if not scheme:
        selector = result.get("selector") if isinstance(result.get("selector"), dict) else {}
        scheme = _uri_scheme(selector.get("host_rpc"))
    return str(scheme).lower() in RETRYABLE_HOST_RPC_SCHEMES


def _uri_scheme(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    if "://" not in text:
        return None
    return text.split("://", 1)[0].lower()


def _maybe_probe_ready_entry(
    entry: Dict[str, Any],
    *,
    probe_tool: Optional[str],
    probe_arguments: Optional[Dict[str, Any]],
    probe_timeout_secs: float,
) -> Optional[Dict[str, Any]]:
    if not probe_tool:
        return None
    return probe_sidecar_tool(
        str(entry.get("mcp_url") or ""),
        probe_tool,
        probe_arguments,
        timeout_secs=probe_timeout_secs,
    )


def _probe_result(success: bool, status: str, message: str, **extra: Any) -> Dict[str, Any]:
    result = {
        "success": success,
        "status": status,
        "message": message,
    }
    result.update({key: value for key, value in extra.items() if value is not None})
    return result


def _json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True)


def _json_loads(value: str) -> Any:
    import json

    try:
        return json.loads(value)
    except ValueError:
        return value


def _query_runtime_state(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    from ._install_lifecycle_runtime import query_runtime_state

    return query_runtime_state(*args, **kwargs)


def _filter_sidecar_readiness_entries(
    entries: Iterable[Dict[str, Any]],
    *,
    instance_id: Optional[str],
    host_rpc: Optional[str],
) -> List[Dict[str, Any]]:
    result = []
    instance_selector = str(instance_id).strip() if instance_id else None
    host_rpc_selector = str(host_rpc).strip() if host_rpc else None
    for entry in entries:
        if instance_selector and not _instance_id_matches(entry.get("instance_id"), instance_selector):
            continue
        if host_rpc_selector and entry.get("host_rpc_uri") != host_rpc_selector:
            continue
        result.append(entry)
    return result


def _selector_ambiguity(
    entries: List[Dict[str, Any]],
    *,
    instance_id: Optional[str],
    host_rpc: Optional[str],
) -> Optional[Dict[str, str]]:
    if len(entries) <= 1:
        return None
    instance_selector = str(instance_id).strip() if instance_id else None
    host_rpc_selector = str(host_rpc).strip() if host_rpc else None
    if not instance_selector and not host_rpc_selector:
        return None
    live_entries = [entry for entry in entries if entry.get("runtime_alive") is not False]
    if len(live_entries) <= 1:
        return None
    labels = []
    if instance_selector:
        labels.append("instance_id")
    if host_rpc_selector:
        labels.append("host_rpc")
    selector_name = " and ".join(labels)
    return {
        "message": (
            f"Multiple live per-DCC sidecars match the {selector_name} readiness selector; "
            "a direct-use readiness proof requires one matching sidecar."
        ),
        "recommended_next_action": (
            "Pass the full unique instance_id from build_sidecar_command().readiness_selector "
            "or make the host_rpc URI unique for this DCC instance, then check readiness again."
        ),
    }


def _instance_id_matches(value: Any, selector: str) -> bool:
    if value in (None, ""):
        return False
    text = str(value)
    return text == selector or text.startswith(selector)
