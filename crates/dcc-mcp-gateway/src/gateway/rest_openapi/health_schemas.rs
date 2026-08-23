use serde_json::{Value, json};

pub(super) fn gateway_health_schema() -> (&'static str, Value) {
    (
        "GatewayHealth",
        json!({
            "type": "object",
            "required": ["ok", "auth_enabled"],
            "properties": {
                "ok": {"type": "boolean"},
                "auth_enabled": {
                    "type": "boolean",
                    "description": "Whether bearer authentication is configured; this does not prove the caller is authorized."
                }
            },
            "additionalProperties": true,
        }),
    )
}

pub(super) fn gateway_readyz_schema() -> (&'static str, Value) {
    (
        "GatewayReadyz",
        json!({
            "type": "object",
            "required": [
                "ok",
                "auth_enabled",
                "checks",
                "live_instance_count",
                "ready_instance_count",
                "not_ready_instance_count",
                "dispatch_reported_instance_count",
                "dispatch_ready_instance_count",
                "dispatch_not_ready_instance_count",
                "gateway_recovery_driver_counts",
                "registration_refresh_mode_counts",
                "gateway_daemon_guardian_instance_count",
                "gateway_daemon_guardian_ready",
                "instances"
            ],
            "properties": {
                "ok": {"type": "boolean"},
                "auth_enabled": {
                    "type": "boolean",
                    "description": "Whether bearer authentication is configured; this does not prove the caller is authorized."
                },
                "checks": {
                    "type": "array",
                    "items": {"type": "object", "additionalProperties": true}
                },
                "live_instance_count": {"type": "integer", "minimum": 0},
                "ready_instance_count": {"type": "integer", "minimum": 0},
                "not_ready_instance_count": {"type": "integer", "minimum": 0},
                "dispatch_reported_instance_count": {"type": "integer", "minimum": 0},
                "dispatch_ready_instance_count": {"type": "integer", "minimum": 0},
                "dispatch_not_ready_instance_count": {"type": "integer", "minimum": 0},
                "gateway_recovery_driver_counts": {
                    "type": "object",
                    "additionalProperties": {"type": "integer", "minimum": 0}
                },
                "registration_refresh_mode_counts": {
                    "type": "object",
                    "additionalProperties": {"type": "integer", "minimum": 0}
                },
                "gateway_daemon_guardian_instance_count": {"type": "integer", "minimum": 0},
                "gateway_daemon_guardian_ready": {"type": "boolean"},
                "gateway_lifecycle": {
                    "type": "object",
                    "properties": {
                        "persist": {"type": "boolean"},
                        "idle_timeout_secs": {"type": "integer", "minimum": 0}
                    }
                },
                "instances": {
                    "type": "array",
                    "items": {"$ref": "#/components/schemas/GatewayInstance"}
                }
            },
            "additionalProperties": true,
        }),
    )
}
