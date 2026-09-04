#!/usr/bin/env python3
"""Dependency-free MEVA contract v2 checker.

This checker validates the shipped JSON Schema subset and the cross-record
semantic invariants that JSON Schema cannot express. It is defense in depth,
not a replacement for runtime sandboxing, trusted approval resolution, or
runtime-owned activation telemetry.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - the shipped atomic writer is POSIX-only.
    fcntl = None


EXPECTED_WORKERS = {
    "planner",
    "implementation_engineer",
    "platform_engineer",
    "validation_engineer",
    "reviewer",
}
READ_ONLY_ROLES = {"planner", "reviewer"}
READ_ONLY_ROLE_ACTIONS = {
    "planner": {"inspect", "plan"},
    "reviewer": {"inspect", "review", "audit"},
}
ROLE_MAX_ENVIRONMENTS = {
    "meva_orchestrator": {"local"},
    "planner": {
        "unit", "local", "ci", "replay", "simulation", "staging",
        "hardware_in_loop", "controlled_hardware", "edge", "production",
    },
    "reviewer": {
        "unit", "local", "ci", "replay", "simulation", "staging",
        "hardware_in_loop", "controlled_hardware", "edge", "production",
    },
    "implementation_engineer": {
        "unit", "local", "ci", "replay", "simulation", "staging",
        "hardware_in_loop", "production",
    },
    "validation_engineer": {
        "unit", "local", "ci", "replay", "simulation", "staging",
        "hardware_in_loop", "controlled_hardware",
    },
    "platform_engineer": {
        "unit", "local", "ci", "replay", "simulation", "staging",
        "hardware_in_loop", "controlled_hardware", "edge", "production",
    },
}
ROLE_MAX_EFFECTS = {
    "meva_orchestrator": {"project_read", "project_write"},
    "planner": {"project_read", "external_read"},
    "reviewer": {"project_read", "external_read"},
    "implementation_engineer": {"project_read", "project_write"},
    "validation_engineer": {"project_read", "project_write", "external_read"},
    "platform_engineer": {
        "project_read", "project_write", "external_read", "external_mutation",
    },
}
ROLE_KEYS = {
    "name",
    "description",
    "model_reasoning_effort",
    "sandbox_mode",
    "developer_instructions",
}
CONFIG_KEYS = {
    "agents": {
        "enabled",
        "max_concurrent_threads_per_session",
        "interrupt_message",
    },
}
TERMINAL_STATES = {"complete", "blocked"}
LEGAL_TRANSITIONS = {
    "intake": {"design", "awaiting_human", "blocked", "complete"},
    "design": {"ready", "awaiting_human", "blocked"},
    "ready": {"building", "awaiting_human", "blocked"},
    "building": {"validating", "awaiting_human", "blocked"},
    "validating": {"reviewing", "building", "awaiting_human", "blocked"},
    "reviewing": {
        "building",
        "validating",
        "awaiting_human",
        "releasing",
        "complete",
        "blocked",
    },
    "awaiting_human": {
        "design",
        "ready",
        "building",
        "validating",
        "reviewing",
        "releasing",
        "blocked",
    },
    "releasing": {"complete", "awaiting_human", "blocked"},
    "complete": set(),
    "blocked": set(),
}
PROVENANCE_KEYS = {
    "runtime",
    "model",
    "provider",
    "permission_mode",
    "sandbox_mode",
    "policy_digest",
    "config_digest",
    "manual_digest",
    "schema_digest",
    "role_digest",
    "ticket_digest",
    "attestation_source",
}
MAX_CONFIGURED_CONCURRENCY = 4
CORE_LOCAL_FALLBACK_NOTICE = (
    "runtime activation is unverified; bounded Core local project-write "
    "eligibility applies"
)
EXPECTED_PROTOCOL_DIGEST = "444bf9b0db6cea89afda56781de2f8279250dc4024a9db982ab6cee7ac38472b"
EXPECTED_PROTOCOL_HARNESS_DIGEST = "95fba374856aa37e02e907d5c141d70c3b643cc1a4789808fc67d2e72631292b"
EXPECTED_REVIEW_PROTOCOL_DIGEST = "bf9fbb45811e6edb7f1e796d53df564c1e57ae4330da659c6991e060510f02e1"
EXPECTED_REVIEW_HARNESS_DIGEST = "808112129f90f39a33e057d8f8f8ab144a15302f21a80d2d5f19db5ea07e4aab"
EXPECTED_ASSURANCE_PROTOCOL_DIGEST = "07baa7f12b50155ba449532ce24bd49a3c009adc4f430425c73c88ca46aa8e15"
EXPECTED_ASSURANCE_HARNESS_DIGEST = "b8c75adc1b35c416a87c5248dce448d5ce5c666c75b921f773e91db14ab04378"
EXPECTED_FINAL_REVIEW_PROTOCOL_DIGEST = "b08e03780d2af87bf2e7f35765e2a941544e502f71f02f9b46545b738f81767a"
EXPECTED_FINAL_REVIEW_HARNESS_DIGEST = "00b02c2b1ca1997ca5db82ae4108ac7c8df275139d6bdfe6670d0e70033707ad"
HANDOFF_TARGET_BYTES = 256
HANDOFF_HARD_LIMIT_BYTES = 512
EXPECTED_CLOSURE_PROTOCOL_DIGEST = "8aac0c9a6cc32b850b9b8961f5c7a35a447c0da9c11d79333ca6f7f38faff719"
EXPECTED_CLOSURE_LOCK_DIGEST = "a7af8daa459578a4ef99dc62a1d8f577d78fff24bbe88afcd690211d91aa0991"
EXPECTED_CLOSURE_HARNESS_DIGEST = "cffcbae412dd63b193d9e331b84c5150f5632f73508cb13f2100f348a9cfbbad"
EXPECTED_FINAL_REVIEW_REPORT_DIGEST = "2c73e72031c9f86323ed9975fea75819a7840009c8a151f49df297e3c3e1f0cc"
EXPECTED_AGENTS_DIGEST = "c8e6cc9e6353c2425868d2b2a8ca1da3d8956e2d512b95e51e3302d45267092d"
RELEASE_PRODUCT_BINDINGS = {
    "AGENTS.md",
    "README.md",
    ".codex/config.toml",
    ".codex/agents/planner.toml",
    ".codex/agents/implementation_engineer.toml",
    ".codex/agents/platform_engineer.toml",
    ".codex/agents/validation_engineer.toml",
    ".codex/agents/reviewer.toml",
    "contracts/meva.schema.json",
    "templates/project-state.json",
    "tools/meva_check.py",
    "docs/reviewer-handbook.md",
}
ORIGINAL_REPORT_BINDINGS = RELEASE_PRODUCT_BINDINGS | {
    "tests/conformance/protocol.v1.json",
    "tests/conformance/protocol.v1.sha256",
    "tests/conformance/test_contracts.py",
}
REVIEW_REPORT_BINDINGS = RELEASE_PRODUCT_BINDINGS | {
    "tests/conformance/protocol.v1.json",
    "tests/conformance/protocol.v1.sha256",
    "tests/conformance/test_contracts.py",
    "tests/conformance/review_protocol.v1.json",
    "tests/conformance/review_protocol.v1.sha256",
    "tests/conformance/test_review_contracts.py",
    "tests/conformance/assurance_protocol.v1.json",
    "tests/conformance/assurance_protocol.v1.sha256",
    "tests/conformance/test_assurance_contracts.py",
}
ASSURANCE_REPORT_BINDINGS = set(REVIEW_REPORT_BINDINGS)
FINAL_REVIEW_REPORT_BINDINGS = REVIEW_REPORT_BINDINGS | {
    "tests/conformance/final_review_protocol.v1.json",
    "tests/conformance/final_review_protocol.v1.sha256",
    "tests/conformance/test_final_review_contracts.py",
    "tests/conformance/validation-report.json",
    "tests/conformance/review-validation-report.json",
    "tests/conformance/assurance-validation-report.json",
}
SUPERSEDED_FINAL_REVIEW_TEST_IDS = {
    "tests.conformance.test_review_contracts.RV2LifecycleTests."
    "test_ac003_positive_r1_current_validation_and_review_gates",
    "tests.conformance.test_assurance_contracts.SemanticLifecycleTests."
    "test_exact_independent_completion_passes",
    "tests.conformance.test_assurance_contracts.SemanticFormalReviewTests."
    "test_exact_formal_review_passes",
}
CLOSURE_REPORT_BINDINGS = {
    "tools/meva_check.py",
    "contracts/meva.schema.json",
    "tests/conformance/closure_protocol.v1.json",
    "tests/conformance/closure_protocol.v1.sha256",
    "tests/conformance/test_closure_contracts.py",
    "tests/conformance/final-review-validation-report.json",
}
NONWAIVABLE_SAFETY_CONTROLS = {
    "emergency_stop",
    "hardware_emergency_stop",
    "software_emergency_stop",
    "deterministic_command_validation",
    "deterministic_safety_layer",
    "watchdog",
    "heartbeat",
    "collision_avoidance",
    "geofence",
}
ACCOUNTING_FIELDS = {
    "cost": "max_cost",
    "compute_units": "max_compute_units",
    "wall_time_seconds": "max_wall_time_seconds",
    "external_calls": "max_external_calls",
    "worker_fanout": "max_worker_fanout",
    "action_chain_steps": "max_action_chain_steps",
}


class ContractError(Exception):
    """Expected user-facing contract error."""


class CASConflict(ContractError):
    """The locked state no longer matches the caller's compare values."""


def _json_output(payload: Mapping[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _loads_strict_json(text: str, source: str) -> Any:
    def reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        value: Dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ContractError("duplicate JSON key {!r} in {}".format(key, source))
            value[key] = item
        return value

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ContractError("non-finite JSON number {!r} in {}".format(value, source))
            ),
        )
    except json.JSONDecodeError as exc:
        raise ContractError(
            "invalid JSON {}:{}:{}: {}".format(source, exc.lineno, exc.colno, exc.msg)
        ) from exc


def _load_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ContractError("missing JSON file: {}".format(path)) from exc
    return _loads_strict_json(text, str(path))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manual_path_for_digest(declared: str, root: Path = Path(".")) -> Path:
    """Use AGENTS.md; recognize Agent.md only for legacy state migration."""

    canonical = root / "AGENTS.md"
    if canonical.is_file() and _digests_equal(declared, _sha256(canonical)):
        return canonical
    legacy = root / "Agent.md"
    if legacy.is_file() and _digests_equal(declared, _sha256(legacy)):
        return legacy
    return canonical


def _canonical_digest(value: str) -> Optional[str]:
    """Return the canonical raw SHA-256 value, or None for unknown/invalid."""

    if not isinstance(value, str) or value == "unknown":
        return None
    raw = value[7:] if value.startswith("sha256:") else value
    return raw if re.fullmatch(r"[a-f0-9]{64}", raw) else None


def _digests_equal(first: str, second: str) -> bool:
    left = _canonical_digest(first)
    right = _canonical_digest(second)
    return left is not None and left == right


def _resolve_ref(root_schema: Mapping[str, Any], ref: str) -> Mapping[str, Any]:
    if not ref.startswith("#/"):
        raise ContractError("only local JSON Schema references are supported: {}".format(ref))
    current: Any = root_schema
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or part not in current:
            raise ContractError("unresolved JSON Schema reference: {}".format(ref))
        current = current[part]
    if not isinstance(current, Mapping):
        raise ContractError("JSON Schema reference is not an object: {}".format(ref))
    return current


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    return False


def validate_json_schema(
    instance: Any,
    schema: Mapping[str, Any],
    root_schema: Optional[Mapping[str, Any]] = None,
    path: str = "$",
) -> List[str]:
    """Validate the Draft 2020-12 keywords used by the shipped schema."""

    root = root_schema or schema
    errors: List[str] = []

    if "$ref" in schema:
        errors.extend(validate_json_schema(instance, _resolve_ref(root, schema["$ref"]), root, path))

    if "const" in schema and instance != schema["const"]:
        errors.append("{}: expected constant {!r}".format(path, schema["const"]))
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("{}: value {!r} is not in canonical enum".format(path, instance))

    expected_types = schema.get("type")
    if expected_types is not None:
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        if not any(_type_matches(instance, item) for item in expected_types):
            errors.append(
                "{}: expected type {}, got {}".format(
                    path, "|".join(expected_types), type(instance).__name__
                )
            )
            return errors

    if "allOf" in schema:
        for index, subschema in enumerate(schema["allOf"]):
            errors.extend(validate_json_schema(instance, subschema, root, path))
    if "anyOf" in schema:
        candidates = [
            validate_json_schema(instance, subschema, root, path)
            for subschema in schema["anyOf"]
        ]
        if not any(not candidate for candidate in candidates):
            errors.append("{}: no anyOf branch matched".format(path))
    if "oneOf" in schema:
        matches = sum(
            not validate_json_schema(instance, subschema, root, path)
            for subschema in schema["oneOf"]
        )
        if matches != 1:
            errors.append("{}: expected exactly one oneOf branch, got {}".format(path, matches))
    if "not" in schema and not validate_json_schema(instance, schema["not"], root, path):
        errors.append("{}: matched prohibited schema".format(path))
    if "if" in schema:
        condition_matches = not validate_json_schema(instance, schema["if"], root, path)
        branch = schema.get("then") if condition_matches else schema.get("else")
        if branch is not None:
            errors.extend(validate_json_schema(instance, branch, root, path))

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                errors.append("{}: missing required field {!r}".format(path, key))
        properties = schema.get("properties", {})
        for key, value in instance.items():
            child_path = "{}.{}".format(path, key)
            if key in properties:
                errors.extend(validate_json_schema(value, properties[key], root, child_path))
            elif "additionalProperties" in schema:
                additional = schema["additionalProperties"]
                if additional is False:
                    errors.append("{}: unknown field".format(child_path))
                elif isinstance(additional, Mapping):
                    errors.extend(validate_json_schema(value, additional, root, child_path))

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append("{}: fewer than {} items".format(path, schema["minItems"]))
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append("{}: more than {} items".format(path, schema["maxItems"]))
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
            if len(encoded) != len(set(encoded)):
                errors.append("{}: items must be unique".format(path))
        if "items" in schema:
            for index, value in enumerate(instance):
                errors.extend(
                    validate_json_schema(value, schema["items"], root, "{}[{}]".format(path, index))
                )

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append("{}: shorter than {} characters".format(path, schema["minLength"]))
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append("{}: longer than {} characters".format(path, schema["maxLength"]))
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append("{}: does not match required pattern".format(path))

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if not math.isfinite(instance):
            errors.append("{}: number must be finite".format(path))
            return errors
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("{}: below minimum {}".format(path, schema["minimum"]))
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append("{}: above maximum {}".format(path, schema["maximum"]))

    return errors


def _parse_utc(value: str) -> Optional[datetime]:
    if value == "unknown":
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _now(value: Optional[str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = _parse_utc(value)
    if parsed is None:
        raise ContractError("--now must be an RFC3339 UTC timestamp")
    return parsed


def _relative_path_error(path: str) -> Optional[str]:
    if not isinstance(path, str) or not path:
        return "empty path is forbidden"
    if "\\" in path:
        return "backslashes are not canonical"
    if path != "." and any(part in {"", ".", ".."} for part in path.split("/")):
        return "dot, empty, and traversal segments are forbidden"
    pure = PurePosixPath(path)
    if pure.is_absolute():
        return "absolute paths are forbidden"
    if ".." in pure.parts:
        return "parent traversal is forbidden"
    return None


def _path_within(path: str, scopes: Sequence[str]) -> bool:
    candidate = PurePosixPath(path)
    for scope in scopes:
        base = PurePosixPath(scope)
        if scope == "." or candidate == base:
            return True
        try:
            candidate.relative_to(base)
            return True
        except ValueError:
            pass
    return False


def _paths_overlap(first: str, second: str) -> bool:
    """Return whether normalized relative scopes are equal or parent/child."""

    left = PurePosixPath(first)
    right = PurePosixPath(second)
    if left == right or first == "." or second == ".":
        return True
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _duplicates(values: Iterable[str]) -> Set[str]:
    seen: Set[str] = set()
    duplicates: Set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _check_cycles(graph: Mapping[str, Sequence[str]], label: str) -> List[str]:
    errors: List[str] = []
    visiting: Set[str] = set()
    visited: Set[str] = set()

    def visit(node: str, trail: List[str]) -> None:
        if node in visiting:
            errors.append("{} dependency cycle: {}".format(label, " -> ".join(trail + [node])))
            return
        if node in visited:
            return
        visiting.add(node)
        for dependency in graph.get(node, []):
            if dependency not in graph:
                errors.append("{} {} references unknown dependency {}".format(label, node, dependency))
            else:
                visit(dependency, trail + [node])
        visiting.remove(node)
        visited.add(node)

    for item in graph:
        visit(item, [])
    return errors


def _records_by_id(records: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {str(record["id"]): record for record in records}


def _explicit_owner_instance(task: Mapping[str, Any]) -> Optional[str]:
    """Return an explicitly declared owner instance, preserving invalid empties."""

    if "owner_instance_id" in task:
        value = task.get("owner_instance_id")
    elif "owner_instance_id" in task.get("extensions", {}):
        value = task["extensions"].get("owner_instance_id")
    else:
        return None
    return value if isinstance(value, str) else ""


def _effective_owner_instance(
    state: Mapping[str, Any],
    task: Mapping[str, Any],
    role: str,
    now: datetime,
) -> Tuple[Optional[str], Optional[str]]:
    explicit = _explicit_owner_instance(task)
    if explicit is not None:
        if not explicit or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", explicit) is None:
            return None, "explicit owner instance identity is empty or malformed"
        return explicit, None
    candidates = []
    ticket_digest = hashlib.sha256(
        json.dumps(task, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    for item in state["permission_attestations"]:
        expiry = _parse_utc(item["expires_at"])
        observed = _parse_utc(item["observed_at"])
        if (
            item["role"] == role
            and item["task_id"] == task["id"]
            and item["project_id"] == state["project"]["id"]
            and item["source_kind"] == "runtime_owned"
            and item["status"] == "current"
            and item["fresh_session"]
            and _digests_equal(item["ticket_digest"], ticket_digest)
            and observed is not None
            and observed <= now
            and expiry is not None
            and now < expiry
        ):
            candidates.append(item["id"])
    if len(candidates) != 1:
        return None, "owner instance identity requires exactly one current exact runtime attestation"
    return candidates[0], None


def _nonwaivable_finding_reason(finding: Mapping[str, Any]) -> Optional[str]:
    extension = finding.get("extensions", {})
    controls = {
        str(item).strip().lower()
        for item in extension.get("required_controls", [])
        if isinstance(item, str)
    }
    if finding["severity"] == "critical" and finding["category"] == "safety":
        return "critical safety findings are non-waivable"
    if controls & NONWAIVABLE_SAFETY_CONTROLS or any(
        "emergency_stop" in item
        or "deterministic" in item
        or item.startswith("live_")
        for item in controls
    ):
        return "deterministic or live safety controls are non-waivable"
    operation = extension.get("affected_operation", {})
    if isinstance(operation, Mapping) and finding["category"] == "safety":
        action = str(operation.get("action_kind", "")).lower()
        environment = operation.get("environment")
        target = operation.get("structured_target", {})
        target_kind = (
            str(target.get("kind", "")).lower()
            if isinstance(target, Mapping)
            else ""
        )
        if (
            environment in {"hardware_in_loop", "controlled_hardware", "edge", "production"}
            or any(token in action for token in ("actuat", "motion", "hardware"))
            or target_kind in {"actuator", "robot", "hardware", "vehicle"}
        ):
            return "live embodied safety findings are non-waivable"
    if extension.get("waivability") == "non_waivable":
        return "finding is declared non-waivable"
    return None


def _approval_operation_limit_errors(
    operation: Mapping[str, Any], approval: Mapping[str, Any]
) -> List[str]:
    errors: List[str] = []
    operation_limits = operation.get("limits")
    approval_limits = approval.get("limits")
    if not isinstance(operation_limits, Mapping) or not isinstance(
        approval_limits, Mapping
    ):
        return ["affected operation and approval limits must be structured objects"]
    for key, expected in operation_limits.items():
        if key not in approval_limits:
            errors.append("approval lacks affected-operation limit {}".format(key))
            continue
        actual = approval_limits[key]
        numeric = (
            isinstance(expected, (int, float))
            and not isinstance(expected, bool)
        )
        if numeric:
            if (
                not isinstance(actual, (int, float))
                or isinstance(actual, bool)
                or not math.isfinite(float(actual))
                or actual > expected
            ):
                errors.append(
                    "approval limit {} is broader than affected operation".format(key)
                )
        elif expected is None:
            if actual is not None and (
                not isinstance(actual, (int, float))
                or isinstance(actual, bool)
                or not math.isfinite(float(actual))
                or actual < 0
            ):
                errors.append("approval limit {} is invalid".format(key))
        elif actual != expected:
            errors.append(
                "approval limit {} mismatches affected operation".format(key)
            )
    return errors


def _accounting_errors(
    accounting: Mapping[str, Any],
    path: str,
    allow_hard_overrun: bool = False,
) -> List[str]:
    errors: List[str] = []
    budget = accounting["budget"]
    usage = accounting["usage"]
    if budget["max_retries_per_operation"] > 1:
        errors.append("{}: identical retry limit may not exceed one".format(path))
    if budget["max_alternative_attempts"] > 1:
        errors.append("{}: materially different alternative limit may not exceed one".format(path))
    if (
        budget["max_delegation_depth"] is not None
        and budget["max_delegation_depth"] > 2
    ):
        errors.append("{}: delegation depth may not exceed two".format(path))

    pairs = {
        "cost": "max_cost",
        "compute_units": "max_compute_units",
        "wall_time_seconds": "max_wall_time_seconds",
        "external_calls": "max_external_calls",
        "worker_fanout": "max_worker_fanout",
        "delegation_depth": "max_delegation_depth",
        "retries_current_operation": "max_retries_per_operation",
        "alternative_attempts": "max_alternative_attempts",
        "action_chain_steps": "max_action_chain_steps",
    }
    ratios: List[float] = []
    for usage_key, limit_key in pairs.items():
        limit = budget[limit_key]
        used = usage[usage_key]
        if not isinstance(used, (int, float)) or isinstance(used, bool) or not math.isfinite(used) or used < 0:
            errors.append("{}: {} usage must be finite and nonnegative".format(path, usage_key))
            continue
        if limit is not None and (
            not isinstance(limit, (int, float))
            or isinstance(limit, bool)
            or not math.isfinite(limit)
            or limit < 0
        ):
            errors.append("{}: {} limit must be finite and nonnegative".format(path, limit_key))
            continue
        if limit is None:
            continue
        if used > limit and not allow_hard_overrun:
            errors.append(
                "{}: {} usage {} exceeds hard limit {}".format(path, usage_key, used, limit)
            )
        if usage_key == "action_chain_steps":
            continue
        if limit == 0:
            if used > 0:
                ratios.append(float("inf"))
        else:
            ratios.append(float(used) / float(limit))
    if ratios and max(ratios) >= 0.70:
        if not accounting["notified_at_70_percent"]:
            errors.append("{}: >=70% use requires notification".format(path))
        if not accounting["reestimated_at_70_percent"]:
            errors.append("{}: >=70% use requires re-estimate".format(path))
    return errors


def _formal_review_contract_errors(
    state: Mapping[str, Any],
    now: datetime,
    allowed_task_statuses: Set[str],
) -> List[str]:
    """Validate the state-bound, read-only proof shared by formal review gates."""

    errors: List[str] = []
    review = state["review"]
    extension = review.get("extensions", {})
    if extension.get("mode") != "formal":
        return ["formal review mode is required"]
    if extension.get("gate_result_emitted") is not True:
        errors.append("formal review must explicitly emit a gate result")
    if extension.get("state_revision") != state["state"]["revision"]:
        errors.append("formal review does not bind the current state revision")
    if (
        extension.get("invalidation_revision")
        != state["state"]["current_invalidation_revision"]
    ):
        errors.append("formal review does not bind the current invalidation revision")
    if not review["target_artifact_ids"]:
        errors.append("formal review target_artifact_ids must be nonempty")
    if not review["target_evidence_ids"]:
        errors.append("formal review target_evidence_ids must be nonempty")

    artifacts = _records_by_id(state["artifacts"])
    evidence = _records_by_id(state["evidence"])
    for artifact_id in review["target_artifact_ids"]:
        artifact = artifacts.get(artifact_id)
        if artifact is None:
            errors.append("formal review targets unknown artifact {}".format(artifact_id))
        elif artifact["status"] != "current":
            errors.append("formal review targets noncurrent artifact {}".format(artifact_id))
    for evidence_id in review["target_evidence_ids"]:
        item = evidence.get(evidence_id)
        if item is None:
            errors.append("formal review targets unknown evidence {}".format(evidence_id))
        elif (
            item["status"] != "current"
            or item["result"] != "pass"
            or item["invalidation_revision"]
            != state["state"]["current_invalidation_revision"]
            or item.get("extensions", {}).get("state_revision")
            != state["state"]["revision"]
        ):
            errors.append(
                "formal review targets stale or nonpassing evidence {}".format(
                    evidence_id
                )
            )

    task_id = extension.get("task_id")
    tasks = [
        task
        for task in state["tasks"]
        if task["accountable_owner"] == "reviewer"
        and task["status"] in allowed_task_statuses
        and (task_id is None or task["id"] == task_id)
    ]
    if len(tasks) != 1:
        errors.append("formal review does not bind one eligible reviewer task")
        return errors
    task = tasks[0]
    current_artifact_ids = {
        artifact_id
        for artifact_id, artifact in artifacts.items()
        if artifact["status"] == "current"
    }
    declared_artifact_ids = {
        item["artifact"]
        for item in task["inputs"]
        if item["artifact"] in current_artifact_ids
    }
    omitted_artifact_ids = declared_artifact_ids - set(
        review["target_artifact_ids"]
    )
    if omitted_artifact_ids:
        errors.append(
            "formal review omits ticket-declared current artifacts {}".format(
                sorted(omitted_artifact_ids)
            )
        )
    try:
        attestation = _selected_permission_attestation(
            state, "reviewer", task["id"], now
        )
    except ContractError as exc:
        errors.append("formal review {}".format(exc))
        return errors
    if (
        attestation["source_kind"] != "runtime_owned"
        or attestation["status"] != "current"
        or not attestation["fresh_session"]
    ):
        errors.append("formal review lacks a current runtime-owned fresh-session attestation")
    observed = _parse_utc(attestation["observed_at"])
    expires = _parse_utc(attestation["expires_at"])
    if observed is None or expires is None or observed > now or now >= expires:
        errors.append("formal reviewer attestation is outside its validity interval")
    permissions = attestation["effective_permissions"]
    if (
        task["writable_scope"]
        or task["changed_paths"]
        or permissions["writable_scopes"]
        or permissions.get("external_mutation", False)
        or not set(task["allowed_actions"]).issubset(
            READ_ONLY_ROLE_ACTIONS["reviewer"]
        )
        or not set(permissions["actions"]).issubset(
            READ_ONLY_ROLE_ACTIONS["reviewer"]
        )
    ):
        errors.append("formal review lacks effective read-only enforcement")
    owner_instance, owner_error = _effective_owner_instance(
        state, task, "reviewer", now
    )
    if (
        owner_error
        or owner_instance is None
        or review["reviewer"] != owner_instance
    ):
        errors.append("formal reviewer identity is not the exact owner instance")
    ticket_digest = hashlib.sha256(
        json.dumps(task, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if not _digests_equal(attestation["ticket_digest"], ticket_digest):
        errors.append("formal review attestation does not bind the exact ticket")
    if attestation["role_digest"] == "unknown":
        errors.append("formal review lacks reviewer role provenance")
    for key in (
        "runtime",
        "model",
        "provider",
        "policy_digest",
        "config_digest",
        "manual_digest",
        "schema_digest",
    ):
        canonical = state["provenance"][key]
        attested = attestation[key]
        equal = (
            _digests_equal(canonical, attested)
            if key.endswith("_digest")
            else canonical == attested
        )
        if canonical == "unknown" or attested == "unknown" or not equal:
            errors.append("formal review lacks current {} provenance".format(key))
    return errors


def _semantic_state_errors(state: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    ledger = state.get("action_ledger")
    recovery_task_ids = {
        item["task_id"]
        for item in ledger.get("reservations", [])
        if item["status"] == "recovery_required"
    } if ledger is not None else set()

    collections = [
        "requirements",
        "interfaces",
        "tasks",
        "gates",
        "artifacts",
        "evidence",
        "findings",
        "invalidations",
        "permission_attestations",
        "persistent_resources",
    ]
    all_ids: List[str] = []
    for collection in collections:
        ids = [str(record["id"]) for record in state[collection]]
        duplicates = _duplicates(ids)
        if duplicates:
            errors.append("{} contains duplicate ids: {}".format(collection, sorted(duplicates)))
        all_ids.extend(ids)
    global_duplicates = _duplicates(all_ids)
    if global_duplicates:
        errors.append("record ids are not globally unique: {}".format(sorted(global_duplicates)))

    for key in ("scopes",):
        for path in state["authority"][key]:
            problem = _relative_path_error(path)
            if problem:
                errors.append("authority.{} {!r}: {}".format(key, path, problem))

    tasks = _records_by_id(state["tasks"])
    errors.extend(
        _check_cycles(
            {task_id: list(task["dependencies"]) for task_id, task in tasks.items()},
            "task",
        )
    )
    for task_id, task in tasks.items():
        for key in ("writable_scope", "changed_paths"):
            for path in task[key]:
                problem = _relative_path_error(path)
                if problem:
                    errors.append("task {} {} {!r}: {}".format(task_id, key, path, problem))
        if task["accountable_owner"] in READ_ONLY_ROLES:
            if task["writable_scope"]:
                errors.append("read-only task {} must have writable_scope []".format(task_id))
            if task["changed_paths"]:
                errors.append("read-only task {} must have changed_paths []".format(task_id))
            if task["authored_artifact_ids"]:
                errors.append("read-only task {} may not author artifacts".format(task_id))
        for changed in task["changed_paths"]:
            if not _path_within(changed, task["writable_scope"]):
                errors.append(
                    "task {} changed path {!r} is outside writable_scope".format(task_id, changed)
                )
        errors.extend(
            _accounting_errors(
                task["accounting"],
                "task {} accounting".format(task_id),
                task_id in recovery_task_ids,
            )
        )

    active_writers = [
        task
        for task in state["tasks"]
        if task["status"] != "complete" and task["writable_scope"]
    ]
    for index, first in enumerate(active_writers):
        for second in active_writers[index + 1 :]:
            overlaps = [
                (left, right)
                for left in first["writable_scope"]
                for right in second["writable_scope"]
                if _paths_overlap(left, right)
            ]
            if overlaps:
                errors.append(
                    "active writer tasks {} ({}, owner instance {!r}) and {} "
                    "({}, owner instance {!r}) have overlapping writable scopes {}".format(
                        first["id"],
                        first["accountable_owner"],
                        _explicit_owner_instance(first),
                        second["id"],
                        second["accountable_owner"],
                        _explicit_owner_instance(second),
                        overlaps,
                    )
                )

    errors.extend(
        _accounting_errors(
            state["accounting"],
            "project accounting",
            bool(recovery_task_ids),
        )
    )
    if ledger is not None:
        reservation_ids = [item["id"] for item in ledger["reservations"]]
        if _duplicates(reservation_ids):
            errors.append("action ledger contains duplicate reservation ids")
        idempotency_keys = [
            item["idempotency_key"] for item in ledger["reservations"]
        ]
        if _duplicates(idempotency_keys):
            errors.append("action ledger contains duplicate idempotency keys")
        reconciliation_ids = [
            item["reconciliation_id"]
            for item in ledger["reservations"]
            if item["reconciliation_id"]
        ]
        if _duplicates(reconciliation_ids):
            errors.append("action ledger contains duplicate reconciliation ids")
        if ledger["revision"] < len(ledger["reservations"]):
            errors.append("action ledger revision is older than its reservations")
        zero_amounts = {key: 0 for key in ACCOUNTING_FIELDS}
        for reservation in ledger["reservations"]:
            reservation_task = tasks.get(reservation["task_id"])
            if reservation_task is None:
                errors.append(
                    "reservation {} references unknown task".format(reservation["id"])
                )
            else:
                role = reservation_task["accountable_owner"]
                if (
                    reservation["environment"]
                    not in ROLE_MAX_ENVIRONMENTS.get(role, set())
                ):
                    errors.append(
                        "reservation {} environment is outside role maximum".format(
                            reservation["id"]
                        )
                    )
                if (
                    reservation["effect"]
                    not in ROLE_MAX_EFFECTS.get(role, set())
                ):
                    errors.append(
                        "reservation {} effect is outside role maximum".format(
                            reservation["id"]
                        )
                    )
                if (
                    role == "implementation_engineer"
                    and reservation["environment"] == "production"
                    and reservation["effect"] != "project_write"
                ):
                    errors.append(
                        "reservation {} exceeds scoped implementation "
                        "production authority".format(reservation["id"])
                    )
                if (
                    reservation["environment"] == "production"
                    or reservation["effect"]
                    in {"external_mutation", "physical"}
                ):
                    approval_ids = reservation["extensions"].get(
                        "authorization_approval_ids"
                    )
                    if (
                        not reservation_task["approvals_required"]
                        or not isinstance(approval_ids, list)
                        or not approval_ids
                        or not set(approval_ids).issubset(
                            set(reservation_task["approvals_required"])
                        )
                    ):
                        errors.append(
                            "reservation {} lacks task-bound authorization approvals".format(
                                reservation["id"]
                            )
                        )
            if (
                reservation["effect"] == "external_read"
                and reservation["reserved"]["external_calls"] < 1
            ):
                errors.append(
                    "reservation {} external read reserves zero calls".format(
                        reservation["id"]
                    )
                )
            if _canonical_digest(reservation["state_digest"]) is None:
                errors.append(
                    "reservation {} has invalid state digest".format(reservation["id"])
                )
            if _canonical_digest(reservation["request_digest"]) is None:
                errors.append(
                    "reservation {} has invalid request digest".format(
                        reservation["id"]
                    )
                )
            target_path = reservation["target"].get("path")
            if target_path is not None:
                problem = _relative_path_error(target_path)
                if problem:
                    errors.append(
                        "reservation {} target path: {}".format(
                            reservation["id"], problem
                        )
                    )
            target_digest = reservation["target"].get("expected_digest")
            if target_digest is not None and _canonical_digest(target_digest) is None:
                errors.append(
                    "reservation {} has invalid target expected digest".format(
                        reservation["id"]
                    )
                )
            for amount_group in ("reserved", "actual"):
                for key, value in reservation[amount_group].items():
                    if (
                        not isinstance(value, (int, float))
                        or isinstance(value, bool)
                        or not math.isfinite(value)
                        or value < 0
                    ):
                        errors.append(
                            "reservation {} {} {} must be finite and nonnegative".format(
                                reservation["id"], amount_group, key
                            )
                        )
            if reservation["status"] == "reconciled" and any(
                reservation["actual"][key] > reservation["reserved"][key]
                for key in ACCOUNTING_FIELDS
            ):
                errors.append(
                    "reservation {} overrun must be recovery_required".format(
                        reservation["id"]
                    )
                )
        for task in tasks.values():
            if task["id"] not in recovery_task_ids:
                errors.extend(
                    _reservation_capacity_errors(
                        state, task, ledger, zero_amounts, "cleanup"
                    )
                )

    history = state["state"]["history"]
    previous_to: Optional[str] = None
    previous_revision = 0
    for index, transition in enumerate(history):
        source = transition["from"]
        target = transition["to"]
        revision = transition["revision"]
        if revision <= previous_revision:
            errors.append("state.history[{}]: revisions must strictly increase".format(index))
        if previous_to is not None and source != previous_to:
            errors.append("state.history[{}]: transition chain is discontinuous".format(index))
        if target not in LEGAL_TRANSITIONS[source]:
            errors.append("state.history[{}]: illegal transition {} -> {}".format(index, source, target))
        if source in TERMINAL_STATES:
            errors.append("state.history[{}]: terminal state may not resume".format(index))
        if source == "intake" and target == "complete" and state["project"]["risk_tier"] != "R0":
            errors.append("intake -> complete is allowed only for the R0 no-delegation fast path")
        previous_to = target
        previous_revision = revision
    if history and state["state"]["status"] != history[-1]["to"]:
        errors.append("state.status does not match the last transition")
    if state["state"]["revision"] < previous_revision:
        errors.append("state.revision is older than transition history")

    artifacts = _records_by_id(state["artifacts"])
    evidence = _records_by_id(state["evidence"])
    findings = _records_by_id(state["findings"])
    dependency_records: Dict[str, Mapping[str, Any]] = {}
    for collection in (
        "requirements",
        "interfaces",
        "decisions",
        "tasks",
        "artifacts",
        "evidence",
        "findings",
        "gates",
        "permission_attestations",
        "persistent_resources",
    ):
        dependency_records.update(_records_by_id(state[collection]))
    approval_records = {
        item["approval_id"]: item for item in state["approvals"]
    }
    dependency_records.update(approval_records)
    for key in PROVENANCE_KEYS:
        dependency_records["PROVENANCE-{}".format(key)] = {
            "id": "PROVENANCE-{}".format(key),
            "depends_on": [],
        }
    dependency_records["AUTHORITY"] = {"id": "AUTHORITY", "depends_on": []}
    dependency_records["ACTION-LEDGER"] = {
        "id": "ACTION-LEDGER",
        "depends_on": [],
    }
    dependency_graph: Dict[str, List[str]] = {}
    for record_id, record in dependency_records.items():
        dependencies = list(
            record.get(
                "depends_on",
                record.get("dependencies", []),
            )
        )
        if "evidence_ids" in record:
            dependencies.extend(record["evidence_ids"])
        if record_id in findings:
            dependencies.extend(record.get("resolution_evidence_ids", []))
            if record.get("approval_id"):
                dependencies.append(record["approval_id"])
        if record_id in {
            item["id"] for item in state["permission_attestations"]
        }:
            dependencies.append(record["task_id"])
        extension_dependencies = record.get("extensions", {}).get("depends_on", [])
        if isinstance(extension_dependencies, list):
            dependencies.extend(extension_dependencies)
        behavior_inputs = record.get("extensions", {}).get(
            "behavior_input_ids", []
        )
        if isinstance(behavior_inputs, list):
            dependencies.extend(behavior_inputs)
        dependency_graph[record_id] = dependencies
    errors.extend(_check_cycles(dependency_graph, "record"))

    gates = _records_by_id(state["gates"])
    review = state["review"]
    review_mode = review.get("extensions", {}).get("mode")
    if review_mode not in {None, "advisory", "formal"}:
        errors.append("review mode is not a supported advisory/formal mode")
    if review_mode == "advisory" and review.get("extensions", {}).get(
        "gate_result_emitted"
    ) is not False:
        errors.append("advisory review may not emit a gate result")
    if review_mode == "formal" and review.get("extensions", {}).get(
        "gate_result_emitted"
    ) is not True:
        errors.append("formal review must explicitly emit a gate result")
    reviewer = review["reviewer"]
    if reviewer != "unknown":
        for artifact_id in review["target_artifact_ids"]:
            if artifact_id not in artifacts:
                errors.append("review targets unknown artifact {}".format(artifact_id))
            elif reviewer in artifacts[artifact_id]["authors"]:
                errors.append("reviewer authorship overlap on artifact {}".format(artifact_id))
        for evidence_id in review["target_evidence_ids"]:
            if evidence_id not in evidence:
                errors.append("review targets unknown evidence {}".format(evidence_id))
            elif reviewer in evidence[evidence_id]["authors"]:
                errors.append("reviewer authorship overlap on evidence {}".format(evidence_id))
        if review["independence_conflicts"]:
            errors.append("review has declared independence conflicts")

    approvals = {item["approval_id"]: item for item in state["approvals"]}
    if len(approvals) != len(state["approvals"]):
        errors.append("approvals contain duplicate approval_id values")
    for approval_id, approval in approvals.items():
        verification = approval["verification"]
        if (
            verification["status"] == "verified"
            and verification["source_kind"] not in {"runtime_owned", "trusted_external"}
        ):
            errors.append("approval {} has untrusted verified source".format(approval_id))
        issued = _parse_utc(approval["issued_at"])
        expires = _parse_utc(approval["expires_at"])
        if issued is not None and expires is not None and expires <= issued:
            errors.append("approval {} expiry must be after issuance".format(approval_id))

    for finding_id, finding in findings.items():
        severity = finding["severity"]
        priority = finding["priority"]
        disposition = finding["disposition"]
        if severity == "critical" and priority != "P0":
            errors.append("critical finding {} must be P0".format(finding_id))
        if severity == "high" and priority not in {"P0", "P1"}:
            errors.append("high finding {} must be P0 or P1".format(finding_id))
        if disposition == "resolved" and not finding["resolution_evidence_ids"]:
            errors.append("resolved finding {} needs resolution evidence".format(finding_id))
        strict_resolution = bool(finding["extensions"]) or any(
            item.get("extensions", {}).get("coverage", {}).get("finding_id")
            == finding_id
            for item in state["evidence"]
            if isinstance(item.get("extensions", {}).get("coverage", {}), Mapping)
        )
        if disposition == "resolved":
            for evidence_id in finding["resolution_evidence_ids"]:
                item = evidence.get(evidence_id)
                if item is None:
                    errors.append(
                        "resolved finding {} references unknown evidence {}".format(
                            finding_id, evidence_id
                        )
                    )
                    continue
                if not strict_resolution:
                    continue
                coverage = item.get("extensions", {}).get("coverage")
                if item["status"] != "current" or item["result"] != "pass":
                    errors.append(
                        "resolved finding {} evidence {} is not current and passing".format(
                            finding_id, evidence_id
                        )
                    )
                if item["invalidation_revision"] != state["state"]["current_invalidation_revision"]:
                    errors.append(
                        "resolved finding {} evidence {} has stale invalidation revision".format(
                            finding_id, evidence_id
                        )
                    )
                evidence_revision = item.get("extensions", {}).get(
                    "state_revision"
                )
                if (
                    not isinstance(evidence_revision, int)
                    or isinstance(evidence_revision, bool)
                    or evidence_revision > state["state"]["revision"]
                ):
                    errors.append(
                        "resolved finding {} evidence {} has invalid or future "
                        "state revision".format(
                            finding_id, evidence_id
                        )
                    )
                if (
                    not isinstance(coverage, Mapping)
                    or coverage.get("finding_id") != finding_id
                    or coverage.get("trigger") is not True
                    or coverage.get("required_action") is not True
                    or not coverage.get("artifact_ids")
                    or coverage.get("environment") != item["environment"]
                ):
                    errors.append(
                        "resolved finding {} evidence {} lacks exact RV2 coverage".format(
                            finding_id, evidence_id
                        )
                    )
                else:
                    for artifact_id in coverage["artifact_ids"]:
                        artifact = artifacts.get(artifact_id)
                        if artifact is None:
                            errors.append(
                                "resolved finding {} evidence {} covers unknown artifact {}".format(
                                    finding_id, evidence_id, artifact_id
                                )
                            )
                        elif artifact["status"] != "current":
                            errors.append(
                                "resolved finding {} evidence {} covers noncurrent artifact {}".format(
                                    finding_id, evidence_id, artifact_id
                                )
                            )
                authors = set(item["authors"])
                prohibited = {finding["owner"], "implementation_engineer"}
                if isinstance(coverage, Mapping):
                    for artifact_id in coverage.get("artifact_ids", []):
                        artifact = artifacts.get(artifact_id)
                        if artifact is not None:
                            prohibited.update(artifact["authors"])
                            prohibited.add(artifact["owner"])
                if authors & prohibited:
                    errors.append(
                        "resolved finding {} evidence {} is not independent of remediation".format(
                            finding_id, evidence_id
                        )
                    )
                provenance_digest = item.get("extensions", {}).get("provenance_digest")
                if _canonical_digest(provenance_digest) is None:
                    errors.append(
                        "resolved finding {} evidence {} lacks provenance digest".format(
                            finding_id, evidence_id
                        )
                    )
        if disposition == "risk_accepted":
            approval_id = finding["approval_id"]
            if not approval_id or approval_id not in approvals:
                errors.append("risk-accepted finding {} needs a known approval".format(finding_id))
            elif finding["extensions"]:
                extension = finding["extensions"]
                approval = approvals[approval_id]
                approval_extension = approval.get("extensions", {})
                nonwaivable = _nonwaivable_finding_reason(finding)
                if nonwaivable:
                    errors.append(
                        "finding {} cannot be risk accepted: {}".format(
                            finding_id, nonwaivable
                        )
                    )
                finding_revision = extension.get("finding_revision")
                if (
                    not isinstance(finding_revision, int)
                    or isinstance(finding_revision, bool)
                    or finding_revision < 1
                    or extension.get("waivability") != "waivable"
                ):
                    errors.append(
                        "finding {} lacks explicit waivability and positive finding revision".format(
                            finding_id
                        )
                    )
                if (
                    approval["action"] != "risk_accept_finding"
                    or approval_extension.get("finding_id") != finding_id
                    or approval_extension.get("finding_revision")
                    != extension.get("finding_revision")
                    or approval_extension.get("affected_operation")
                    != extension.get("affected_operation")
                ):
                    errors.append("finding {} approval does not exactly bind RV2 risk".format(finding_id))
                for limit_error in _approval_operation_limit_errors(
                    extension.get("affected_operation", {}), approval
                ):
                    errors.append(
                        "finding {}: {}".format(finding_id, limit_error)
                    )
            elif approvals[approval_id]["action"] != "accept_finding:{}".format(finding_id):
                errors.append("finding {} legacy approval action is not exact".format(finding_id))
        if disposition == "duplicate":
            if not finding["duplicate_of"] or finding["duplicate_of"] not in findings:
                errors.append("duplicate finding {} needs a known duplicate_of".format(finding_id))
            if not finding["original_evidence"] or not finding["rationale"]:
                errors.append("duplicate finding {} must retain evidence and rationale".format(finding_id))
        if disposition == "withdrawn" and (
            not finding["original_evidence"] or not finding["rationale"]
        ):
            errors.append("withdrawn finding {} must retain evidence and rationale".format(finding_id))

    if (
        state["project"]["risk_tier"] in {"R1", "R2"}
        and state["state"]["status"] in {"releasing", "complete"}
    ):
        completion_times = [_parse_utc(state["state"]["updated_at"])]
        completion_times.extend(
            _parse_utc(item["observed_at"])
            for item in state["permission_attestations"]
            if item["role"] == "reviewer"
            and item["source_kind"] == "runtime_owned"
            and item["status"] == "current"
        )
        completion_now = max(
            (item for item in completion_times if item is not None),
            default=None,
        )
        if completion_now is None:
            errors.append("release/completion time is invalid")
        else:
            errors.extend(
                _formal_review_contract_errors(
                    state, completion_now, {"complete"}
                )
            )
        required_gates = {"validation", "independent_review"}
        passing = {
            gate["gate"]: gate
            for gate in state["gates"]
            if gate["gate"] in required_gates and gate["result"] == "pass"
        }
        missing = required_gates - set(passing)
        if missing:
            errors.append(
                "R1/R2 release or completion lacks current passing gates {}".format(
                    sorted(missing)
                )
                )
        if review["recommendation"] != "pass":
            errors.append("independent review gate conflicts with a nonpassing review")
        gate_owners: Dict[str, str] = {}
        implementation_identities = {"implementation_engineer"}
        for artifact in artifacts.values():
            if artifact["owner"] == "implementation_engineer":
                implementation_identities.update(artifact["authors"])
        for gate_name, gate in passing.items():
            owner = gate.get("extensions", {}).get("owner_instance_id")
            if not owner:
                errors.append("{} gate lacks owner instance identity".format(gate_name))
            else:
                gate_owners[gate_name] = owner
            if gate["invalidation_revision"] != state["state"]["current_invalidation_revision"]:
                errors.append("{} gate has stale invalidation revision".format(gate_name))
            if not gate["evidence_ids"]:
                errors.append("{} gate lacks supporting evidence".format(gate_name))
            for evidence_id in gate["evidence_ids"]:
                item = evidence.get(evidence_id)
                if (
                    item is None
                    or item["status"] != "current"
                    or item["result"] != "pass"
                    or item["invalidation_revision"]
                    != state["state"]["current_invalidation_revision"]
                    or item.get("extensions", {}).get("state_revision")
                    != state["state"]["revision"]
                ):
                    errors.append(
                        "{} gate evidence {} is missing, stale, or not passing".format(
                            gate_name, evidence_id
                        )
                    )
                elif set(item["authors"]) & implementation_identities:
                    errors.append(
                        "{} gate evidence {} is implementation-authored".format(
                            gate_name, evidence_id
                        )
                    )
        review_gate_owner = gate_owners.get("independent_review")
        if (
            review_gate_owner is not None
            and review["reviewer"] != review_gate_owner
        ):
            errors.append("independent review gate owner does not match reviewer identity")
        if len(gate_owners) == 2 and len(set(gate_owners.values())) != 2:
            errors.append("validation and independent review gate owners are not independent")
        nonterminal = [task["id"] for task in state["tasks"] if task["status"] != "complete"]
        if nonterminal:
            errors.append("release/completion has nonterminal tasks {}".format(nonterminal))
        if any(
            finding["severity"] in {"critical", "high"}
            and finding["disposition"] == "open"
            for finding in state["findings"]
        ):
            errors.append("release/completion has open critical/high findings")
        legacy_high_dispositions = [
            finding["id"]
            for finding in state["findings"]
            if finding["severity"] in {"critical", "high"}
            and finding["disposition"] in {"resolved", "risk_accepted"}
            and not finding["extensions"]
        ]
        if legacy_high_dispositions:
            errors.append(
                "release/completion has legacy critical/high dispositions without "
                "current structured evidence {}".format(legacy_high_dispositions)
            )
        if completion_now is not None:
            for finding in state["findings"]:
                if (
                    finding["severity"] in {"critical", "high"}
                    and finding["disposition"] == "risk_accepted"
                    and finding["extensions"]
                ):
                    approval = approvals.get(finding["approval_id"])
                    if approval is None:
                        continue
                    for item in _approval_validity_errors(
                        approval, completion_now
                    ):
                        errors.append(
                            "release/completion finding {}: {}".format(
                                finding["id"], item
                            )
                        )
        ledger = state.get("action_ledger", {"reservations": []})
        if any(
            item["status"] in {"reserved", "claimed", "recovery_required"}
            for item in ledger.get("reservations", [])
        ):
            errors.append(
                "release/completion has outstanding or recovery-required action reservations"
            )

    if (
        state["project"]["physical_safety_tier"] in {"E1", "E2"}
        and set(state["project"]["target_environments"])
        & {"hardware_in_loop", "controlled_hardware"}
        and state["state"]["status"] in {"releasing", "complete"}
    ):
        safety_tier = state["project"]["physical_safety_tier"]
        embodied_tasks = [
            task
            for task in state["tasks"]
            if task["physical_safety_tier"] == safety_tier
            and task["target_environment"]
            in {"hardware_in_loop", "controlled_hardware"}
        ]
        embodied_task = embodied_tasks[0] if len(embodied_tasks) == 1 else None
        safety = (
            embodied_task.get("extensions", {}).get("embodied_safety")
            if embodied_task is not None
            else None
        )
        safety_now = _parse_utc(state["state"]["updated_at"])
        if not isinstance(safety, Mapping):
            errors.append(
                "{} hardware release lacks one embodied safety record".format(
                    safety_tier
                )
            )
        else:
            evidence_fields = (
                "hardware_emergency_stop_evidence_id",
                "software_emergency_stop_evidence_id",
                "watchdog_evidence_id",
                "heartbeat_timeout_evidence_id",
                "telemetry_evidence_id",
                "dry_run_evidence_id",
            )
            for field in evidence_fields:
                evidence_id = safety.get(field)
                item = evidence.get(evidence_id)
                if (
                    item is None
                    or item["status"] != "current"
                    or item["result"] != "pass"
                    or item["environment"]
                    not in {"hardware_in_loop", "controlled_hardware"}
                    or item["invalidation_revision"]
                    != state["state"]["current_invalidation_revision"]
                    or item.get("extensions", {}).get("state_revision")
                    != state["state"]["revision"]
                ):
                    errors.append(
                        "{} hardware {} is missing, stale, or nonpassing".format(
                            safety_tier, field
                        )
                    )
            envelope = safety.get("physical_envelope")
            numeric_envelope_fields = (
                "max_speed_mps",
                "max_force_newtons",
                "max_duration_seconds",
                "min_proximity_meters",
            )
            workspace = (
                envelope.get("workspace")
                if isinstance(envelope, Mapping)
                else None
            )
            if (
                not isinstance(envelope, Mapping)
                or not isinstance(workspace, Mapping)
                or not workspace
                or any(
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                    for value in workspace.values()
                )
                or any(
                    not isinstance(envelope.get(field), (int, float))
                    or isinstance(envelope.get(field), bool)
                    or not math.isfinite(envelope[field])
                    or envelope[field] < 0
                    or (
                        field == "max_duration_seconds"
                        and envelope[field] <= 0
                    )
                    for field in numeric_envelope_fields
                )
            ):
                errors.append(
                    "{} hardware physical envelope is incomplete or nonnumeric".format(
                        safety_tier
                    )
                )
            command_rate = safety.get("bounded_command_rate_hz")
            if (
                not isinstance(command_rate, (int, float))
                or isinstance(command_rate, bool)
                or not math.isfinite(command_rate)
                or command_rate <= 0
            ):
                errors.append(
                    "{} hardware command rate is not bounded".format(safety_tier)
                )
            required_hazards = {
                "collision_avoidance",
                "geofence",
                "joint_limits",
                "thermal_limits",
                "battery_limits",
                "communication_loss_stop",
            }
            if not required_hazards.issubset(
                set(safety.get("hazard_controls", []))
            ):
                errors.append(
                    "{} hardware hazard controls are incomplete".format(
                        safety_tier
                    )
                )
            required_stops = {
                "unexpected_motion",
                "safety_anomaly",
                "sensor_integrity_failure",
                "lost_telemetry",
                "emergency_stop",
            }
            if not required_stops.issubset(
                set(safety.get("stop_conditions", []))
            ):
                errors.append(
                    "{} hardware stop conditions are incomplete".format(
                        safety_tier
                    )
                )
            if (
                not isinstance(safety.get("incident_recovery"), str)
                or not safety["incident_recovery"]
                or safety.get("deterministic_command_validation") is not True
            ):
                errors.append(
                    "{} hardware recovery or deterministic validation is "
                    "incomplete".format(safety_tier)
                )
            approval_id = safety.get("start_approval_id")
            approval = approvals.get(approval_id)
            if (
                approval is None
                or safety_now is None
                or embodied_task is None
                or approval_id not in embodied_task["approvals_required"]
            ):
                errors.append(
                    "{} hardware start approval is missing or unbound".format(
                        safety_tier
                    )
                )
            else:
                start_errors = _approval_validity_errors(approval, safety_now)
                expected_start_action = "start_{}".format(
                    embodied_task["target_environment"]
                )
                if approval["action"] != expected_start_action:
                    start_errors.append("approval action mismatch")
                if approval["environment"] != embodied_task["target_environment"]:
                    start_errors.append("approval environment mismatch")
                if not approval["scope"]:
                    start_errors.append("approval scope is empty")
                if (
                    approval["limits"].get("physical_envelope")
                    != safety.get("physical_envelope")
                ):
                    start_errors.append("approval physical envelope mismatch")
                errors.extend(
                    "{} hardware start approval: {}".format(safety_tier, item)
                    for item in start_errors
                )

    reverse: Dict[str, Set[str]] = {record_id: set() for record_id in dependency_graph}
    for record_id, dependencies in dependency_graph.items():
        for dependency in dependencies:
            if dependency in reverse:
                reverse[dependency].add(record_id)

    invalidation_revisions = [record["revision"] for record in state["invalidations"]]
    expected_current_revision = max(invalidation_revisions) if invalidation_revisions else 0
    if state["state"]["current_invalidation_revision"] != expected_current_revision:
        errors.append("state.current_invalidation_revision does not match invalidation ledger")

    if state["invalidations"]:
        manual_path = _manual_path_for_digest(
            state["provenance"].get("manual_digest", "unknown")
        )
        behavior_paths = {
            "manual_digest": manual_path,
            "schema_digest": Path("contracts/meva.schema.json"),
        }
        for key, path in behavior_paths.items():
            declared = state["provenance"].get(key, "unknown")
            if (
                declared != "unknown"
                and path.is_file()
                and not _digests_equal(declared, _sha256(path))
            ):
                errors.append(
                    "behavior-affecting provenance {} changed without a current "
                    "invalidation closure".format(key)
                )

    for invalidation in state["invalidations"]:
        revision = invalidation["revision"]
        changed = set(invalidation["changed_ids"])
        unknown_changed = changed - set(dependency_graph)
        if unknown_changed:
            errors.append(
                "invalidation {} has unknown changed_ids {}".format(
                    invalidation["id"], sorted(unknown_changed)
                )
            )
            continue
        affected = set(changed)
        queue = list(changed)
        while queue:
            current = queue.pop()
            for dependent in reverse.get(current, set()):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)
        expected_artifacts = affected & set(artifacts)
        expected_evidence = affected & set(evidence)
        expected_gates = affected & set(gates)
        expected_tasks = affected & set(tasks)
        expected_findings = affected & set(findings)
        expected_approvals = affected & set(approval_records)
        permission_ids = {
            item["id"] for item in state["permission_attestations"]
        }
        resource_ids = {item["id"] for item in state["persistent_resources"]}
        expected_permissions = affected & permission_ids
        expected_resources = affected & resource_ids
        actual_groups = [
            ("artifact", set(invalidation["affected_artifact_ids"]), expected_artifacts),
            ("evidence", set(invalidation["affected_evidence_ids"]), expected_evidence),
            ("gate", set(invalidation["affected_gate_ids"]), expected_gates),
        ]
        for label, actual, expected in actual_groups:
            if actual != expected:
                errors.append(
                    "invalidation {} {} set mismatch: expected {}, got {}".format(
                        invalidation["id"], label, sorted(expected), sorted(actual)
                    )
                )
        actual_tasks = invalidation.get("extensions", {}).get(
            "affected_task_ids", []
        )
        if not isinstance(actual_tasks, list) or set(actual_tasks) != expected_tasks:
            errors.append(
                "invalidation {} task set mismatch: expected {}, got {}".format(
                    invalidation["id"],
                    sorted(expected_tasks),
                    sorted(actual_tasks) if isinstance(actual_tasks, list) else actual_tasks,
                )
            )
        extension_sets = (
            ("finding", "affected_finding_ids", expected_findings),
            ("approval", "affected_approval_ids", expected_approvals),
            (
                "permission attestation",
                "affected_permission_attestation_ids",
                expected_permissions,
            ),
            (
                "persistent resource",
                "affected_persistent_resource_ids",
                expected_resources,
            ),
        )
        for label, key, expected in extension_sets:
            actual = invalidation.get("extensions", {}).get(key, [])
            if not isinstance(actual, list) or set(actual) != expected:
                errors.append(
                    "invalidation {} {} set mismatch: expected {}, got {}".format(
                        invalidation["id"],
                        label,
                        sorted(expected),
                        sorted(actual) if isinstance(actual, list) else actual,
                    )
                )
        acknowledgements = invalidation["acknowledgements"]
        ack_owners = [ack["owner"] for ack in acknowledgements]
        if any(ack["revision"] != revision for ack in acknowledgements):
            errors.append("invalidation {} has stale acknowledgement".format(invalidation["id"]))
        if invalidation["status"] in {"acknowledged", "resolved"} and set(ack_owners) != set(
            invalidation["required_owners"]
        ):
            errors.append("invalidation {} acknowledgement set is incomplete".format(invalidation["id"]))
        required_instances = invalidation.get("extensions", {}).get(
            "required_owner_instance_ids"
        )
        if required_instances is not None:
            if (
                not isinstance(required_instances, list)
                or not required_instances
                or any(not isinstance(item, str) or not item for item in required_instances)
            ):
                errors.append(
                    "invalidation {} has invalid required owner-instance identities".format(
                        invalidation["id"]
                    )
                )
            else:
                acknowledged_instances = [
                    ack.get("owner_instance_id") for ack in acknowledgements
                ]
                if set(acknowledged_instances) != set(required_instances):
                    errors.append(
                        "invalidation {} owner-instance acknowledgement set is incomplete".format(
                            invalidation["id"]
                        )
                    )
                if any(
                    ack.get("state_revision") != state["state"]["revision"]
                    for ack in acknowledgements
                ):
                    errors.append(
                        "invalidation {} has stale state-revision acknowledgement".format(
                            invalidation["id"]
                        )
                    )
        if invalidation["status"] == "resolved":
            provenance_changes = {
                item
                for item in changed
                if item.startswith("PROVENANCE-")
            }
            if provenance_changes and (
                not expected_evidence or not expected_gates
            ):
                errors.append(
                    "resolved behavior-affecting provenance invalidation {} "
                    "requires affected evidence and gates".format(
                        invalidation["id"]
                    )
                )
            if not expected_evidence.issubset(set(invalidation["rerun_evidence_ids"])):
                errors.append("invalidation {} lacks required evidence reruns".format(invalidation["id"]))
            for artifact_id in expected_artifacts:
                if artifacts[artifact_id]["status"] != "current":
                    errors.append(
                        "resolved invalidation leaves artifact {} invalidated".format(
                            artifact_id
                        )
                    )
            for evidence_id in expected_evidence:
                if (
                    evidence[evidence_id]["status"] != "current"
                    or evidence[evidence_id]["result"] != "pass"
                ):
                    errors.append(
                        "resolved invalidation evidence {} is not current and passing".format(
                            evidence_id
                        )
                    )
                if evidence[evidence_id]["invalidation_revision"] != revision:
                    errors.append(
                        "rerun evidence {} is not at exact invalidation revision".format(
                            evidence_id
                        )
                    )
            for gate_id in expected_gates:
                gate = gates[gate_id]
                if gate["result"] != "pass":
                    errors.append(
                        "resolved invalidation gate {} is not passing".format(gate_id)
                    )
                if gate["invalidation_revision"] != revision:
                    errors.append(
                        "resolved invalidation gate {} is not at exact revision".format(
                            gate_id
                        )
                    )
                if not gate["evidence_ids"]:
                    errors.append(
                        "resolved invalidation gate {} lacks supporting evidence".format(
                            gate_id
                        )
                    )
                for evidence_id in gate["evidence_ids"]:
                    supporting = evidence.get(evidence_id)
                    if (
                        supporting is None
                        or supporting["status"] != "current"
                        or supporting["result"] != "pass"
                        or supporting["invalidation_revision"] != revision
                    ):
                        errors.append(
                            "resolved invalidation gate {} has missing, stale, or "
                            "nonpassing evidence {}".format(gate_id, evidence_id)
                        )
            affected_task_ids = invalidation.get("extensions", {}).get(
                "affected_task_ids", []
            )
            if not isinstance(affected_task_ids, list):
                errors.append(
                    "invalidation {} affected_task_ids must be an array".format(
                        invalidation["id"]
                    )
                )
            else:
                for task_id in affected_task_ids:
                    task = tasks.get(task_id)
                    if task is None:
                        errors.append(
                            "invalidation {} references unknown affected task {}".format(
                                invalidation["id"], task_id
                            )
                        )
                    elif task["status"] == "blocked":
                        errors.append(
                            "resolved invalidation leaves affected task {} blocked".format(
                                task_id
                            )
                        )
        else:
            for artifact_id in expected_artifacts:
                if artifacts[artifact_id]["status"] != "invalidated":
                    errors.append("open invalidation does not mark {} invalidated".format(artifact_id))
            for evidence_id in expected_evidence:
                if evidence[evidence_id]["status"] != "invalidated":
                    errors.append("open invalidation does not mark {} invalidated".format(evidence_id))
            for gate_id in expected_gates:
                if gates[gate_id]["result"] != "unverified":
                    errors.append("open invalidation does not make gate {} unverified".format(gate_id))

    return errors


def validate_state(
    state_path: Path, schema_path: Path
) -> Tuple[Mapping[str, Any], Mapping[str, Any], List[str]]:
    schema = _load_json(schema_path)
    state = _load_json(state_path)
    if not isinstance(schema, Mapping):
        raise ContractError("schema root must be an object")
    if not isinstance(state, Mapping):
        raise ContractError("state root must be an object")
    errors = validate_json_schema(state, schema)
    if not errors:
        errors.extend(_semantic_state_errors(state))
    return state, schema, errors


def _canonical_handoff_bytes(handoff: Any) -> int:
    """Return the UTF-8 size of the compact, key-sorted handoff payload."""

    return len(
        json.dumps(
            handoff,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def validate_handoff(
    handoff: Any, schema: Mapping[str, Any]
) -> Tuple[List[str], List[str], int]:
    """Validate a compact handoff and enforce its transport-size budget."""

    errors = validate_json_schema(handoff, schema["$defs"]["compactHandoff"], schema)
    size = _canonical_handoff_bytes(handoff)
    warnings: List[str] = []
    if size > HANDOFF_HARD_LIMIT_BYTES:
        errors.append(
            "handoff exceeds hard compact limit: {} bytes > {}".format(
                size, HANDOFF_HARD_LIMIT_BYTES
            )
        )
    elif size > HANDOFF_TARGET_BYTES:
        warnings.append(
            "handoff exceeds compact target: {} bytes > {}".format(
                size, HANDOFF_TARGET_BYTES
            )
        )
    return errors, warnings, size


def _approval_check(
    approval: Mapping[str, Any],
    action: str,
    scope: Sequence[str],
    environment: str,
    limits: Mapping[str, Any],
    now: datetime,
) -> List[str]:
    errors: List[str] = []
    verification = approval["verification"]
    if approval["status"] != "active":
        errors.append("approval is revoked")
    if verification["status"] != "verified":
        errors.append("approval verification is not verified")
    if verification["source_kind"] not in {"runtime_owned", "trusted_external"}:
        errors.append("approval verification source is not trusted")
    if approval["action"] != action:
        errors.append("approval action mismatch")
    if approval["scope"] != list(scope):
        errors.append("approval scope mismatch")
    if approval["environment"] != environment:
        errors.append("approval environment mismatch")
    if approval["limits"] != dict(limits):
        errors.append("approval limits mismatch")
    issued = _parse_utc(approval["issued_at"])
    if issued is None:
        errors.append("approval issuance is unknown or invalid")
    elif now < issued:
        errors.append("approval is not yet valid")
    verified = _parse_utc(verification["verified_at"])
    if verified is None:
        errors.append("approval verification time is unknown or invalid")
    elif now < verified:
        errors.append("approval verification is in the future")
    expires = _parse_utc(approval["expires_at"])
    if expires is None:
        errors.append("approval expiry is unknown or invalid")
    elif now >= expires:
        errors.append("approval is expired")
    return errors


def _approval_validity_errors(
    approval: Mapping[str, Any], now: datetime
) -> List[str]:
    errors: List[str] = []
    verification = approval["verification"]
    if approval["status"] != "active":
        errors.append("approval is revoked")
    if verification["status"] != "verified":
        errors.append("approval verification is not verified")
    if verification["source_kind"] not in {"runtime_owned", "trusted_external"}:
        errors.append("approval verification source is not trusted")
    issued = _parse_utc(approval["issued_at"])
    verified = _parse_utc(verification["verified_at"])
    expires = _parse_utc(approval["expires_at"])
    if issued is None or now < issued:
        errors.append("approval is not yet valid")
    if verified is None or now < verified:
        errors.append("approval verification is not current")
    if expires is None or now >= expires:
        errors.append("approval is expired")
    return errors


def _required_action_approval_errors(
    state: Mapping[str, Any],
    task: Mapping[str, Any],
    action: str,
    effect: str,
    target: Mapping[str, Any],
    environment: str,
    amounts: Mapping[str, Any],
    now: datetime,
) -> Tuple[List[str], List[str]]:
    if not (
        environment == "production"
        or effect in {"external_mutation", "physical"}
    ):
        return [], []
    required = task["approvals_required"]
    if not required:
        return ["consequential action lacks task approvals_required"], []
    approvals = {item["approval_id"]: item for item in state["approvals"]}
    errors: List[str] = []
    valid_ids: List[str] = []
    expected_scope = (
        [target["path"]]
        if target.get("path") is not None
        else ["{}:{}".format(target["kind"], target["id"])]
    )
    amount_limits = {
        "cost": "max_cost",
        "compute_units": "max_compute_units",
        "wall_time_seconds": "max_wall_time_seconds",
        "external_calls": "max_external_calls",
        "action_chain_steps": "max_action_chain_steps",
    }
    for approval_id in required:
        approval = approvals.get(approval_id)
        if approval is None:
            errors.append("required approval {} is missing".format(approval_id))
            continue
        item_errors = _approval_validity_errors(approval, now)
        if approval["action"] != action:
            item_errors.append("approval action mismatch")
        if approval["environment"] != environment:
            item_errors.append("approval environment mismatch")
        if approval["scope"] != expected_scope:
            item_errors.append("approval scope does not exactly bind target")
        structured_target = approval.get("extensions", {}).get(
            "structured_target"
        )
        if structured_target is not None and structured_target != dict(target):
            item_errors.append("approval structured target mismatch")
        for amount_key, limit_key in amount_limits.items():
            limit = approval["limits"][limit_key]
            used = amounts[amount_key]
            if limit is not None and used > limit:
                item_errors.append(
                    "approval {} is narrower than requested {}".format(
                        limit_key, amount_key
                    )
                )
        if item_errors:
            errors.extend(
                "{}: {}".format(approval_id, item) for item in item_errors
            )
        else:
            valid_ids.append(approval_id)
    if not valid_ids:
        errors.append("no required approval authorizes the exact action")
    return errors, valid_ids


def _runtime_activation(
    state: Mapping[str, Any],
    role: str,
    task_id: Optional[str],
    now: datetime,
    root: Path,
    configured_concurrency: int = MAX_CONFIGURED_CONCURRENCY,
) -> Tuple[str, List[str]]:
    if task_id is None:
        return "unverified", ["runtime activation is not bound to a task"]
    task = next((item for item in state["tasks"] if item["id"] == task_id), None)
    if task is None:
        return "unverified", ["runtime activation references an unknown task"]
    relevant = [
        item
        for item in state["permission_attestations"]
        if item["role"] == role and item["task_id"] == task_id
    ]
    if not relevant:
        return "unverified", ["no matching runtime-owned attestation"]

    dated: List[Tuple[datetime, Mapping[str, Any]]] = []
    unknown_observation = False
    for item in relevant:
        observed = _parse_utc(item["observed_at"])
        if observed is None:
            unknown_observation = True
        else:
            dated.append((observed, item))
    if not dated:
        return "unverified", ["matching attestation observation time is unknown"]
    latest_time = max(item[0] for item in dated)
    latest = [item for observed, item in dated if observed == latest_time]
    if len(latest) != 1:
        return "fail", ["latest matching attestation is ambiguous"]
    attestation = latest[0]

    errors: List[str] = []
    unknowns: List[str] = []
    state_provenance = state["provenance"]
    unknowns.extend(
        key for key in PROVENANCE_KEYS if state_provenance.get(key) == "unknown"
    )
    if attestation["source_kind"] != "runtime_owned":
        errors.append("activation source is not runtime-owned")
    if attestation["status"] != "current":
        errors.append("activation attestation is not current")
    if not attestation["fresh_session"]:
        errors.append("session is not attested fresh")
    if attestation["project_id"] != state["project"]["id"]:
        errors.append("attested project does not match")
    if task["accountable_owner"] != role:
        errors.append("attested role does not own the exact task")
    if task["status"] != "in_progress":
        errors.append("attested task is not active")
    if latest_time > now:
        errors.append("latest matching attestation is future-dated")
    owner_instance, owner_error = _effective_owner_instance(state, task, role, now)
    if owner_error:
        errors.append(owner_error)
    else:
        attested_owner = attestation.get("extensions", {}).get(
            "owner_instance_id"
        )
        if attested_owner is not None and owner_instance != attested_owner:
            errors.append("owner instance identity does not bind the selected attestation")

    authority = state["authority"]
    if authority["source_kind"] not in {"runtime_owned", "trusted_external"}:
        errors.append("human authority source is not trusted")
    authority_expiry = _parse_utc(authority["expires_at"])
    if authority_expiry is None:
        unknowns.append("human authority expiry")
    elif now >= authority_expiry:
        errors.append("human authority is expired")

    permissions = attestation["effective_permissions"]
    task_environments = set(
        task["extensions"].get("allowed_environments", [task["target_environment"]])
    )
    role_environments = ROLE_MAX_ENVIRONMENTS.get(role, set())
    if not task_environments.issubset(role_environments):
        errors.append("exact task environments are broader than role maximum")
    if not set(task["allowed_actions"]).issubset(set(authority["allowed_actions"])):
        errors.append("exact task actions are broader than human authority")
    if not task_environments.issubset(set(authority["environments"])):
        errors.append("exact task environments are broader than human authority")
    for task_scope in task["writable_scope"]:
        if not _path_within(task_scope, authority["scopes"]):
            errors.append("exact task writable scope is broader than human authority")
    if not set(permissions["actions"]).issubset(set(task["allowed_actions"])):
        errors.append("attested actions are broader than the exact task")
    if not set(permissions["actions"]).issubset(set(authority["allowed_actions"])):
        errors.append("attested actions are broader than human authority")
    if not set(permissions["environments"]).issubset(task_environments):
        errors.append("attested environments are broader than the exact task")
    if not set(permissions["environments"]).issubset(role_environments):
        errors.append("attested environments are broader than role maximum")
    if not set(permissions["environments"]).issubset(set(authority["environments"])):
        errors.append("attested environments are broader than human authority")
    for writable_scope in permissions["writable_scopes"]:
        if not _path_within(writable_scope, task["writable_scope"]):
            errors.append("attested writable scope is broader than the exact task")
        if not _path_within(writable_scope, authority["scopes"]):
            errors.append("attested writable scope is broader than human authority")
    if role in READ_ONLY_ROLES:
        role_actions = READ_ONLY_ROLE_ACTIONS[role]
        if not set(task["allowed_actions"]).issubset(role_actions):
            errors.append("exact task actions are broader than read-only role maximum")
        if not set(permissions["actions"]).issubset(role_actions):
            errors.append("attested actions are broader than read-only role maximum")
        if permissions["writable_scopes"]:
            errors.append("read-only role does not prove empty writable scopes")
        if permissions["external_calls"]:
            task_extensions = task["extensions"]
            authority_extensions = authority["extensions"]
            trusted = task_extensions.get("trusted_capability_metadata", {})
            if task_extensions.get("allow_external_calls") is not True:
                errors.append("read-only external access lacks exact task authorization")
            if authority_extensions.get("allow_external_calls") is not True:
                errors.append("read-only external access lacks exact human authorization")
            if task_extensions.get("external_effect") != "read_only":
                errors.append("read-only external access has non-read-only task effect")
            if authority_extensions.get("external_effect") != "read_only":
                errors.append("read-only external access has non-read-only authority effect")
            targets = task_extensions.get("structured_external_targets")
            if not isinstance(targets, list) or not targets or any(
                not isinstance(target, Mapping)
                or not isinstance(target.get("kind"), str)
                or not target.get("kind")
                or not isinstance(target.get("id"), str)
                or not target.get("id")
                for target in targets
            ):
                errors.append("read-only external access lacks structured exact targets")
            if trusted and trusted.get("effect", "external_read") not in {
                "read_only",
                "external_read",
            }:
                errors.append("trusted capability effect is not read-only")
    if permissions["external_calls"]:
        if not task["extensions"].get("allow_external_calls", False):
            errors.append("external-call capability is broader than the exact task")
        if not authority["extensions"].get("allow_external_calls", False):
            errors.append("external-call capability is broader than human authority")
        if task["accounting"]["budget"]["max_external_calls"] in {None, 0}:
            errors.append("external-call capability lacks a positive task limit")
    if permissions["max_concurrency"] > configured_concurrency:
        errors.append(
            "attested max_concurrency {} exceeds configured cap {}".format(
                permissions["max_concurrency"], configured_concurrency
            )
        )
    task_concurrency = task["accounting"]["budget"]["max_worker_fanout"]
    if task_concurrency is not None and permissions["max_concurrency"] > task_concurrency:
        errors.append("attested max_concurrency is broader than the exact task")

    expected_sandbox = "read_only" if role in READ_ONLY_ROLES else "workspace_write"
    if (
        state_provenance["sandbox_mode"] != "unknown"
        and state_provenance["sandbox_mode"] != expected_sandbox
    ):
        errors.append("canonical sandbox_mode exceeds or conflicts with role maximum")
    if state_provenance["permission_mode"] == "elevated" and not (
        task["extensions"].get("allow_elevated_permissions", False)
        and authority["extensions"].get("allow_elevated_permissions", False)
    ):
        errors.append("elevated permission mode lacks exact task and human authority")

    attested_provenance_keys = (
        "runtime",
        "model",
        "provider",
        "policy_digest",
        "config_digest",
        "manual_digest",
        "schema_digest",
        "role_digest",
        "ticket_digest",
    )
    for key in attested_provenance_keys:
        canonical = state_provenance[key]
        attested = attestation[key]
        if canonical == "unknown" or attested == "unknown":
            unknowns.append(key)
        else:
            differs = (
                not _digests_equal(attested, canonical)
                if key.endswith("_digest")
                else attested != canonical
            )
            if differs:
                errors.append(
                    "attested {} does not match canonical state provenance".format(key)
                )
    if (
        state_provenance["attestation_source"] != "unknown"
        and attestation["source"] != state_provenance["attestation_source"]
    ):
        errors.append("attestation source does not match canonical state provenance")
    elif state_provenance["attestation_source"] == "unknown":
        unknowns.append("attestation_source")

    canonical_ticket_digest = hashlib.sha256(
        json.dumps(task, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if attestation["ticket_digest"] != "unknown" and (
        not _digests_equal(attestation["ticket_digest"], canonical_ticket_digest)
    ):
        errors.append("attested ticket_digest does not bind the exact task")
    if state_provenance["ticket_digest"] != "unknown" and (
        not _digests_equal(state_provenance["ticket_digest"], canonical_ticket_digest)
    ):
        errors.append("canonical ticket_digest does not bind the exact task")

    manual_path = _manual_path_for_digest(state_provenance["manual_digest"], root)
    package_paths = {
        "config_digest": root / ".codex/config.toml",
        "manual_digest": manual_path,
        "schema_digest": root / "contracts/meva.schema.json",
    }
    role_path = root / ".codex/agents" / "{}.toml".format(role)
    if role_path.is_file():
        package_paths["role_digest"] = role_path
    for key, path in package_paths.items():
        if not path.is_file():
            errors.append("package artifact for {} is missing".format(key))
            continue
        actual = _sha256(path)
        canonical = state_provenance[key]
        attested = attestation[key]
        if canonical == "unknown" or attested == "unknown":
            if key not in unknowns:
                unknowns.append(key)
            continue
        if not _digests_equal(canonical, actual):
            errors.append("canonical {} does not match package artifact".format(key))
        if not _digests_equal(attested, actual):
            errors.append("attested {} does not match package artifact".format(key))

    for relative, declared in state_provenance.get("artifact_digests", {}).items():
        problem = _relative_path_error(relative)
        if problem:
            errors.append("declared artifact digest path {!r}: {}".format(relative, problem))
            continue
        path = root / relative
        if not path.is_file():
            errors.append("declared activation artifact {} is missing".format(relative))
        elif not _digests_equal(declared, _sha256(path)):
            errors.append("declared activation artifact {} digest mismatch".format(relative))

    expires = _parse_utc(attestation["expires_at"])
    if expires is None:
        unknowns.append("attestation expiry")
    elif now >= expires:
        errors.append("attestation is expired")
    if errors:
        return "fail", errors
    if unknown_observation:
        unknowns.append("older matching attestation observation time")
    if unknowns:
        return "unverified", [
            "activation-relevant value is unknown: {}".format(", ".join(sorted(set(unknowns))))
        ]
    return "pass", []


def _tiny_toml(path: Path) -> Dict[str, Dict[str, Any]]:
    """Extract the MEVA-owned [agents] overlay without rewriting the file."""

    result: Dict[str, Dict[str, Any]] = {"agents": {}}
    section = ""
    agents_tables = 0
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if not section:
                raise ContractError("{}:{} invalid table".format(path, line_number))
            if section == "agents":
                agents_tables += 1
                if agents_tables > 1:
                    raise ContractError("{}:{} duplicate [agents] table".format(path, line_number))
            continue
        if section != "agents":
            if section == "features" and re.match(r"multi_agent\s*=", line):
                raise ContractError(
                    "{}:{} deprecated features.multi_agent conflicts with "
                    "the required agents.enabled control".format(path, line_number)
                )
            continue
        if "=" not in line:
            raise ContractError("{}:{} unsupported [agents] syntax".format(path, line_number))
        key, raw_value = [item.strip() for item in line.split("=", 1)]
        if key in result["agents"]:
            raise ContractError("{}:{} duplicate key {}".format(path, line_number, key))
        if raw_value in {"true", "false"}:
            value: Any = raw_value == "true"
        elif re.fullmatch(r"[0-9]+", raw_value):
            value = int(raw_value)
        elif len(raw_value) >= 2 and raw_value[0] == raw_value[-1] == '"':
            value = raw_value[1:-1]
        else:
            raise ContractError("{}:{} unsupported TOML value".format(path, line_number))
        result["agents"][key] = value
    if agents_tables != 1:
        raise ContractError("{}: expected exactly one [agents] table".format(path))
    return result


def _role_toml(path: Path) -> Mapping[str, Any]:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r'^developer_instructions\s*=\s*"""(.*)"""\s*$',
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise ContractError("{}: missing developer_instructions multiline string".format(path))
    prefix = text[: match.start()]
    if "[" in prefix or "]" in prefix:
        raise ContractError("{}: TOML tables are not allowed in role files".format(path))
    values: Dict[str, Any] = {"developer_instructions": match.group(1)}
    for line_number, raw in enumerate(prefix.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = re.fullmatch(r'([A-Za-z0-9_]+)\s*=\s*"([^"]*)"', line)
        if parsed is None:
            raise ContractError("{}:{} unsupported role TOML syntax".format(path, line_number))
        values[parsed.group(1)] = parsed.group(2)
    if set(values) != ROLE_KEYS:
        raise ContractError(
            "{}: expected keys {}, got {}".format(path, sorted(ROLE_KEYS), sorted(values))
        )
    return values


def _package_checks(root: Path) -> Tuple[List[str], Dict[str, Any]]:
    errors: List[str] = []
    details: Dict[str, Any] = {}
    required = [
        "AGENTS.md",
        ".codex/config.toml",
        "contracts/meva.schema.json",
        "templates/project-state.json",
        "tools/meva_check.py",
        "README.md",
        "docs/reviewer-handbook.md",
        "tests/conformance/protocol.v1.json",
        "tests/conformance/protocol.v1.sha256",
        "tests/conformance/test_contracts.py",
        "tests/conformance/review_protocol.v1.json",
        "tests/conformance/review_protocol.v1.sha256",
        "tests/conformance/test_review_contracts.py",
        "tests/conformance/assurance_protocol.v1.json",
        "tests/conformance/assurance_protocol.v1.sha256",
        "tests/conformance/test_assurance_contracts.py",
        "tests/conformance/final_review_protocol.v1.json",
        "tests/conformance/final_review_protocol.v1.sha256",
        "tests/conformance/test_final_review_contracts.py",
    ]
    for relative in required:
        if not (root / relative).is_file():
            errors.append("missing required package artifact {}".format(relative))

    agents_path = root / "AGENTS.md"
    if agents_path.is_file():
        agents_digest = _sha256(agents_path)
        details["agents_digest"] = agents_digest
        if agents_digest != EXPECTED_AGENTS_DIGEST:
            errors.append(
                "AGENTS.md bootstrap digest does not match embedded release anchor"
            )

    frozen = [
        (
            "original protocol",
            "tests/conformance/protocol.v1.json",
            "tests/conformance/protocol.v1.sha256",
            EXPECTED_PROTOCOL_DIGEST,
        ),
        (
            "review protocol",
            "tests/conformance/review_protocol.v1.json",
            "tests/conformance/review_protocol.v1.sha256",
            EXPECTED_REVIEW_PROTOCOL_DIGEST,
        ),
        (
            "assurance protocol",
            "tests/conformance/assurance_protocol.v1.json",
            "tests/conformance/assurance_protocol.v1.sha256",
            EXPECTED_ASSURANCE_PROTOCOL_DIGEST,
        ),
        (
            "final review protocol",
            "tests/conformance/final_review_protocol.v1.json",
            "tests/conformance/final_review_protocol.v1.sha256",
            EXPECTED_FINAL_REVIEW_PROTOCOL_DIGEST,
        ),
    ]
    for label, relative, lock_relative, literal in frozen:
        artifact = root / relative
        digest_file = root / lock_relative
        if artifact.is_file() and digest_file.is_file():
            lock_value = digest_file.read_text(encoding="utf-8").split()[0]
            actual = _sha256(artifact)
            details[label.replace(" ", "_") + "_digest"] = actual
            if actual != lock_value:
                if label == "original protocol":
                    errors.append("frozen protocol digest mismatch")
                else:
                    errors.append("{} digest does not match lock".format(label))
            if actual != literal:
                if label == "original protocol":
                    errors.append(
                        "frozen protocol digest mismatch against embedded release anchor"
                    )
                else:
                    errors.append(
                        "{} digest does not match embedded release anchor".format(label)
                    )
            if lock_value != literal:
                errors.append("{} lock does not match embedded release anchor".format(label))
    harnesses = [
        (
            "original harness",
            "tests/conformance/test_contracts.py",
            EXPECTED_PROTOCOL_HARNESS_DIGEST,
        ),
        (
            "review harness",
            "tests/conformance/test_review_contracts.py",
            EXPECTED_REVIEW_HARNESS_DIGEST,
        ),
        (
            "assurance harness",
            "tests/conformance/test_assurance_contracts.py",
            EXPECTED_ASSURANCE_HARNESS_DIGEST,
        ),
        (
            "final review harness",
            "tests/conformance/test_final_review_contracts.py",
            EXPECTED_FINAL_REVIEW_HARNESS_DIGEST,
        ),
    ]
    for label, relative, literal in harnesses:
        artifact = root / relative
        if artifact.is_file() and _sha256(artifact) != literal:
            errors.append("{} digest does not match embedded release anchor".format(label))

    roles_dir = root / ".codex/agents"
    role_files = sorted(roles_dir.glob("*.toml")) if roles_dir.is_dir() else []
    details["role_files"] = [str(path.relative_to(root)) for path in role_files]
    if len(role_files) != 5:
        errors.append("expected exactly five role TOMLs, got {}".format(len(role_files)))
    role_names: List[str] = []
    for path in role_files:
        try:
            role = _role_toml(path)
        except ContractError as exc:
            errors.append(str(exc))
            continue
        role_names.append(role["name"])
        expected_sandbox = "read-only" if role["name"] in READ_ONLY_ROLES else "workspace-write"
        if role["sandbox_mode"] != expected_sandbox:
            errors.append("{} has incorrect sandbox_mode".format(path.relative_to(root)))
        if "AGENTS.md" not in role["developer_instructions"]:
            errors.append("{} does not reference AGENTS.md".format(path.relative_to(root)))
        if "contracts/meva.schema.json" not in role["developer_instructions"]:
            errors.append("{} does not reference schema authority".format(path.relative_to(root)))
    if set(role_names) != EXPECTED_WORKERS or len(role_names) != len(set(role_names)):
        errors.append("role names do not exactly match the five canonical workers")
    if (roles_dir / "meva_orchestrator.toml").exists():
        errors.append("custom primary orchestrator role must not exist")

    config_path = root / ".codex/config.toml"
    if config_path.is_file():
        try:
            config = _tiny_toml(config_path)
            for table, keys in CONFIG_KEYS.items():
                if set(config.get(table, {})) != keys:
                    errors.append(
                        "config table [{}] must contain only {}".format(table, sorted(keys))
                    )
            if config.get("agents", {}).get("enabled") is not True:
                errors.append("agents.enabled must be true")
            concurrency = config.get("agents", {}).get(
                "max_concurrent_threads_per_session"
            )
            if not isinstance(concurrency, int) or isinstance(concurrency, bool) or not 1 <= concurrency <= 4:
                errors.append(
                    "agents.max_concurrent_threads_per_session must be an integer from 1 to 4"
                )
            else:
                details["configured_concurrency"] = concurrency
            if config.get("agents", {}).get("interrupt_message") is not True:
                errors.append("agents.interrupt_message must be true")
        except ContractError as exc:
            errors.append(str(exc))

    schema_path = root / "contracts/meva.schema.json"
    template_path = root / "templates/project-state.json"
    if schema_path.is_file() and template_path.is_file():
        try:
            _, schema, state_errors = validate_state(template_path, schema_path)
            errors.extend("template: {}".format(item) for item in state_errors)
            defs = schema.get("$defs", {})
            canonical = {
                "workerRole": EXPECTED_WORKERS,
                "severity": {"critical", "high", "medium", "low"},
                "priority": {"P0", "P1", "P2", "P3"},
                "reviewRecommendation": {"pass", "conditional", "fail"},
                "findingDisposition": {
                    "open",
                    "resolved",
                    "risk_accepted",
                    "duplicate",
                    "withdrawn",
                },
            }
            for name, expected in canonical.items():
                actual = set(defs.get(name, {}).get("enum", []))
                if actual != expected:
                    errors.append("schema enum {} does not match canonical set".format(name))
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                errors.append("schema is not declared as Draft 2020-12")
        except ContractError as exc:
            errors.append(str(exc))

    absolute_pattern = re.compile(
        r"(?:^|[\"'\\s])(?:/Users/|/home/|/workspace/|[A-Za-z]:[\\\\/])"
    )
    scan_paths = [
        "AGENTS.md",
        ".codex/config.toml",
        "contracts/meva.schema.json",
        "templates/project-state.json",
        "README.md",
        "docs/reviewer-handbook.md",
    ] + details.get("role_files", [])
    for relative in scan_paths:
        path = root / relative
        if path.is_file() and absolute_pattern.search(path.read_text(encoding="utf-8")):
            errors.append("{} contains a shipped absolute path".format(relative))

    return errors, details


def _find_task(state: Mapping[str, Any], task_id: str) -> Mapping[str, Any]:
    for task in state["tasks"]:
        if task["id"] == task_id:
            return task
    raise ContractError("unknown task_id {}".format(task_id))


def _preflight(
    state: Mapping[str, Any],
    task_id: str,
    role: str,
    action: str,
    action_kind: str,
    path: Optional[str],
    environment: str,
    increments: Mapping[str, float],
    delegation_depth: Optional[int],
    retry_count: Optional[int],
    alternative_attempts: Optional[int],
    action_chain_steps: Optional[int],
    now: datetime,
    root: Optional[Path] = None,
    state_path: Optional[Path] = None,
    target_expected_digest: Optional[str] = None,
    target_expected_absent: bool = False,
) -> Tuple[str, List[str], List[str]]:
    errors: List[str] = []
    notices: List[str] = []
    task = _find_task(state, task_id)
    for label, value in increments.items():
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value < 0
        ):
            errors.append("{} increment must be finite and nonnegative".format(label))
    for label, value in (
        ("delegation depth", delegation_depth),
        ("retry count", retry_count),
        ("alternative attempts", alternative_attempts),
        ("action-chain steps", action_chain_steps),
    ):
        if value is not None and value < 0:
            errors.append("{} must be nonnegative".format(label))
    if state["state"]["status"] in TERMINAL_STATES:
        errors.append("project state is terminal")
    if task["accountable_owner"] != role:
        errors.append("role does not own task")
    if environment not in ROLE_MAX_ENVIRONMENTS.get(role, set()):
        errors.append("environment is outside role maximum")
    if action not in task["allowed_actions"]:
        errors.append("action is outside task authority")
    trusted_metadata = task["extensions"].get("trusted_capability_metadata", {})
    trusted_kind = trusted_metadata.get("trusted_action_kind")
    if trusted_kind is not None and action_kind != trusted_kind:
        errors.append("caller action kind conflicts with trusted capability metadata")
    effect = trusted_metadata.get("effect")
    if effect is not None and effect not in ROLE_MAX_EFFECTS.get(role, set()):
        errors.append("requested effect is outside role maximum")
    if (
        role == "implementation_engineer"
        and environment == "production"
        and effect != "project_write"
    ):
        errors.append(
            "implementation production authority is limited to scoped project_write"
        )
    write_effect = effect == "project_write" or (
        action in {"edit_assigned_files", "write", "delete", "migrate"}
        and role not in READ_ONLY_ROLES
    )
    if write_effect and path is None:
        errors.append("write effect requires an exact structured path target")
    authority = state["authority"]
    if authority["source_kind"] not in {"runtime_owned", "trusted_external"}:
        return "unverified", ["human authority source is unknown or untrusted"], notices
    if action not in authority["allowed_actions"]:
        errors.append("action is outside human authority")
    if environment not in task["extensions"].get("allowed_environments", [task["target_environment"]]):
        errors.append("environment is outside task authority")
    if environment not in authority["environments"]:
        errors.append("environment is outside human authority")
    authority_expiry = _parse_utc(authority["expires_at"])
    authority_expiry_unknown = authority_expiry is None
    if authority_expiry is not None and now >= authority_expiry:
        errors.append("human authority is expired")

    permissions: Optional[Mapping[str, Any]] = None
    try:
        attestation = _selected_permission_attestation(
            state, role, task_id, now
        )
    except ContractError as exc:
        fallback_errors: List[str] = []
        matching_attestations = [
            item
            for item in state["permission_attestations"]
            if item["role"] == role and item["task_id"] == task_id
        ]
        if (
            str(exc) != "selected permission attestation is unavailable"
            or matching_attestations
        ):
            return "unverified", [str(exc)], notices
        if role in READ_ONLY_ROLES:
            fallback_errors.append("Core local fallback is unavailable to read-only roles")
        if task["status"] != "in_progress":
            fallback_errors.append("Core local fallback requires an active task")
        if state["project"]["risk_tier"] != "R0" or task["risk_tier"] != "R0":
            fallback_errors.append("Core local fallback is limited to R0")
        if environment != "local":
            fallback_errors.append("Core local fallback is limited to local")
        if action != "edit_assigned_files" or action_kind != "ordinary":
            fallback_errors.append(
                "Core local fallback permits only ordinary edit_assigned_files"
            )
        if effect != "project_write" or not write_effect:
            fallback_errors.append(
                "Core local fallback requires explicit trusted project_write metadata"
            )
        if task["physical_safety_tier"] not in {"not_applicable", "E0"} or state[
            "project"
        ]["physical_safety_tier"] not in {"not_applicable", "E0"}:
            fallback_errors.append("Core local fallback excludes E1-E3 physical work")
        if task["approvals_required"]:
            fallback_errors.append("Core local fallback cannot satisfy required approvals")
        if increments.get("external_calls", 0) != 0:
            fallback_errors.append("Core local fallback forbids external calls")
        if increments.get("worker_fanout", 0) != 0:
            fallback_errors.append("Core local fallback does not authorize fan-out")
        if any(
            increments.get(label, 0) != 0
            for label in ("cost", "compute_units", "wall_time_seconds")
        ):
            fallback_errors.append(
                "Core local fallback does not accept metered resource increments"
            )
        if any(
            value not in {None, 0}
            for value in (
                delegation_depth,
                retry_count,
                alternative_attempts,
                action_chain_steps,
            )
        ):
            fallback_errors.append(
                "Core local fallback does not accept delegated, retry, "
                "alternative, or chained execution"
            )
        if task["accounting"]["budget"]["max_external_calls"] != 0 or state[
            "accounting"
        ]["budget"]["max_external_calls"] != 0:
            fallback_errors.append(
                "Core local fallback requires zero external-call capacity"
            )
        if authority.get("extensions", {}).get("external_effect") != "none":
            fallback_errors.append(
                "Core local fallback requires human authority with no external effect"
            )
        if authority_expiry_unknown and authority.get("extensions", {}).get(
            "core_local_authority"
        ) is not True:
            fallback_errors.append(
                "unknown authority expiry requires explicit current-session "
                "Core local authority"
            )
        if state["project"]["data_classification"] not in {
            "public",
            "internal",
        } or task["data_classification"] not in {"public", "internal"}:
            fallback_errors.append(
                "Core local fallback is limited to public/internal data"
            )
        if task.get("extensions", {}).get("core_local_rollback") != (
            "restore_preimage"
        ):
            fallback_errors.append(
                "Core local fallback requires explicit restore_preimage rollback"
            )
        if root is None:
            fallback_errors.append(
                "Core local fallback requires an exact trusted project root"
            )
        elif state_path is None:
            fallback_errors.append(
                "Core local fallback requires the exact canonical state path"
            )
        else:
            try:
                state_path.resolve().relative_to(root.resolve())
            except ValueError:
                fallback_errors.append(
                    "Core local fallback state is outside the trusted project root"
                )
        if target_expected_absent:
            fallback_errors.append(
                "Core local fallback does not create new files"
            )
        if target_expected_digest is None:
            fallback_errors.append(
                "Core local fallback requires an existing-file preimage digest"
            )
        if target_expected_digest is not None and _canonical_digest(
            target_expected_digest
        ) is None:
            fallback_errors.append(
                "Core local fallback target digest is not canonical SHA-256"
            )
        if any(
            item["status"] in {"reserved", "claimed", "recovery_required"}
            for item in state.get("action_ledger", {}).get("reservations", [])
        ):
            fallback_errors.append(
                "Core local fallback is unavailable with pending atomic actions"
            )
        if fallback_errors:
            return "unverified", fallback_errors, notices
        notices.append(CORE_LOCAL_FALLBACK_NOTICE)
        if authority_expiry_unknown:
            notices.append(
                "human authority expiry is unknown; eligibility is limited to "
                "the current interactive session"
            )
    else:
        if authority_expiry_unknown:
            return "unverified", ["human authority expiry is unknown"], notices
        if attestation["source_kind"] != "runtime_owned":
            errors.append("permission attestation is not runtime-owned")
        if attestation["status"] != "current":
            errors.append("permission attestation is not current")
        attestation_expiry = _parse_utc(attestation["expires_at"])
        if attestation_expiry is None:
            return "unverified", ["permission attestation expiry is unknown"], notices
        if now >= attestation_expiry:
            errors.append("permission attestation is expired")
        permissions = attestation["effective_permissions"]
        if action not in permissions["actions"]:
            errors.append("runtime does not attest requested action")
        if effect == "external_read" and increments.get("external_calls", 0) < 1:
            errors.append("external read must reserve at least one external call")
        if not set(permissions["actions"]).issubset(set(task["allowed_actions"])):
            errors.append("runtime actions are broader than ticket")
        if not set(permissions["environments"]).issubset(
            set(task["extensions"].get("allowed_environments", [task["target_environment"]]))
        ):
            errors.append("runtime environments are broader than ticket")
        if not set(permissions["environments"]).issubset(set(authority["environments"])):
            errors.append("runtime environments are broader than human authority")
        if permissions["external_calls"] and task["accounting"]["budget"]["max_external_calls"] == 0:
            errors.append("runtime external-call capability is broader than ticket")
        for runtime_scope in permissions["writable_scopes"]:
            if not _path_within(runtime_scope, task["writable_scope"]):
                errors.append("runtime writable scope is broader than ticket")
            if not _path_within(runtime_scope, authority["scopes"]):
                errors.append("runtime writable scope is broader than human authority")
        if role in READ_ONLY_ROLES and permissions["writable_scopes"]:
            errors.append("read-only role has effective write permission")

    if path is not None:
        problem = _relative_path_error(path)
        if problem:
            errors.append("requested path: {}".format(problem))
        if role in READ_ONLY_ROLES:
            errors.append("read-only role may not write")
        if not _path_within(path, task["writable_scope"]):
            errors.append("requested path is outside ticket writable_scope")
        if not _path_within(path, authority["scopes"]):
            errors.append("requested path is outside human authority")
        if permissions is not None and not _path_within(
            path, permissions["writable_scopes"]
        ):
            errors.append("requested path is outside attested runtime capability")
        if CORE_LOCAL_FALLBACK_NOTICE in notices and root is not None and not problem:
            resolved_root = root.resolve()
            unresolved_target = resolved_root / path
            resolved_target = unresolved_target.resolve(strict=False)
            try:
                resolved_target.relative_to(resolved_root)
            except ValueError:
                errors.append("Core local fallback target escapes the project root")
            cursor = resolved_root
            if any(
                (cursor := cursor / component).is_symlink()
                for component in PurePosixPath(path).parts
            ):
                errors.append(
                    "Core local fallback target path may not contain a symlink"
                )
            if target_expected_absent:
                if unresolved_target.exists():
                    errors.append(
                        "Core local fallback expected-absent target already exists"
                    )
            elif target_expected_digest is not None:
                if not unresolved_target.is_file():
                    errors.append(
                        "Core local fallback digest target is not a regular file"
                    )
                elif not _digests_equal(
                    target_expected_digest, _sha256(unresolved_target)
                ):
                    errors.append(
                        "Core local fallback target digest compare failed"
                    )

    accounting = task["accounting"]
    budget = accounting["budget"]
    usage = accounting["usage"]
    pairs = {
        "cost": "max_cost",
        "compute_units": "max_compute_units",
        "wall_time_seconds": "max_wall_time_seconds",
        "external_calls": "max_external_calls",
        "worker_fanout": "max_worker_fanout",
        "action_chain_steps": "max_action_chain_steps",
    }
    ratios: List[float] = []
    for usage_key, limit_key in pairs.items():
        proposed = usage[usage_key] + increments.get(usage_key, 0)
        limit = budget[limit_key]
        if limit is None:
            continue
        if proposed > limit:
            errors.append("{} would exceed hard limit".format(usage_key))
        if limit == 0:
            ratio = float("inf") if proposed > 0 else 0.0
        else:
            ratio = float(proposed) / float(limit)
        if usage_key != "action_chain_steps":
            ratios.append(ratio)
    maximum_ratio = max(ratios) if ratios else 0.0
    if maximum_ratio >= 1.0 and action_kind not in {"cleanup", "emergency_safe_stop"}:
        errors.append("100% threshold denies ordinary work")
    elif maximum_ratio >= 0.9 and action_kind in {"fanout", "nonessential"}:
        errors.append("90% threshold denies fan-out and nonessential work")
    elif maximum_ratio >= 0.7:
        notices.append("70% threshold requires notification and re-estimate")
        if not accounting["notified_at_70_percent"] or not accounting[
            "reestimated_at_70_percent"
        ]:
            errors.append("70% threshold accounting controls are incomplete")

    bounded_values = [
        ("delegation depth", delegation_depth, budget["max_delegation_depth"]),
        ("retry count", retry_count, budget["max_retries_per_operation"]),
        ("alternative attempts", alternative_attempts, budget["max_alternative_attempts"]),
        ("action-chain steps", action_chain_steps, budget["max_action_chain_steps"]),
    ]
    for label, proposed, limit in bounded_values:
        if proposed is not None and limit is not None and proposed > limit:
            errors.append("{} exceeds hard limit".format(label))

    return ("fail" if errors else "pass"), errors, notices


def _evaluate_review(
    state: Mapping[str, Any], now: datetime, root: Path
) -> Tuple[str, List[str], List[str], bool]:
    errors: List[str] = []
    blockers: List[str] = []
    review = state["review"]
    mode = review.get("extensions", {}).get("mode")
    emits_gate = review.get("extensions", {}).get("gate_result_emitted")
    if mode not in {None, "advisory", "formal"}:
        errors.append("review mode is not supported")
    if mode == "advisory" and emits_gate is not False:
        errors.append("advisory review may not emit a gate result")
    if mode == "formal":
        errors.extend(
            _formal_review_contract_errors(
                state, now, {"in_progress"}
            )
        )
        if emits_gate is not True:
            errors.append("formal review must explicitly emit a gate result")
        if review["extensions"].get("state_revision") != state["state"]["revision"]:
            errors.append("formal review does not bind the current state revision")
        if (
            review["extensions"].get("invalidation_revision")
            != state["state"]["current_invalidation_revision"]
        ):
            errors.append("formal review does not bind the current invalidation revision")
        reviewer_tasks = [
            task
            for task in state["tasks"]
            if task["accountable_owner"] == "reviewer"
            and task["status"] == "in_progress"
        ]
        matching = [
            item
            for item in state["permission_attestations"]
            if item["role"] == "reviewer"
            and item["source_kind"] == "runtime_owned"
            and item["status"] == "current"
            and item["fresh_session"]
        ]
        if len(reviewer_tasks) != 1 or len(matching) != 1:
            errors.append("formal review lacks one current runtime-owned reviewer attestation")
        else:
            task = reviewer_tasks[0]
            attestation = matching[0]
            declared_task_id = review["extensions"].get("task_id", task["id"])
            if declared_task_id != task["id"]:
                errors.append("formal review does not bind the exact reviewer task")
            package_errors, package_details = _package_checks(root)
            if package_errors:
                errors.append("formal review package is not trusted")
            else:
                activation, activation_errors = _runtime_activation(
                    state,
                    "reviewer",
                    task["id"],
                    now,
                    root,
                    package_details.get(
                        "configured_concurrency", MAX_CONFIGURED_CONCURRENCY
                    ),
                )
                if activation != "pass":
                    errors.extend(
                        "formal review activation {}: {}".format(
                            activation, item
                        )
                        for item in activation_errors
                    )
            expires = _parse_utc(attestation["expires_at"])
            observed = _parse_utc(attestation["observed_at"])
            owner_instance, owner_error = _effective_owner_instance(
                state, task, "reviewer", now
            )
            if (
                owner_error
                or owner_instance is None
                or review["reviewer"] != owner_instance
            ):
                errors.append("formal reviewer identity is not the exact owner instance")
            if (
                expires is None
                or observed is None
                or observed > now
                or now >= expires
            ):
                errors.append("formal reviewer attestation is outside its validity interval")
            permissions = attestation["effective_permissions"]
            if (
                task["writable_scope"]
                or task["changed_paths"]
                or permissions["writable_scopes"]
                or not set(task["allowed_actions"]).issubset(
                    READ_ONLY_ROLE_ACTIONS["reviewer"]
                )
                or not set(permissions["actions"]).issubset(
                    READ_ONLY_ROLE_ACTIONS["reviewer"]
                )
            ):
                errors.append("formal review lacks effective read-only enforcement")
            ticket_digest = hashlib.sha256(
                json.dumps(task, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest()
            if not _digests_equal(attestation["ticket_digest"], ticket_digest):
                errors.append("formal review attestation does not bind the exact ticket")
            for key in (
                "runtime",
                "model",
                "provider",
                "policy_digest",
                "config_digest",
                "manual_digest",
                "schema_digest",
                "role_digest",
                "ticket_digest",
            ):
                canonical = state["provenance"][key]
                attested = attestation[key]
                equal = (
                    _digests_equal(canonical, attested)
                    if key.endswith("_digest")
                    else canonical == attested
                )
                if canonical == "unknown" or attested == "unknown" or not equal:
                    errors.append(
                        "formal review lacks current {} provenance".format(key)
                    )
    if review["reviewer"] == "unknown":
        errors.append("reviewer identity is unknown")
    if review["independence_conflicts"]:
        errors.append("review independence conflict")
    artifacts = _records_by_id(state["artifacts"])
    evidence = _records_by_id(state["evidence"])
    for artifact_id in review["target_artifact_ids"]:
        if artifact_id in artifacts and review["reviewer"] in artifacts[artifact_id]["authors"]:
            errors.append("reviewer authored target artifact {}".format(artifact_id))
    for evidence_id in review["target_evidence_ids"]:
        if evidence_id in evidence and review["reviewer"] in evidence[evidence_id]["authors"]:
            errors.append("reviewer authored target evidence {}".format(evidence_id))

    approvals = {item["approval_id"]: item for item in state["approvals"]}
    open_nonblockers: List[str] = []
    legacy_nongating: List[str] = []
    for finding in state["findings"]:
        if finding["disposition"] == "open":
            if finding["severity"] in {"critical", "high"}:
                blockers.append(finding["id"])
            else:
                open_nonblockers.append(finding["id"])
        elif finding["disposition"] == "risk_accepted" and finding["severity"] in {
            "critical",
            "high",
        }:
            approval = approvals.get(finding["approval_id"])
            if approval is None:
                blockers.append(finding["id"])
            else:
                if finding["extensions"]:
                    operation = finding["extensions"].get("affected_operation", {})
                    approval_errors = []
                    nonwaivable = _nonwaivable_finding_reason(finding)
                    if nonwaivable:
                        approval_errors.append(nonwaivable)
                    if approval["action"] != "risk_accept_finding":
                        approval_errors.append("approval action mismatch")
                    extension = approval.get("extensions", {})
                    if (
                        extension.get("finding_id") != finding["id"]
                        or extension.get("finding_revision")
                        != finding["extensions"].get("finding_revision")
                        or extension.get("affected_operation") != operation
                    ):
                        approval_errors.append("approval affected operation mismatch")
                    if approval["scope"] != operation.get("scope"):
                        approval_errors.append("approval scope mismatch")
                    if approval["environment"] != operation.get("environment"):
                        approval_errors.append("approval environment mismatch")
                    approval_errors.extend(
                        _approval_operation_limit_errors(operation, approval)
                    )
                    verification = approval["verification"]
                    if (
                        approval["status"] != "active"
                        or verification["status"] != "verified"
                        or verification["source_kind"]
                        not in {"runtime_owned", "trusted_external"}
                    ):
                        approval_errors.append("approval is not current and trusted")
                    issued = _parse_utc(approval["issued_at"])
                    expires = _parse_utc(approval["expires_at"])
                    if issued is None or expires is None or now < issued or now >= expires:
                        approval_errors.append("approval is outside its validity interval")
                else:
                    legacy_nongating.append(finding["id"])
                    approval_errors = _approval_check(
                        approval,
                        "accept_finding:{}".format(finding["id"]),
                        approval["scope"],
                        approval["environment"],
                        approval["limits"],
                        now,
                    )
                if approval_errors:
                    blockers.append(finding["id"])
                    errors.extend(
                        "finding {}: {}".format(finding["id"], item)
                        for item in approval_errors
                    )
        elif (
            finding["disposition"] == "resolved"
            and finding["severity"] in {"critical", "high"}
            and not finding["extensions"]
        ):
            legacy_nongating.append(finding["id"])

    if errors or blockers:
        expected = "fail"
    elif open_nonblockers:
        expected = "conditional"
    else:
        expected = "pass"
    if review["recommendation"] != expected:
        errors.append(
            "declared recommendation {} attempts to differ from {}".format(
                review["recommendation"], expected
            )
        )
    gate_eligible = (
        not errors
        and not blockers
        and not legacy_nongating
        and mode == "formal"
        and emits_gate is True
        and expected == "pass"
    )
    return expected, errors, blockers, gate_eligible


@contextlib.contextmanager
def _locked_state(path: Path) -> Iterable[Tuple[bytes, Mapping[str, Any]]]:
    """Lock an adjacent stable inode, then read and hash the exact state bytes."""

    if fcntl is None:
        raise ContractError("atomic reservation requires POSIX flock support")
    path = path.resolve()
    lock_path = path.parent / (path.name + ".meva.lock")
    descriptor = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CASConflict("state reservation lock is held by another writer") from exc
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            raise ContractError("missing JSON file: {}".format(path)) from exc
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError("state is not UTF-8") from exc
        state = _loads_strict_json(text, str(path))
        if not isinstance(state, Mapping):
            raise ContractError("state JSON root must be an object")
        yield raw, state
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _durable_replace_json(path: Path, state: Mapping[str, Any]) -> str:
    """Write mode-0600 JSON, fsync it, replace atomically, and fsync its directory."""

    payload = (
        json.dumps(
            state,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(
        prefix="." + path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return hashlib.sha256(payload).hexdigest()


def _cas_inputs(
    raw: bytes,
    state: Mapping[str, Any],
    expected_state_revision: int,
    expected_ledger_revision: int,
    expected_state_digest: str,
) -> Mapping[str, Any]:
    actual_digest = hashlib.sha256(raw).hexdigest()
    if not _digests_equal(expected_state_digest, actual_digest):
        raise CASConflict("exact state digest compare failed")
    if state["state"]["revision"] != expected_state_revision:
        raise CASConflict("state revision compare failed")
    ledger = state.get("action_ledger")
    if ledger is None:
        raise ContractError(
            "legacy state has no action_ledger; consequential authorization is unavailable"
        )
    if ledger["revision"] != expected_ledger_revision:
        raise CASConflict("action ledger revision compare failed")
    return ledger


def _action_amounts(args: argparse.Namespace, prefix: str = "") -> Dict[str, Any]:
    def value(name: str) -> Any:
        attribute = prefix + name.replace("-", "_")
        if name == "action-chain-steps" and not hasattr(args, attribute):
            return 1
        return getattr(args, attribute)

    amounts = {
        "cost": value("cost"),
        "compute_units": value("compute_units"),
        "wall_time_seconds": value("wall_time_seconds"),
        "external_calls": value("external_calls"),
        "worker_fanout": value("worker_fanout"),
        "action_chain_steps": value("action-chain-steps"),
    }
    for key, item in amounts.items():
        if (
            not isinstance(item, (int, float))
            or isinstance(item, bool)
            or not math.isfinite(item)
            or item < 0
        ):
            raise ContractError("{} must be finite and nonnegative".format(key))
    return amounts


def _trusted_action_metadata(
    task: Mapping[str, Any], action: str
) -> Tuple[str, str, str]:
    declared = task["extensions"].get("trusted_capability_metadata", {})
    if declared:
        if declared.get("action", action) != action:
            raise ContractError("trusted capability metadata does not bind the action")
        kind = declared.get("trusted_action_kind")
        effect = declared.get("effect")
        if kind not in {
            "ordinary",
            "essential",
            "nonessential",
            "fanout",
            "cleanup",
            "emergency_safe_stop",
        } or effect not in {
            "project_read",
            "project_write",
            "external_read",
            "external_mutation",
            "physical",
        }:
            raise ContractError("trusted capability metadata is incomplete")
        capability_id = declared.get("capability_id")
        if capability_id is None:
            capability_digest = hashlib.sha256(
                json.dumps(
                    declared,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            capability_id = "capability-" + capability_digest
        if (
            not isinstance(capability_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", capability_id) is None
        ):
            raise ContractError("trusted capability identity is invalid")
        return str(kind), str(effect), capability_id
    if (
        task["accountable_owner"] in READ_ONLY_ROLES
        and action in READ_ONLY_ROLE_ACTIONS[task["accountable_owner"]]
        and task["extensions"].get("allow_external_calls") is True
        and task["extensions"].get("external_effect") == "read_only"
        and task["extensions"].get("structured_external_targets")
    ):
        derived = {
            "action": action,
            "trusted_action_kind": "ordinary",
            "effect": "external_read",
            "targets": task["extensions"]["structured_external_targets"],
        }
        digest = hashlib.sha256(
            json.dumps(
                derived, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        ).hexdigest()
        return "ordinary", "external_read", "capability-" + digest
    raise ContractError("action lacks trusted capability metadata")


def _validate_exact_target(
    state: Mapping[str, Any],
    task: Mapping[str, Any],
    root: Path,
    permissions: Mapping[str, Any],
    effect: str,
    kind: str,
    identifier: str,
    path: Optional[str],
    expected_revision: Optional[int],
    expected_digest: Optional[str],
) -> Dict[str, Any]:
    if not kind or not identifier:
        raise ContractError("structured target kind and id are required")
    target = {"kind": kind, "id": identifier}
    if path is not None:
        problem = _relative_path_error(path)
        if problem:
            raise ContractError("structured target path: {}".format(problem))
        target["path"] = path
    if expected_revision is not None:
        if expected_revision < 0:
            raise ContractError("target expected revision must be nonnegative")
        actual_revision: Optional[int] = None
        if kind == "project_state" and identifier in {
            "state",
            state["project"]["id"],
        }:
            actual_revision = state["state"]["revision"]
        else:
            for collection in (
                "requirements",
                "interfaces",
                "decisions",
                "tasks",
                "gates",
                "artifacts",
                "evidence",
                "findings",
                "invalidations",
                "persistent_resources",
            ):
                record = next(
                    (item for item in state[collection] if item["id"] == identifier),
                    None,
                )
                if record is None:
                    continue
                candidate = record.get(
                    "revision",
                    record.get("extensions", {}).get("target_revision"),
                )
                if isinstance(candidate, int) and not isinstance(candidate, bool):
                    actual_revision = candidate
                break
        if actual_revision is None:
            raise ContractError(
                "target expected revision is unsupported without a trusted current revision"
            )
        if expected_revision != actual_revision:
            raise CASConflict("target expected revision compare failed")
        target["expected_revision"] = expected_revision
    if expected_digest is not None:
        if _canonical_digest(expected_digest) is None:
            raise ContractError("target expected digest must be a SHA-256 digest")
        target["expected_digest"] = _canonical_digest(expected_digest)
    if effect == "project_write" and path is None:
        raise ContractError("project write requires a canonical path target")
    if path is not None:
        candidate = (root / path).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ContractError("target path escapes package root") from exc
        for label, scopes in (
            ("ticket", task["writable_scope"]),
            ("human authority", state["authority"]["scopes"]),
            ("attested runtime", permissions["writable_scopes"]),
        ):
            resolved_scopes = [(root / scope).resolve(strict=False) for scope in scopes]
            if not any(
                candidate == scope or _is_relative_to(candidate, scope)
                for scope in resolved_scopes
            ):
                raise ContractError(
                    "resolved target path is outside {} scope".format(label)
                )
    if effect == "external_read":
        allowed = task["extensions"].get("structured_external_targets", [])
        comparable = {"kind": kind, "id": identifier}
        if comparable not in allowed:
            raise ContractError("external target is not an exact authorized target")
    if effect in {"external_mutation", "physical"}:
        raise ContractError("{} is not authorized by the generic reservation interface".format(effect))
    return target


def _selected_permission_attestation(
    state: Mapping[str, Any],
    role: str,
    task_id: str,
    now: Optional[datetime] = None,
) -> Mapping[str, Any]:
    dated: List[Tuple[datetime, Mapping[str, Any]]] = []
    for item in state["permission_attestations"]:
        if item["role"] == role and item["task_id"] == task_id:
            observed = _parse_utc(item["observed_at"])
            if observed is not None:
                dated.append((observed, item))
    if not dated:
        raise ContractError("selected permission attestation is unavailable")
    latest_time = max(observed for observed, _ in dated)
    latest = [item for observed, item in dated if observed == latest_time]
    if len(latest) != 1:
        raise ContractError("selected permission attestation is ambiguous")
    if now is not None and latest_time > now:
        raise ContractError("selected permission attestation is future-dated")
    return latest[0]


def _canonical_request_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _trusted_state_path(
    raw_state: str, root: Path, trusted_state_root: Optional[str]
) -> Path:
    root = root.resolve()
    state_path = Path(raw_state).resolve()
    allowed_root = (
        Path(trusted_state_root).resolve()
        if trusted_state_root is not None
        else root
    )
    try:
        state_path.relative_to(allowed_root)
    except ValueError as exc:
        raise ContractError(
            "state path is outside the package root; use --trusted-state-root "
            "only for an explicitly trusted external state root"
        ) from exc
    if trusted_state_root is None:
        try:
            state_path.relative_to(root)
        except ValueError as exc:
            raise ContractError("state path escapes package root") from exc
    return state_path


def _outstanding_amounts(
    ledger: Mapping[str, Any], task_id: Optional[str] = None
) -> Dict[str, float]:
    totals: Dict[str, float] = {key: 0 for key in ACCOUNTING_FIELDS}
    for reservation in ledger["reservations"]:
        if reservation["status"] not in {"reserved", "claimed"}:
            continue
        if task_id is not None and reservation["task_id"] != task_id:
            continue
        for key in totals:
            totals[key] += reservation["reserved"][key]
    return totals


def _reservation_capacity_errors(
    state: Mapping[str, Any],
    task: Mapping[str, Any],
    ledger: Mapping[str, Any],
    amounts: Mapping[str, Any],
    action_kind: str = "ordinary",
) -> List[str]:
    errors: List[str] = []
    project_pending = _outstanding_amounts(ledger)
    task_pending = _outstanding_amounts(ledger, str(task["id"]))
    for label, accounting, pending in (
        ("project", state["accounting"], project_pending),
        ("task", task["accounting"], task_pending),
    ):
        ratios: List[float] = []
        for usage_key, limit_key in ACCOUNTING_FIELDS.items():
            limit = accounting["budget"][limit_key]
            effective = (
                accounting["usage"][usage_key]
                + pending[usage_key]
                + amounts[usage_key]
            )
            if limit is not None and effective > limit:
                errors.append(
                    "{} {} committed plus reserved use would exceed hard limit".format(
                        label, usage_key
                    )
                )
            if limit is not None and usage_key != "action_chain_steps":
                ratios.append(
                    float("inf")
                    if limit == 0 and effective > 0
                    else (0.0 if limit == 0 else float(effective) / float(limit))
                )
        maximum = max(ratios) if ratios else 0.0
        if maximum >= 1.0 and action_kind not in {
            "cleanup",
            "emergency_safe_stop",
        }:
            errors.append(
                "{} committed plus pending capacity reaches the ordinary-work stop".format(
                    label
                )
            )
        elif maximum >= 0.9 and action_kind in {"fanout", "nonessential"}:
            errors.append(
                "{} committed plus pending capacity denies fan-out/nonessential work".format(
                    label
                )
            )
        elif maximum >= 0.7 and (
            not accounting["notified_at_70_percent"]
            or not accounting["reestimated_at_70_percent"]
        ):
            errors.append(
                "{} committed plus pending capacity lacks 70% controls".format(label)
            )
    return errors


def _atomic_error_payload(message: str, exit_code: int) -> Tuple[int, Dict[str, Any]]:
    result = "unverified" if exit_code == 2 else "fail"
    return exit_code, {
        "contract_version": "2.0",
        "result": result,
        "errors": [message],
        "authorizes_consequential_action": False,
    }


def command_check_package(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    errors, details = _package_checks(root)
    static_result = "fail" if errors else "pass"
    activation_result = "unverified"
    activation_errors = ["runtime activation was not evaluated"]
    if args.state:
        state_path = (root / args.state).resolve()
        schema_path = root / "contracts/meva.schema.json"
        try:
            state, _, state_errors = validate_state(state_path, schema_path)
            details["migration_mode"] = (
                "rv2" if "action_ledger" in state else "legacy_read_only"
            )
            if state_errors:
                activation_result = "fail"
                activation_errors = ["state: {}".format(item) for item in state_errors]
            else:
                activation_result, activation_errors = _runtime_activation(
                    state,
                    args.role,
                    args.task_id,
                    _now(args.now),
                    root,
                    details.get("configured_concurrency", MAX_CONFIGURED_CONCURRENCY),
                )
        except ContractError as exc:
            activation_result = "fail"
            activation_errors = [str(exc)]
    _json_output(
        {
            "contract_version": "2.0",
            "static_package": static_result,
            "runtime_activation": activation_result,
            "static_errors": errors,
            "activation_observations": activation_errors,
            "details": details,
        }
    )
    return 1 if static_result == "fail" or activation_result == "fail" else 0


def _validated_report_digests(
    root: Path,
    report_path: Path,
    maps: Sequence[Tuple[str, Any]],
    required: Set[str],
) -> List[str]:
    errors: List[str] = []
    declared: Dict[str, Any] = {}
    label = str(report_path.relative_to(root))
    for map_name, value in maps:
        if not isinstance(value, Mapping):
            errors.append("{} lacks required {} digest map".format(label, map_name))
            continue
        for relative, digest in value.items():
            if relative in declared and declared[relative] != digest:
                errors.append(
                    "{} has conflicting digest bindings for {}".format(label, relative)
                )
            declared[str(relative)] = digest
    missing = required - set(declared)
    if missing:
        errors.append(
            "{} lacks required digest bindings {}".format(label, sorted(missing))
        )
    for relative, expected in declared.items():
        problem = _relative_path_error(relative)
        if problem or relative == ".":
            errors.append(
                "{} has noncanonical digest path {!r}".format(label, relative)
            )
            continue
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            errors.append(
                "{} digest path escapes distribution root: {}".format(
                    label, relative
                )
            )
            continue
        if _canonical_digest(str(expected)) is None:
            errors.append(
                "{} has absent or invalid digest for {}".format(label, relative)
            )
        elif not candidate.is_file():
            errors.append("{} binds missing artifact {}".format(label, relative))
        elif not _digests_equal(str(expected), _sha256(candidate)):
            errors.append("{} has stale digest for {}".format(label, relative))
    return errors


def _exact_run_errors(
    report_label: str,
    run_name: str,
    run: Any,
    expected_count: int,
    expected_command: str,
) -> List[str]:
    if not isinstance(run, Mapping):
        return ["{} lacks required {} run record".format(report_label, run_name)]
    expected = {
        "exit_code": 0,
        "tests_run": expected_count,
        "passed": expected_count,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }
    errors = []
    if run.get("command") != expected_command:
        errors.append(
            "{} {} run has inexact command".format(report_label, run_name)
        )
    for key, value in expected.items():
        if run.get(key) != value:
            errors.append(
                "{} {} run has inexact {}: expected {}, got {!r}".format(
                    report_label, run_name, key, value, run.get(key)
                )
            )
    output = run.get("command_output", run.get("output_summary"))
    if (
        not isinstance(output, str)
        or "Ran {} tests".format(expected_count) not in output
        or re.search(r"(^|\n)OK(?:\n|$)", output) is None
        or "FAILED" in output
        or "Traceback" in output
    ):
        errors.append(
            "{} {} run output does not truthfully record an exact passing run".format(
                report_label, run_name
            )
        )
    if run.get("conclusion") != "pass":
        errors.append(
            "{} {} run conclusion is not pass".format(report_label, run_name)
        )
    return errors


def _historical_check_release(args: argparse.Namespace) -> int:
    """Check the installed package plus Validation-owned release reports."""

    root = Path(args.root).resolve()
    errors, details = _package_checks(root)
    original_path = root / "tests/conformance/validation-report.json"
    review_path = root / "tests/conformance/review-validation-report.json"
    assurance_path = root / "tests/conformance/assurance-validation-report.json"
    reports: Dict[str, Mapping[str, Any]] = {}
    for report_path in (original_path, review_path, assurance_path):
        if not report_path.is_file():
            errors.append(
                "release report is missing: {}".format(report_path.relative_to(root))
            )
            continue
        try:
            report = _load_json(report_path)
        except ContractError as exc:
            errors.append(str(exc))
            continue
        if not isinstance(report, Mapping):
            errors.append("{} root must be an object".format(report_path))
            continue
        reports[report_path.name] = report

    original = reports.get(original_path.name)
    if original is not None:
        post_wp4 = original.get("post_wp4")
        protocol_record = original.get("protocol")
        protocol_binding: Any = None
        if (
            isinstance(protocol_record, Mapping)
            and protocol_record.get("path")
            == "tests/conformance/protocol.v1.json"
            and protocol_record.get("lock_verified") is True
        ):
            protocol_binding = {
                "tests/conformance/protocol.v1.json": protocol_record.get("sha256")
            }
        else:
            errors.append(
                "{} lacks exact frozen protocol/lock record".format(
                    original_path.relative_to(root)
                )
            )
        errors.extend(
            _validated_report_digests(
                root,
                original_path,
                [
                    (
                        "post_wp4.implementation_digests",
                        post_wp4.get("implementation_digests")
                        if isinstance(post_wp4, Mapping)
                        else None,
                    ),
                    (
                        "validation_artifact_digests",
                        original.get("validation_artifact_digests"),
                    ),
                    ("protocol", protocol_binding),
                ],
                ORIGINAL_REPORT_BINDINGS,
            )
        )
        if not isinstance(post_wp4, Mapping):
            errors.append(
                "{} lacks current post_wp4 record".format(
                    original_path.relative_to(root)
                )
            )
        else:
            errors.extend(
                _exact_run_errors(
                    str(original_path.relative_to(root)),
                    "post_wp4 original",
                    post_wp4.get("suite"),
                    43,
                    "python3 -B -m unittest -v tests.conformance.test_contracts",
                )
            )
            conclusion = post_wp4.get("conclusion")
            if (
                not isinstance(conclusion, Mapping)
                or conclusion.get("frozen_static_and_fixture_checks") != "pass"
                or conclusion.get("result") not in {"pass", "conditional"}
            ):
                errors.append(
                    "{} post_wp4 conclusion contradicts its passing release evidence".format(
                        original_path.relative_to(root)
                    )
                )

    review = reports.get(review_path.name)
    if review is not None:
        errors.extend(
            _validated_report_digests(
                root,
                review_path,
                [("digests", review.get("digests"))],
                REVIEW_REPORT_BINDINGS,
            )
        )
        runs = review.get("runs")
        if not isinstance(runs, Mapping):
            errors.append(
                "{} lacks exact runs map".format(review_path.relative_to(root))
            )
        else:
            for run_name, count, command in (
                (
                    "original",
                    43,
                    "python3 -B -m unittest -v tests.conformance.test_contracts",
                ),
                (
                    "rv2",
                    30,
                    "python3 -B -m unittest -v tests.conformance.test_review_contracts",
                ),
                (
                    "combined",
                    73,
                    "python3 -B -m unittest -v tests.conformance.test_contracts tests.conformance.test_review_contracts",
                ),
            ):
                errors.extend(
                    _exact_run_errors(
                        str(review_path.relative_to(root)),
                        run_name,
                        runs.get(run_name),
                        count,
                        command,
                    )
                )
        conclusion = review.get("conclusion")
        if (
            not isinstance(conclusion, Mapping)
            or conclusion.get("original_regression_gate") != "pass"
            or conclusion.get("rv2_static_package") != "pass"
            or conclusion.get("overall") != "pass"
        ):
            errors.append(
                "{} conclusion contradicts required passing release evidence".format(
                    review_path.relative_to(root)
                )
            )

    assurance = reports.get(assurance_path.name)
    if assurance is not None:
        errors.extend(
            _validated_report_digests(
                root,
                assurance_path,
                [("digests", assurance.get("digests"))],
                ASSURANCE_REPORT_BINDINGS,
            )
        )
        runs = assurance.get("runs")
        if not isinstance(runs, Mapping):
            errors.append(
                "{} lacks exact runs map".format(
                    assurance_path.relative_to(root)
                )
            )
        else:
            for run_name, count, command in (
                (
                    "assurance",
                    38,
                    "python3 -B -m unittest -v tests.conformance.test_assurance_contracts",
                ),
                (
                    "combined",
                    111,
                    "python3 -B -m unittest -v tests.conformance.test_contracts tests.conformance.test_review_contracts tests.conformance.test_assurance_contracts",
                ),
            ):
                errors.extend(
                    _exact_run_errors(
                        str(assurance_path.relative_to(root)),
                        run_name,
                        runs.get(run_name),
                        count,
                        command,
                    )
                )
        conclusion = assurance.get("conclusion")
        if (
            not isinstance(conclusion, Mapping)
            or conclusion.get("assurance_gate") != "pass"
            or conclusion.get("overall") != "pass"
        ):
            errors.append(
                "{} conclusion contradicts required passing release evidence".format(
                    assurance_path.relative_to(root)
                )
            )
    result = "fail" if errors else "pass"
    _json_output(
        {
            "contract_version": "2.0",
            "release_integrity": result,
            "errors": errors,
            "details": details,
        }
    )
    return 1 if errors else 0


def _final_raw_prior_errors(
    report_label: str, run: Any
) -> List[str]:
    if not isinstance(run, Mapping):
        return ["{} lacks required raw_prior run record".format(report_label)]
    expected = {
        "command": (
            "python3 -B -m unittest -v tests.conformance.test_contracts "
            "tests.conformance.test_review_contracts "
            "tests.conformance.test_assurance_contracts"
        ),
        "exit_code": 1,
        "tests_run": 111,
        "passed": 108,
        "failures": 3,
        "errors": 0,
        "skipped": 0,
        "conclusion": "pass_with_exact_declared_superseded_failures",
    }
    errors: List[str] = []
    for key, value in expected.items():
        if run.get(key) != value:
            errors.append(
                "{} raw_prior has inexact {}: expected {!r}, got {!r}".format(
                    report_label, key, value, run.get(key)
                )
            )
    failure_ids = run.get("failure_test_ids")
    if (
        not isinstance(failure_ids, list)
        or len(failure_ids) != 3
        or set(failure_ids) != SUPERSEDED_FINAL_REVIEW_TEST_IDS
    ):
        errors.append("{} raw_prior has inexact superseded failures".format(report_label))
    if run.get("unexpected_failures") != []:
        errors.append("{} raw_prior has unexpected failures".format(report_label))
    output = run.get("command_output")
    if (
        not isinstance(output, str)
        or "Ran 111 tests" not in output
        or "FAILED (failures=3)" not in output
        or "Traceback" in output
    ):
        errors.append("{} raw_prior output is absent or false".format(report_label))
    return errors


def _final_release_report_errors(
    root: Path,
    report_path: Path,
    report: Mapping[str, Any],
) -> Tuple[List[str], Dict[str, Any]]:
    label = str(report_path.relative_to(root))
    errors: List[str] = []
    details: Dict[str, Any] = {"current_candidate_report": label}
    if (
        report.get("report_version") != "1.0"
        or report.get("contract_version") != "2.0"
        or report.get("task_id") != "WP6-VALIDATION"
        or report.get("phase") != "final-immutable"
    ):
        errors.append("{} identity or phase is not the final candidate".format(label))
    errors.extend(
        _validated_report_digests(
            root,
            report_path,
            [("digests", report.get("digests"))],
            FINAL_REVIEW_REPORT_BINDINGS,
        )
    )

    protocol = report.get("protocol")
    if not isinstance(protocol, Mapping):
        errors.append("{} lacks the final protocol record".format(label))
    else:
        expected_protocol = root / "tests/conformance/final_review_protocol.v1.json"
        expected_lock = root / "tests/conformance/final_review_protocol.v1.sha256"
        if (
            protocol.get("id") != "SAG-FINAL-REVIEW-CONFORMANCE-1.0"
            or protocol.get("path")
            != "tests/conformance/final_review_protocol.v1.json"
            or protocol.get("sha256") != EXPECTED_FINAL_REVIEW_PROTOCOL_DIGEST
            or protocol.get("lock_sha256") != _sha256(expected_lock)
            or protocol.get("lock_verified") is not True
            or _sha256(expected_protocol) != EXPECTED_FINAL_REVIEW_PROTOCOL_DIGEST
        ):
            errors.append("{} final protocol or lock binding is inexact".format(label))

    state_binding = report.get("state_binding")
    state_path = root / ".meva/state.json"
    expected_state_digest: Optional[str] = None
    expected_state_revision: Optional[int] = None
    expected_invalidation_revision: Optional[int] = None
    try:
        state, _, state_errors = validate_state(
            state_path, root / "contracts/meva.schema.json"
        )
    except ContractError as exc:
        state = {}
        state_errors = [str(exc)]
    if state_errors:
        errors.append(
            "{} current state is invalid: {}".format(label, "; ".join(state_errors))
        )
    if not isinstance(state_binding, Mapping):
        errors.append("{} lacks current state_binding".format(label))
    elif state:
        current_revision = state["state"]["revision"]
        current_invalidation = state["state"]["current_invalidation_revision"]
        candidate_revision = state_binding.get("state_revision")
        candidate_invalidation = state_binding.get("invalidation_revision")
        candidate_digest = state_binding.get("sha256")
        details["candidate_state_revision"] = candidate_revision
        if (
            state_binding.get("path") != ".meva/state.json"
            or state_binding.get("validation_result") != "pass"
            or state_binding.get("migration_mode") != "rv2"
            or _canonical_digest(str(candidate_digest)) is None
            or not isinstance(candidate_revision, int)
            or isinstance(candidate_revision, bool)
            or not isinstance(candidate_invalidation, int)
            or isinstance(candidate_invalidation, bool)
        ):
            errors.append("{} state binding is stale or partial".format(label))
        elif candidate_revision == current_revision:
            details["release_binding_mode"] = "direct"
            expected_state_digest = _sha256(state_path)
            expected_state_revision = current_revision
            expected_invalidation_revision = current_invalidation
            if (
                candidate_digest != expected_state_digest
                or candidate_invalidation != current_invalidation
                or "validation_integration"
                in state.get("extensions", {})
            ):
                errors.append("{} direct state binding is inexact".format(label))
        elif candidate_revision < current_revision:
            details["release_binding_mode"] = "integrated"
            expected_state_digest = str(candidate_digest)
            expected_state_revision = candidate_revision
            expected_invalidation_revision = candidate_invalidation
            integration = state.get("extensions", {}).get(
                "validation_integration"
            )
            integration_keys = {
                "candidate_state_sha256",
                "candidate_state_revision",
                "candidate_invalidation_revision",
                "report_path",
                "report_sha256",
                "current_checker_sha256",
                "integrated_state_revision",
            }
            checker_digest = _sha256(root / "tools/meva_check.py")
            report_digest = _sha256(report_path)
            expected_integration = {
                "candidate_state_sha256": candidate_digest,
                "candidate_state_revision": candidate_revision,
                "candidate_invalidation_revision": candidate_invalidation,
                "report_path":
                    "tests/conformance/final-review-validation-report.json",
                "report_sha256": report_digest,
                "current_checker_sha256": checker_digest,
                "integrated_state_revision": candidate_revision + 1,
            }
            if (
                candidate_invalidation != current_invalidation
                or not isinstance(integration, Mapping)
                or set(integration) != integration_keys
                or dict(integration) != expected_integration
            ):
                errors.append(
                    "{} integrated validation lineage is absent or inexact".format(
                        label
                    )
                )

            artifacts = {
                item["id"]: item for item in state["artifacts"]
            }
            report_artifact = artifacts.get("ART-WP6-VALIDATION-REPORT")
            if (
                report_artifact is None
                or report_artifact["location"]
                != "tests/conformance/final-review-validation-report.json"
                or report_artifact["digest"] != report_digest
                or report_artifact["status"] != "current"
            ):
                errors.append(
                    "{} integrated report artifact is absent or stale".format(
                        label
                    )
                )
            evidence = {
                item["id"]: item for item in state["evidence"]
            }
            integrated_evidence = {
                evidence_id
                for evidence_id, item in evidence.items()
                if item["status"] == "current"
                and item["result"] == "pass"
                and item["invalidation_revision"] == current_invalidation
                and item.get("extensions", {}).get("state_revision")
                == candidate_revision + 1
                and "ART-WP6-VALIDATION-REPORT"
                in item.get("depends_on", [])
            }
            integrated_gates = [
                gate
                for gate in state["gates"]
                if gate["gate"] == "validation"
                and gate["result"] == "pass"
                and gate["invalidation_revision"] == current_invalidation
                and gate.get("extensions", {}).get("state_revision")
                == candidate_revision + 1
                and "ART-WP6-VALIDATION-REPORT"
                in gate.get("depends_on", [])
                and bool(set(gate["evidence_ids"]) & integrated_evidence)
            ]
            if not integrated_evidence or not integrated_gates:
                errors.append(
                    "{} integrated Validation gate/evidence lineage is absent".format(
                        label
                    )
                )
        else:
            errors.append(
                "{} state binding is neither direct nor one-revision integrated".format(
                    label
                )
            )
        behavior_provenance = {
            "config_digest": root / ".codex/config.toml",
            "manual_digest": _manual_path_for_digest(
                state["provenance"].get("manual_digest", "unknown"), root
            ),
            "schema_digest": root / "contracts/meva.schema.json",
        }
        for key, path in behavior_provenance.items():
            if (
                not path.is_file()
                or not _digests_equal(
                    state["provenance"].get(key, "unknown"), _sha256(path)
                )
            ):
                errors.append(
                    "{} behavior-affecting {} drifted after Validation".format(
                        label, key
                    )
                )

    runs = report.get("runs")
    if not isinstance(runs, Mapping):
        errors.append("{} lacks exact runs map".format(label))
    else:
        errors.extend(_final_raw_prior_errors(label, runs.get("raw_prior")))
        errors.extend(
            _exact_run_errors(
                label,
                "new",
                runs.get("new"),
                16,
                "python3 -B -m unittest -v tests.conformance.test_final_review_contracts",
            )
        )
        errors.extend(
            _exact_run_errors(
                label,
                "corrected_aggregate",
                runs.get("corrected_aggregate"),
                124,
                "python3 -B tests/conformance/test_final_review_contracts.py --corrected-aggregate",
            )
        )

    supersession = report.get("supersession")
    if (
        not isinstance(supersession, Mapping)
        or supersession.get("count") != 3
        or set(supersession.get("test_ids", []))
        != SUPERSEDED_FINAL_REVIEW_TEST_IDS
        or supersession.get("old_bytes_changed") is not False
    ):
        errors.append("{} supersession record is absent or inexact".format(label))
    history = report.get("harness_correction_history")
    expected_history = [
        "1d38736cc11b5f03b7aa9438b929af2b836824bbab13c07e6bef1fb4e5df547d",
        "70662cc001c4b16af324a54da7762c7ecaf45c7760546bd7ea47e2e21551ec6b",
        EXPECTED_FINAL_REVIEW_HARNESS_DIGEST,
    ]
    if (
        not isinstance(history, list)
        or [item.get("sha256") for item in history if isinstance(item, Mapping)]
        != expected_history
        or history[-1].get("status") != "final_executed"
    ):
        errors.append("{} harness correction history is absent or partial".format(label))
    criteria = report.get("criteria")
    expected_criteria = {"FR-{:03d}".format(index) for index in range(1, 10)}
    if (
        not isinstance(criteria, Mapping)
        or set(criteria) != expected_criteria
        or any(value != "pass" for value in criteria.values())
    ):
        errors.append("{} criteria are absent, partial, or nonpassing".format(label))

    supplemental = report.get("supplemental_checks")
    if not isinstance(supplemental, Mapping):
        errors.append("{} lacks supplemental checks".format(label))
    else:
        template = supplemental.get("template_validation", {})
        package = supplemental.get("check_package", {})
        compile_check = supplemental.get("python_compile", {})
        if (
            template.get("command")
            != "python3 -B tools/meva_check.py validate-state templates/project-state.json"
            or template.get("result") != "pass"
            or template.get("errors") != []
        ):
            errors.append("{} template validation is absent or false".format(label))
        if (
            package.get("command")
            != "python3 -B tools/meva_check.py check-package --root ."
            or package.get("exit_code") != 0
            or package.get("static_package") != "pass"
            or package.get("static_errors") != []
        ):
            errors.append("{} package check is absent or false".format(label))
        if (
            compile_check.get("exit_code") != 0
            or compile_check.get("result") != "pass"
        ):
            errors.append("{} compile check is absent or false".format(label))

    rerun = report.get("final_release_rerun")
    checker_digest = _sha256(root / "tools/meva_check.py")
    if not isinstance(rerun, Mapping):
        errors.append(
            "{} lacks required post-binding final_release_rerun".format(label)
        )
    elif state:
        output = rerun.get("command_output")
        if (
            rerun.get("command")
            != "python3 -B tools/meva_check.py check-release --root ."
            or rerun.get("checker_sha256") != checker_digest
            or rerun.get("state_sha256") != expected_state_digest
            or rerun.get("state_revision") != expected_state_revision
            or rerun.get("invalidation_revision")
            != expected_invalidation_revision
            or rerun.get("exit_code") != 0
            or rerun.get("release_integrity") != "pass"
            or rerun.get("errors") != []
            or rerun.get("conclusion") != "pass"
            or not isinstance(output, str)
            or '"release_integrity": "pass"' not in output
        ):
            errors.append(
                "{} final_release_rerun is stale, partial, or nonpassing".format(
                    label
                )
            )

    conclusion = report.get("conclusion")
    if (
        not isinstance(conclusion, Mapping)
        or conclusion.get("raw_prior")
        != "pass_with_exact_declared_superseded_failures"
        or conclusion.get("new_gate") != "pass"
        or conclusion.get("corrected_aggregate_gate") != "pass"
        or conclusion.get("static_package") != "pass"
        or conclusion.get("release_integrity") != "pass"
        or conclusion.get("overall") != "pass"
    ):
        errors.append("{} final conclusion is absent or nonpassing".format(label))
    return errors, details


_CLOSURE_BEHAVIOR_TASK_KEYS = {
    "id",
    "objective",
    "accountable_owner",
    "owner_instance_id",
    "risk_tier",
    "scope",
    "out_of_scope",
    "inputs",
    "dependencies",
    "writable_scope",
    "required_outputs",
    "acceptance_checks",
    "constraints",
    "data_classification",
    "physical_safety_tier",
    "target_environment",
    "allowed_actions",
    "rollback_or_recovery",
    "approvals_required",
    "extensions",
}
_CLOSURE_LIFECYCLE_TASK_EXTENSION_KEYS = {
    "gate_result_emitted",
    "runtime_activation_status",
}


def _closure_review_bookkeeping_path(path: str) -> bool:
    """Identify state, handoff, and Validation records integrated after a candidate."""

    return (
        path in {".meva/state.json", "NEXT_SESSION_HANDOFF.md"}
        or PurePosixPath(path).name.endswith("validation-report.json")
    )


def _closure_behavior_state_sha256(state: Mapping[str, Any]) -> str:
    """Hash behavior-bearing state while excluding review/lifecycle bookkeeping."""

    task_contracts = []
    for task in state["tasks"]:
        projected = {
            key: task[key]
            for key in sorted(_CLOSURE_BEHAVIOR_TASK_KEYS)
            if key in task
        }
        projected["extensions"] = {
            key: value
            for key, value in task.get("extensions", {}).items()
            if key not in _CLOSURE_LIFECYCLE_TASK_EXTENSION_KEYS
        }
        projected["budget"] = task["accounting"]["budget"]
        task_contracts.append(projected)

    behavior_artifacts = [
        artifact
        for artifact in state["artifacts"]
        if not _closure_review_bookkeeping_path(artifact["location"])
    ]
    behavior_artifact_digests = {
        path: digest
        for path, digest in state["provenance"]["artifact_digests"].items()
        if not _closure_review_bookkeeping_path(path)
    }
    behavior_extensions = {
        key: value
        for key, value in state.get("extensions", {}).items()
        if key not in {"activation", "validation_integration"}
    }
    projection = {
        "contract_version": state["contract_version"],
        "schema_uri": state["schema_uri"],
        "project": state["project"],
        "authority": state["authority"],
        "requirements": state["requirements"],
        "interfaces": state["interfaces"],
        "decisions": state["decisions"],
        "task_contracts": task_contracts,
        "behavior_artifacts": behavior_artifacts,
        "approvals": state["approvals"],
        "accounting_budget": state["accounting"]["budget"],
        "invalidations": state["invalidations"],
        "persistent_resources": state["persistent_resources"],
        "action_ledger": state.get("action_ledger"),
        "behavior_provenance": {
            "policy_digest": state["provenance"]["policy_digest"],
            "config_digest": state["provenance"]["config_digest"],
            "manual_digest": state["provenance"]["manual_digest"],
            "schema_digest": state["provenance"]["schema_digest"],
            "artifact_digests": behavior_artifact_digests,
        },
        "extensions": behavior_extensions,
    }
    encoded = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _closure_release_report_errors(
    root: Path,
    report_path: Path,
    report: Mapping[str, Any],
) -> Tuple[List[str], Dict[str, Any]]:
    label = str(report_path.relative_to(root))
    errors: List[str] = []
    details: Dict[str, Any] = {
        "current_candidate_report": label,
        "release_binding_mode": "closure_direct",
    }
    if (
        report.get("report_version") != "1.0"
        or report.get("contract_version") != "2.0"
        or report.get("task_id") != "CLOSURE-VALIDATION"
        or report.get("phase") != "final-immutable"
    ):
        errors.append("{} identity or phase is not the closure candidate".format(label))

    digests = report.get("digests")
    if not isinstance(digests, Mapping) or set(digests) != CLOSURE_REPORT_BINDINGS:
        errors.append("{} closure digest envelope is absent or inexact".format(label))
    errors.extend(
        _validated_report_digests(
            root,
            report_path,
            [("digests", digests)],
            CLOSURE_REPORT_BINDINGS,
        )
    )
    if (
        isinstance(digests, Mapping)
        and digests.get("tests/conformance/final-review-validation-report.json")
        != EXPECTED_FINAL_REVIEW_REPORT_DIGEST
    ):
        errors.append("{} immutable final report binding is inexact".format(label))

    protocol = report.get("protocol")
    protocol_path = root / "tests/conformance/closure_protocol.v1.json"
    lock_path = root / "tests/conformance/closure_protocol.v1.sha256"
    harness_path = root / "tests/conformance/test_closure_contracts.py"
    if (
        not isinstance(protocol, Mapping)
        or protocol.get("id") != "SAG-CLOSURE-CONFORMANCE-1.0"
        or protocol.get("path") != "tests/conformance/closure_protocol.v1.json"
        or protocol.get("sha256") != EXPECTED_CLOSURE_PROTOCOL_DIGEST
        or protocol.get("lock_sha256") != EXPECTED_CLOSURE_LOCK_DIGEST
        or protocol.get("harness_sha256") != EXPECTED_CLOSURE_HARNESS_DIGEST
        or protocol.get("lock_verified") is not True
        or _sha256(protocol_path) != EXPECTED_CLOSURE_PROTOCOL_DIGEST
        or _sha256(lock_path) != EXPECTED_CLOSURE_LOCK_DIGEST
        or _sha256(harness_path) != EXPECTED_CLOSURE_HARNESS_DIGEST
    ):
        errors.append("{} closure protocol, lock, or harness is inexact".format(label))

    state_binding = report.get("state_binding")
    state_path = root / ".meva/state.json"
    expected_state_digest: Optional[str] = None
    expected_state_revision: Optional[int] = None
    expected_invalidation_revision: Optional[int] = None
    try:
        state, _, state_errors = validate_state(
            state_path, root / "contracts/meva.schema.json"
        )
    except ContractError as exc:
        state = {}
        state_errors = [str(exc)]
    if state_errors:
        errors.append(
            "{} current state is invalid: {}".format(label, "; ".join(state_errors))
        )
    if not isinstance(state_binding, Mapping):
        errors.append("{} lacks direct candidate state binding".format(label))
    elif state:
        current_revision = state["state"]["revision"]
        current_invalidation = state["state"]["current_invalidation_revision"]
        candidate_digest = state_binding.get("sha256")
        candidate_revision = state_binding.get("state_revision")
        candidate_invalidation = state_binding.get("invalidation_revision")
        details["candidate_state_revision"] = candidate_revision
        if (
            set(state_binding)
            != {
                "path",
                "sha256",
                "state_revision",
                "invalidation_revision",
                "validation_result",
                "migration_mode",
            }
            or state_binding.get("path") != ".meva/state.json"
            or not isinstance(candidate_digest, str)
            or not isinstance(candidate_revision, int)
            or isinstance(candidate_revision, bool)
            or not isinstance(candidate_invalidation, int)
            or isinstance(candidate_invalidation, bool)
            or state_binding.get("validation_result") != "pass"
            or state_binding.get("migration_mode") != "rv2"
        ):
            errors.append("{} closure state binding is stale or partial".format(label))
        elif candidate_revision == current_revision:
            details["release_binding_mode"] = "closure_direct"
            expected_state_digest = _sha256(state_path)
            expected_state_revision = current_revision
            expected_invalidation_revision = current_invalidation
            if (
                candidate_digest != expected_state_digest
                or candidate_invalidation != current_invalidation
            ):
                errors.append("{} closure direct state binding is inexact".format(label))
        elif candidate_revision + 1 <= current_revision:
            details["release_binding_mode"] = "closure_integrated"
            expected_state_digest = candidate_digest
            expected_state_revision = candidate_revision
            expected_invalidation_revision = candidate_invalidation
            integration = state.get("extensions", {}).get(
                "validation_integration"
            )
            integration_keys = {
                "candidate_state_sha256",
                "candidate_state_revision",
                "candidate_invalidation_revision",
                "report_path",
                "report_sha256",
                "current_checker_sha256",
                "integrated_state_revision",
                "validated_behavior_sha256",
            }
            checker_digest = _sha256(root / "tools/meva_check.py")
            report_digest = _sha256(report_path)
            behavior_state_digest = _closure_behavior_state_sha256(state)
            expected_integration = {
                "candidate_state_sha256": candidate_digest,
                "candidate_state_revision": candidate_revision,
                "candidate_invalidation_revision": candidate_invalidation,
                "report_path":
                    "tests/conformance/closure-validation-report.json",
                "report_sha256": report_digest,
                "current_checker_sha256": checker_digest,
                "integrated_state_revision": candidate_revision + 1,
                "validated_behavior_sha256": behavior_state_digest,
            }
            if (
                candidate_invalidation != current_invalidation
                or not isinstance(integration, Mapping)
                or set(integration) != integration_keys
                or dict(integration) != expected_integration
            ):
                errors.append(
                    "{} closure integrated validation lineage is absent or inexact".format(
                        label
                    )
                )
            if (
                not isinstance(integration, Mapping)
                or integration.get("validated_behavior_sha256")
                != behavior_state_digest
            ):
                errors.append(
                    "{} closure behavior state drifted after Validation".format(
                        label
                    )
                )

            artifacts = {
                item["id"]: item for item in state["artifacts"]
            }
            report_artifact = artifacts.get("ART-CLOSURE-VALIDATION-REPORT")
            if (
                report_artifact is None
                or report_artifact["location"]
                != "tests/conformance/closure-validation-report.json"
                or report_artifact["digest"] != report_digest
                or report_artifact["status"] != "current"
            ):
                errors.append(
                    "{} closure integrated report artifact is absent or stale".format(
                        label
                    )
                )
            evidence = {
                item["id"]: item for item in state["evidence"]
            }
            integrated_evidence = {
                evidence_id
                for evidence_id, item in evidence.items()
                if item["status"] == "current"
                and item["result"] == "pass"
                and item["invalidation_revision"] == current_invalidation
                and item.get("extensions", {}).get("state_revision")
                == candidate_revision + 1
                and "ART-CLOSURE-VALIDATION-REPORT"
                in item.get("depends_on", [])
            }
            integrated_gates = [
                gate
                for gate in state["gates"]
                if gate["gate"] == "validation"
                and gate["result"] == "pass"
                and gate["invalidation_revision"] == current_invalidation
                and gate.get("extensions", {}).get("state_revision")
                == candidate_revision + 1
                and "ART-CLOSURE-VALIDATION-REPORT"
                in gate.get("depends_on", [])
                and bool(set(gate["evidence_ids"]) & integrated_evidence)
            ]
            if not integrated_evidence or not integrated_gates:
                errors.append(
                    "{} closure integrated Validation gate/evidence lineage is absent".format(
                        label
                    )
                )
            behavior_provenance = {
                "config_digest": root / ".codex/config.toml",
                "manual_digest": _manual_path_for_digest(
                    state["provenance"].get("manual_digest", "unknown"), root
                ),
                "schema_digest": root / "contracts/meva.schema.json",
            }
            for key, path in behavior_provenance.items():
                if (
                    not path.is_file()
                    or not _digests_equal(
                        state["provenance"].get(key, "unknown"), _sha256(path)
                    )
                ):
                    errors.append(
                        "{} closure behavior-affecting {} drifted after Validation".format(
                            label, key
                        )
                    )
        else:
            errors.append(
                "{} closure state binding is neither direct nor one-revision integrated".format(
                    label
                )
            )

    runs = report.get("runs")
    if not isinstance(runs, Mapping) or set(runs) != {
        "raw_prior",
        "new",
        "corrected_preclosure",
        "corrected_aggregate",
    }:
        errors.append("{} closure runs map is absent or inexact".format(label))
    else:
        errors.extend(_final_raw_prior_errors(label, runs.get("raw_prior")))
        errors.extend(
            _exact_run_errors(
                label,
                "new",
                runs.get("new"),
                8,
                "python3 -B -m unittest -v tests.conformance.test_closure_contracts",
            )
        )
        errors.extend(
            _exact_run_errors(
                label,
                "corrected_preclosure",
                runs.get("corrected_preclosure"),
                124,
                "python3 -B tests/conformance/test_final_review_contracts.py --corrected-aggregate",
            )
        )
        errors.extend(
            _exact_run_errors(
                label,
                "corrected_aggregate",
                runs.get("corrected_aggregate"),
                132,
                "python3 -B tests/conformance/test_closure_contracts.py --corrected-aggregate",
            )
        )

    criteria = report.get("criteria")
    if (
        not isinstance(criteria, Mapping)
        or set(criteria) != {"CL-001", "CL-002", "CL-003", "CL-004"}
        or any(value != "pass" for value in criteria.values())
    ):
        errors.append("{} closure criteria are absent or nonpassing".format(label))

    rerun = report.get("final_release_rerun")
    if not isinstance(rerun, Mapping):
        errors.append("{} lacks content-stable final_release_rerun".format(label))
    elif state:
        output = rerun.get("command_output")
        if (
            set(rerun)
            != {
                "command",
                "checker_sha256",
                "schema_sha256",
                "state_sha256",
                "state_revision",
                "invalidation_revision",
                "exit_code",
                "release_integrity",
                "errors",
                "command_output",
                "report_content_stable",
                "conclusion",
            }
            or rerun.get("command")
            != "python3 -B tools/meva_check.py check-release --root ."
            or rerun.get("checker_sha256")
            != _sha256(root / "tools/meva_check.py")
            or rerun.get("schema_sha256")
            != _sha256(root / "contracts/meva.schema.json")
            or rerun.get("state_sha256") != expected_state_digest
            or rerun.get("state_revision") != expected_state_revision
            or rerun.get("invalidation_revision")
            != expected_invalidation_revision
            or rerun.get("exit_code") != 0
            or rerun.get("release_integrity") != "pass"
            or rerun.get("errors") != []
            or rerun.get("report_content_stable") is not True
            or rerun.get("conclusion") != "pass"
            or not isinstance(output, str)
            or '"release_integrity": "pass"' not in output
        ):
            errors.append(
                "{} closure final_release_rerun is stale, partial, or false".format(
                    label
                )
            )

    conclusion = report.get("conclusion")
    if (
        not isinstance(conclusion, Mapping)
        or set(conclusion)
        != {
            "raw_prior",
            "new_gate",
            "corrected_preclosure_gate",
            "corrected_aggregate_gate",
            "release_integrity",
            "runtime_activation",
            "overall",
        }
        or conclusion.get("raw_prior")
        != "pass_with_exact_declared_superseded_failures"
        or conclusion.get("new_gate") != "pass"
        or conclusion.get("corrected_preclosure_gate") != "pass"
        or conclusion.get("corrected_aggregate_gate") != "pass"
        or conclusion.get("release_integrity") != "pass"
        or conclusion.get("runtime_activation") != "unverified"
        or conclusion.get("overall") != "pass"
    ):
        errors.append("{} closure conclusion is absent or nonpassing".format(label))
    return errors, details


def command_check_release(args: argparse.Namespace) -> int:
    """Validate only the explicit superseding current-candidate report."""

    root = Path(args.root).resolve()
    closure_path = root / "tests/conformance/closure-validation-report.json"
    if closure_path.is_file() and (root / ".meva/state.json").is_file():
        errors, details = _package_checks(root)
        try:
            closure_report = _load_json(closure_path)
        except ContractError as exc:
            errors.append(str(exc))
        else:
            if not isinstance(closure_report, Mapping):
                errors.append("{} root must be an object".format(closure_path))
            else:
                report_errors, report_details = _closure_release_report_errors(
                    root, closure_path, closure_report
                )
                errors.extend(report_errors)
                details.update(report_details)
        result = "fail" if errors else "pass"
        _json_output(
            {
                "contract_version": "2.0",
                "release_integrity": result,
                "errors": errors,
                "details": details,
            }
        )
        return 1 if errors else 0

    if not (root / ".meva/state.json").is_file():
        return _historical_check_release(args)
    report_path = root / "tests/conformance/final-review-validation-report.json"
    report: Any = None
    if report_path.is_file():
        try:
            report = _load_json(report_path)
        except ContractError as exc:
            errors, details = _package_checks(root)
            errors.append(str(exc))
            result = "fail"
            _json_output(
                {
                    "contract_version": "2.0",
                    "release_integrity": result,
                    "errors": errors,
                    "details": details,
                }
            )
            return 1
        if not isinstance(report, Mapping):
            errors, details = _package_checks(root)
            errors.append("{} root must be an object".format(report_path))
            _json_output(
                {
                    "contract_version": "2.0",
                    "release_integrity": "fail",
                    "errors": errors,
                    "details": details,
                }
            )
            return 1
    if report is None or "final_release_rerun" not in report:
        return _historical_check_release(args)

    errors, details = _package_checks(root)
    report_errors, report_details = _final_release_report_errors(
        root, report_path, report
    )
    errors.extend(report_errors)
    details.update(report_details)
    result = "fail" if errors else "pass"
    _json_output(
        {
            "contract_version": "2.0",
            "release_integrity": result,
            "errors": errors,
            "details": details,
        }
    )
    return 1 if errors else 0


def command_validate_state(args: argparse.Namespace) -> int:
    try:
        state, _, errors = validate_state(Path(args.state), Path(args.schema))
        migration_mode = "rv2" if "action_ledger" in state else "legacy_read_only"
    except ContractError as exc:
        errors = [str(exc)]
        migration_mode = "unknown"
    result = "fail" if errors else "pass"
    _json_output(
        {
            "contract_version": "2.0",
            "result": result,
            "errors": errors,
            "migration_mode": migration_mode,
        }
    )
    return 1 if errors else 0


def command_validate_handoff(args: argparse.Namespace) -> int:
    try:
        handoff = _load_json(Path(args.handoff))
        schema = _load_json(Path(args.schema))
        if not isinstance(schema, Mapping):
            raise ContractError("schema root must be an object")
        errors, warnings, size = validate_handoff(handoff, schema)
    except ContractError as exc:
        errors = [str(exc)]
        warnings = []
        size = None
    result = "fail" if errors else "pass"
    _json_output(
        {
            "contract_version": "2.0",
            "result": result,
            "errors": errors,
            "warnings": warnings,
            "canonical_bytes": size,
            "authorizes_consequential_action": False,
        }
    )
    return 1 if errors else 0


def command_verify_approval(args: argparse.Namespace) -> int:
    try:
        state, _, state_errors = validate_state(Path(args.state), Path(args.schema))
        if state_errors:
            raise ContractError("state validation failed: {}".format("; ".join(state_errors)))
        approval = next(
            (item for item in state["approvals"] if item["approval_id"] == args.approval_id),
            None,
        )
        if approval is None:
            raise ContractError("unknown approval_id {}".format(args.approval_id))
        limits = json.loads(args.limits_json)
        if not isinstance(limits, dict):
            raise ContractError("--limits-json must decode to an object")
        errors = _approval_check(
            approval,
            args.action,
            args.scope,
            args.environment,
            limits,
            _now(args.now),
        )
    except (ContractError, json.JSONDecodeError) as exc:
        errors = [str(exc)]
    result = "fail" if errors else "pass"
    _json_output({"contract_version": "2.0", "result": result, "errors": errors})
    return 1 if errors else 0


def command_preflight(args: argparse.Namespace) -> int:
    try:
        state, _, state_errors = validate_state(Path(args.state), Path(args.schema))
        if state_errors:
            raise ContractError("state validation failed: {}".format("; ".join(state_errors)))
        diagnostic_now = (
            _now(args.now)
            if args.now is not None
            else _parse_utc(state["state"]["updated_at"])
        )
        if diagnostic_now is None:
            raise ContractError("diagnostic state time is unknown or invalid")
        increments = {
            "cost": args.cost,
            "compute_units": args.compute_units,
            "wall_time_seconds": args.wall_time_seconds,
            "external_calls": args.external_calls,
            "worker_fanout": args.worker_fanout,
        }
        result, errors, notices = _preflight(
            state,
            args.task_id,
            args.role,
            args.action,
            args.action_kind,
            args.path,
            args.environment,
            increments,
            args.delegation_depth,
            args.retry_count,
            args.alternative_attempts,
            args.action_chain_steps,
            diagnostic_now,
            Path(args.root),
            Path(args.state),
            args.target_expected_digest,
            args.target_expected_absent,
        )
    except ContractError as exc:
        result, errors, notices = "fail", [str(exc)], []
    _json_output(
        {
            "contract_version": "2.0",
            "result": result,
            "errors": errors,
            "notices": notices,
            "local_execution_eligible": (
                result == "pass" and CORE_LOCAL_FALLBACK_NOTICE in notices
            ),
            "runtime_activation": "unverified",
            "execution_mode": (
                "denied"
                if result != "pass"
                else (
                    "core_local"
                    if CORE_LOCAL_FALLBACK_NOTICE in notices
                    else "attestation_present_preflight"
                )
            ),
            "authorizes_consequential_action": False,
            "authorization_boundary": (
                "current_human_plus_host_cas"
                if result == "pass" and CORE_LOCAL_FALLBACK_NOTICE in notices
                else "reserve-action"
            ),
            "local_action_binding": (
                {
                    "state_revision": state["state"]["revision"],
                    "state_digest": _sha256(Path(args.state)),
                    "task_id": args.task_id,
                    "role": args.role,
                    "root": str(Path(args.root).resolve()),
                    "path": args.path,
                    "target_expected_digest": args.target_expected_digest,
                }
                if result == "pass" and CORE_LOCAL_FALLBACK_NOTICE in notices
                else {}
            ),
        }
    )
    return 0 if result == "pass" else (2 if result == "unverified" else 1)


def command_evaluate_review(args: argparse.Namespace) -> int:
    try:
        state, _, state_errors = validate_state(Path(args.state), Path(args.schema))
        if state_errors:
            raise ContractError("state validation failed: {}".format("; ".join(state_errors)))
        recommendation, errors, blockers, gate_eligible = _evaluate_review(
            state, _now(args.now), Path(args.root).resolve()
        )
    except ContractError as exc:
        recommendation, errors, blockers, gate_eligible = (
            "fail",
            [str(exc)],
            [],
            False,
        )
    _json_output(
        {
            "contract_version": "2.0",
            "recommendation": recommendation,
            "errors": errors,
            "blocking_findings": blockers,
            "gate_eligible": gate_eligible,
            "authorizes_consequential_action": False,
        }
    )
    return 1 if recommendation == "fail" or errors else 0


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _production_now(supplied: Optional[str]) -> datetime:
    if supplied is not None:
        raise ContractError(
            "--now is diagnostic-only and is not accepted by atomic action commands"
        )
    return datetime.now(timezone.utc)


def _trusted_atomic_now(
    state: Mapping[str, Any], production_now: datetime
) -> datetime:
    """Use a monotonic trusted floor; never allow state or caller time rollback."""

    candidates = [production_now, _parse_utc(state["state"]["updated_at"])]
    candidates.extend(
        _parse_utc(item["observed_at"])
        for item in state["permission_attestations"]
    )
    candidates.extend(
        _parse_utc(item["verification"]["verified_at"])
        for item in state["approvals"]
        if item["verification"]["source_kind"]
        in {"runtime_owned", "trusted_external"}
        and item["verification"]["status"] == "verified"
    )
    return max(item for item in candidates if item is not None)


def _target_digest_check(root: Path, target: Mapping[str, Any]) -> None:
    expected = target.get("expected_digest")
    path = target.get("path")
    if expected is None:
        return
    if path is None:
        raise ContractError("target expected digest requires a canonical path")
    candidate = (root / path).resolve(strict=False)
    if not candidate.is_file():
        raise CASConflict("target expected digest references a missing file")
    if not _digests_equal(str(expected), _sha256(candidate)):
        raise CASConflict("target expected digest compare failed")


def command_reserve_action(args: argparse.Namespace) -> int:
    try:
        root = Path(args.root).resolve()
        state_path = _trusted_state_path(
            args.state, root, args.trusted_state_root
        )
        if re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]*", args.idempotency_key
        ) is None:
            raise ContractError("idempotency key is not a canonical identifier")
        now = _production_now(args.now)
        expires = _parse_utc(args.expires_at)
        if expires is None:
            raise ContractError("reservation expiry must be an RFC3339 UTC timestamp")
        amounts = _action_amounts(args)
        with _locked_state(state_path) as (raw, state):
            ledger = state.get("action_ledger")
            if ledger is None:
                raise ContractError(
                    "legacy state has no action_ledger; consequential authorization is unavailable"
                )
            schema = _load_json(Path(args.schema))
            state_errors = validate_json_schema(state, schema)
            state_errors.extend(_semantic_state_errors(state))
            if state_errors:
                raise ContractError(
                    "state validation failed: {}".format("; ".join(state_errors))
                )
            now = _trusted_atomic_now(state, now)
            task = _find_task(state, args.task_id)
            trusted_kind, trusted_effect, capability_id = _trusted_action_metadata(
                task, args.action
            )
            if args.action_kind != trusted_kind:
                raise ContractError("caller action kind conflicts with trusted metadata")
            if args.effect != trusted_effect:
                raise ContractError("caller effect conflicts with trusted metadata")
            selected_attestation = _selected_permission_attestation(
                state, args.role, args.task_id, now
            )
            target = _validate_exact_target(
                state,
                task,
                root,
                selected_attestation["effective_permissions"],
                trusted_effect,
                args.target_kind,
                args.target_id,
                args.path,
                args.target_expected_revision,
                args.target_expected_digest,
            )
            _target_digest_check(root, target)
            approval_errors, authorization_approval_ids = (
                _required_action_approval_errors(
                    state,
                    task,
                    args.action,
                    trusted_effect,
                    target,
                    args.environment,
                    amounts,
                    now,
                )
            )
            if approval_errors:
                raise ContractError(
                    "action approval failed: {}".format(
                        "; ".join(approval_errors)
                    )
                )
            existing = [
                item
                for item in ledger["reservations"]
                if item["idempotency_key"] == args.idempotency_key
            ]
            if len(existing) > 1:
                raise CASConflict("idempotency key is duplicated in action ledger")
            permission_attestation_id = (
                existing[0]["permission_attestation_id"] if existing else ""
            )
            package_errors, package_details = _package_checks(root)
            if package_errors:
                raise ContractError(
                    "static package is not trusted: {}".format(
                        "; ".join(package_errors)
                    )
                )
            activation, activation_errors = _runtime_activation(
                state,
                args.role,
                args.task_id,
                now,
                root,
                package_details.get(
                    "configured_concurrency", MAX_CONFIGURED_CONCURRENCY
                ),
            )
            if activation != "pass":
                code = 2 if activation == "unverified" else 1
                payload = _atomic_error_payload(
                    "runtime activation {}: {}".format(
                        activation, "; ".join(activation_errors)
                    ),
                    code,
                )[1]
                _json_output(payload)
                return code
            authority_expiry = _parse_utc(state["authority"]["expires_at"])
            attestation_expiry = _parse_utc(selected_attestation["expires_at"])
            if (
                authority_expiry is None
                or attestation_expiry is None
                or expires > min(authority_expiry, attestation_expiry)
            ):
                raise ContractError(
                    "reservation expiry exceeds current authority or attestation"
                )
            if now >= expires:
                raise ContractError("reservation is expired")

            def request_for(attestation_id: str) -> Dict[str, Any]:
                return {
                    "idempotency_key": args.idempotency_key,
                    "task_id": args.task_id,
                    "role": args.role,
                    "action": args.action,
                    "action_kind": trusted_kind,
                    "effect": trusted_effect,
                    "capability_id": capability_id,
                    "permission_attestation_id": attestation_id,
                    "target": target,
                    "environment": args.environment,
                    "reserved": amounts,
                    "expires_at": args.expires_at,
                    "authorization_approval_ids": authorization_approval_ids,
                }

            if existing:
                request_digest = _canonical_request_digest(
                    request_for(permission_attestation_id)
                )
                reservation = existing[0]
                if reservation["request_digest"] != request_digest:
                    raise CASConflict("divergent idempotency-key reuse")
                result, replay_errors, _ = _preflight(
                    state,
                    args.task_id,
                    args.role,
                    args.action,
                    args.action_kind,
                    args.path,
                    args.environment,
                    amounts,
                    None,
                    None,
                    None,
                    1,
                    now,
                )
                if result != "pass":
                    raise ContractError(
                        "replay no longer passes current preflight: {}".format(
                            "; ".join(replay_errors)
                        )
                    )
                _json_output(
                    {
                        "contract_version": "2.0",
                        "result": "pass",
                        "errors": [],
                        "replayed": True,
                        "authorizes_consequential_action": False,
                        "authorization_boundary": "claim-action",
                        "reservation_token": reservation["id"],
                        "permission_attestation_id":
                            reservation["permission_attestation_id"],
                        "request_digest": request_digest,
                        "state_revision": state["state"]["revision"],
                        "ledger_revision": ledger["revision"],
                        "state_digest": hashlib.sha256(raw).hexdigest(),
                    }
                )
                return 0

            _cas_inputs(
                raw,
                state,
                args.expected_state_revision,
                args.expected_ledger_revision,
                args.expected_state_digest,
            )
            if now >= expires:
                raise ContractError(
                    "reservation expiry must be in the future for a new reservation"
                )
            if any(
                item["status"] == "recovery_required"
                for item in ledger["reservations"]
            ):
                raise ContractError(
                    "recovery-required action blocks new consequential reservations"
                )
            permission_attestation_id = str(selected_attestation["id"])
            request_digest = _canonical_request_digest(
                request_for(permission_attestation_id)
            )
            result, errors, _ = _preflight(
                state,
                args.task_id,
                args.role,
                args.action,
                args.action_kind,
                args.path,
                args.environment,
                amounts,
                None,
                None,
                None,
                1,
                now,
            )
            if result != "pass":
                code = 2 if result == "unverified" else 1
                payload = _atomic_error_payload(
                    "preflight {}: {}".format(result, "; ".join(errors)), code
                )[1]
                _json_output(payload)
                return code
            capacity_errors = _reservation_capacity_errors(
                state, task, ledger, amounts, trusted_kind
            )
            if capacity_errors:
                raise ContractError("; ".join(capacity_errors))
            owner_instance, owner_error = _effective_owner_instance(
                state, task, args.role, now
            )
            if owner_error or owner_instance is None:
                code, payload = _atomic_error_payload(
                    owner_error or "owner instance identity is unavailable", 2
                )
                _json_output(payload)
                return code
            reservation_id = "RES-" + uuid.uuid4().hex
            zeros = {key: 0 for key in ACCOUNTING_FIELDS}
            reservation = {
                "id": reservation_id,
                "task_id": args.task_id,
                "owner_instance_id": owner_instance,
                "idempotency_key": args.idempotency_key,
                "request_digest": request_digest,
                "permission_attestation_id": permission_attestation_id,
                "capability_id": capability_id,
                "state_revision": args.expected_state_revision,
                "ledger_revision": args.expected_ledger_revision,
                "state_digest": hashlib.sha256(raw).hexdigest(),
                "action": args.action,
                "action_kind": trusted_kind,
                "effect": trusted_effect,
                "target": target,
                "environment": args.environment,
                "reserved": amounts,
                "actual": zeros,
                "status": "reserved",
                "created_at": _format_utc(now),
                "expires_at": args.expires_at,
                "outcome_digest": "unknown",
                "reconciliation_id": "",
                "extensions": {
                    "execution_status": "not_started",
                    "claim_status": "unclaimed",
                    "ticket_digest": selected_attestation["ticket_digest"],
                    "authorization_approval_ids": authorization_approval_ids,
                },
            }
            ledger["reservations"].append(reservation)
            ledger["revision"] += 1
            state["state"]["revision"] += 1
            state["state"]["updated_at"] = _format_utc(now)
            post_errors = validate_json_schema(state, schema)
            post_errors.extend(_semantic_state_errors(state))
            if post_errors:
                raise ContractError(
                    "reserved state would violate contract: {}".format(
                        "; ".join(post_errors)
                    )
                )
            new_digest = _durable_replace_json(state_path, state)
        _json_output(
            {
                "contract_version": "2.0",
                "result": "pass",
                "errors": [],
                "authorizes_consequential_action": False,
                "authorization_boundary": "claim-action",
                "reservation_token": reservation_id,
                "permission_attestation_id": permission_attestation_id,
                "request_digest": request_digest,
                "replayed": False,
                "state_revision": args.expected_state_revision + 1,
                "ledger_revision": args.expected_ledger_revision + 1,
                "state_digest": new_digest,
            }
        )
        return 0
    except CASConflict as exc:
        code, payload = _atomic_error_payload(str(exc), 3)
    except ContractError as exc:
        code = 2 if "legacy state has no action_ledger" in str(exc) else 1
        code, payload = _atomic_error_payload(str(exc), code)
    except (OSError, ValueError) as exc:
        code, payload = _atomic_error_payload(
            "atomic reservation failed: {}".format(exc), 1
        )
    _json_output(payload)
    return code


def command_claim_action(args: argparse.Namespace) -> int:
    """Atomically consume one reservation for one adapter execution attempt."""

    try:
        root = Path(args.root).resolve()
        state_path = _trusted_state_path(
            args.state, root, args.trusted_state_root
        )
        if (
            args.claim_id is not None
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]*", args.claim_id
            ) is None
        ):
            raise ContractError("claim id is not a canonical identifier")
        if (
            args.expected_request_digest is not None
            and _canonical_digest(args.expected_request_digest) is None
        ):
            raise ContractError("expected request digest is not canonical")
        now = _production_now(args.now)
        with _locked_state(state_path) as (raw, state):
            ledger = state.get("action_ledger")
            if ledger is None:
                raise ContractError(
                    "legacy state has no action_ledger; consequential authorization is unavailable"
                )
            schema = _load_json(Path(args.schema))
            state_errors = validate_json_schema(state, schema)
            state_errors.extend(_semantic_state_errors(state))
            if state_errors:
                raise ContractError(
                    "state validation failed: {}".format("; ".join(state_errors))
                )
            now = _trusted_atomic_now(state, now)
            matches = [
                item
                for item in ledger["reservations"]
                if item["id"] == args.reservation_token
            ]
            if len(matches) != 1:
                raise ContractError("unknown or ambiguous reservation token")
            reservation = matches[0]
            if (
                args.expected_request_digest is not None
                and not _digests_equal(
                    reservation["request_digest"], args.expected_request_digest
                )
            ):
                raise CASConflict("reservation request digest compare failed")
            claim_id = args.claim_id or (
                "CLAIM-"
                + hashlib.sha256(
                    (
                        reservation["id"]
                        + ":"
                        + reservation["request_digest"]
                    ).encode("utf-8")
                ).hexdigest()
            )
            stored_claim = reservation["extensions"].get("claim_id")
            if reservation["status"] == "claimed":
                if stored_claim != claim_id:
                    raise CASConflict("reservation is already claimed")
                _json_output(
                    {
                        "contract_version": "2.0",
                        "result": "pass",
                        "errors": [],
                        "replayed": True,
                        "authorizes_consequential_action": False,
                        "reservation_token": reservation["id"],
                        "claim_id": claim_id,
                        "state_revision": state["state"]["revision"],
                        "ledger_revision": ledger["revision"],
                        "state_digest": hashlib.sha256(raw).hexdigest(),
                    }
                )
                return 0
            if reservation["status"] != "reserved":
                raise CASConflict("reservation is not claimable")
            _cas_inputs(
                raw,
                state,
                args.expected_state_revision,
                args.expected_ledger_revision,
                args.expected_state_digest,
            )
            expires = _parse_utc(reservation["expires_at"])
            if expires is None or now >= expires:
                raise ContractError("reservation is expired")
            if reservation["task_id"] != args.task_id:
                raise ContractError("reservation does not bind the exact task")
            task = _find_task(state, args.task_id)
            package_errors, package_details = _package_checks(root)
            if package_errors:
                raise ContractError(
                    "static package is not trusted: {}".format(
                        "; ".join(package_errors)
                    )
                )
            activation, activation_errors = _runtime_activation(
                state,
                args.role,
                args.task_id,
                now,
                root,
                package_details.get(
                    "configured_concurrency", MAX_CONFIGURED_CONCURRENCY
                ),
            )
            if activation != "pass":
                code = 2 if activation == "unverified" else 1
                payload = _atomic_error_payload(
                    "runtime activation {}: {}".format(
                        activation, "; ".join(activation_errors)
                    ),
                    code,
                )[1]
                _json_output(payload)
                return code
            selected_attestation = _selected_permission_attestation(
                state, args.role, args.task_id, now
            )
            authority_expiry = _parse_utc(state["authority"]["expires_at"])
            attestation_expiry = _parse_utc(selected_attestation["expires_at"])
            if (
                authority_expiry is None
                or attestation_expiry is None
                or expires > min(authority_expiry, attestation_expiry)
            ):
                raise ContractError(
                    "reservation exceeds current authority or attestation expiry"
                )
            trusted_kind, trusted_effect, capability_id = _trusted_action_metadata(
                task, reservation["action"]
            )
            if (
                trusted_kind != reservation["action_kind"]
                or trusted_effect != reservation["effect"]
                or capability_id != reservation["capability_id"]
            ):
                raise ContractError(
                    "reservation no longer binds current trusted capability"
                )
            target = reservation["target"]
            verified_target = _validate_exact_target(
                state,
                task,
                root,
                selected_attestation["effective_permissions"],
                trusted_effect,
                target["kind"],
                target["id"],
                target.get("path"),
                target.get("expected_revision"),
                target.get("expected_digest"),
            )
            if verified_target != target:
                raise CASConflict("reservation target binding changed")
            _target_digest_check(root, target)
            approval_errors, authorization_approval_ids = (
                _required_action_approval_errors(
                    state,
                    task,
                    reservation["action"],
                    trusted_effect,
                    target,
                    reservation["environment"],
                    reservation["reserved"],
                    now,
                )
            )
            if approval_errors:
                raise ContractError(
                    "claim approval failed: {}".format(
                        "; ".join(approval_errors)
                    )
                )
            if (
                reservation["extensions"].get(
                    "authorization_approval_ids", []
                )
                != authorization_approval_ids
            ):
                raise ContractError(
                    "claim approval set differs from reserved authorization"
                )
            result, errors, _ = _preflight(
                state,
                args.task_id,
                args.role,
                reservation["action"],
                reservation["action_kind"],
                target.get("path"),
                reservation["environment"],
                reservation["reserved"],
                None,
                None,
                None,
                None,
                now,
            )
            if result != "pass":
                raise ContractError(
                    "claim no longer passes current preflight: {}".format(
                        "; ".join(errors)
                    )
                )
            reservation["status"] = "claimed"
            reservation["extensions"]["claim_status"] = "claimed"
            reservation["extensions"]["claim_id"] = claim_id
            reservation["extensions"]["claimed_at"] = _format_utc(now)
            reservation["extensions"][
                "claim_permission_attestation_id"
            ] = selected_attestation["id"]
            ledger["revision"] += 1
            state["state"]["revision"] += 1
            state["state"]["updated_at"] = _format_utc(now)
            post_errors = validate_json_schema(state, schema)
            post_errors.extend(_semantic_state_errors(state))
            if post_errors:
                raise ContractError(
                    "claimed state would violate contract: {}".format(
                        "; ".join(post_errors)
                    )
                )
            new_digest = _durable_replace_json(state_path, state)
        _json_output(
            {
                "contract_version": "2.0",
                "result": "pass",
                "errors": [],
                "replayed": False,
                "authorizes_consequential_action": True,
                "reservation_token": args.reservation_token,
                "claim_id": claim_id,
                "state_revision": state["state"]["revision"],
                "ledger_revision": ledger["revision"],
                "state_digest": new_digest,
            }
        )
        return 0
    except CASConflict as exc:
        code, payload = _atomic_error_payload(str(exc), 3)
    except ContractError as exc:
        code = 2 if "legacy state has no action_ledger" in str(exc) else 1
        code, payload = _atomic_error_payload(str(exc), code)
    except (OSError, ValueError) as exc:
        code, payload = _atomic_error_payload(
            "atomic claim failed: {}".format(exc), 1
        )
    _json_output(payload)
    return code


def command_reconcile_action(args: argparse.Namespace) -> int:
    try:
        root = Path(args.root).resolve()
        state_path = _trusted_state_path(
            args.state, root, args.trusted_state_root
        )
        if re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]*", args.reconciliation_id
        ) is None:
            raise ContractError("reconciliation id is not a canonical identifier")
        now = _production_now(args.now)
        supplied_actual = _action_amounts(args, "actual_")
        canonical_outcome = _canonical_digest(args.outcome_digest)
        outcome = canonical_outcome or "unknown"
        if args.execution_status != "unknown" and canonical_outcome is None:
            raise ContractError("known execution requires a SHA-256 outcome digest")
        request = {
            "reconciliation_id": args.reconciliation_id,
            "task_id": args.task_id,
            "role": args.role,
            "execution_status": args.execution_status,
            "actual": supplied_actual,
            "outcome_digest": outcome,
        }
        with _locked_state(state_path) as (raw, state):
            ledger = state.get("action_ledger")
            if ledger is None:
                raise ContractError(
                    "legacy state has no action_ledger; consequential authorization is unavailable"
                )
            matches = [
                item
                for item in ledger["reservations"]
                if item["id"] == args.reservation_token
            ]
            if len(matches) != 1:
                raise ContractError("unknown or ambiguous reservation token")
            reservation = matches[0]
            if (
                args.expected_request_digest is not None
                and not _digests_equal(
                    reservation["request_digest"], args.expected_request_digest
                )
            ):
                raise CASConflict("reservation request digest compare failed")
            schema = _load_json(Path(args.schema))
            state_errors = validate_json_schema(state, schema)
            state_errors.extend(_semantic_state_errors(state))
            if state_errors:
                raise ContractError(
                    "state validation failed: {}".format("; ".join(state_errors))
                )
            now = _trusted_atomic_now(state, now)
            stored_request = reservation["extensions"].get("reconcile_request")
            if reservation["status"] in {"reconciled", "recovery_required"}:
                if stored_request == request:
                    _json_output(
                        {
                            "contract_version": "2.0",
                            "result": "pass",
                            "errors": [],
                            "replayed": True,
                            "authorizes_consequential_action": False,
                            "reservation_status": reservation["status"],
                            "reconciliation_id": args.reconciliation_id,
                            "state_revision": state["state"]["revision"],
                            "ledger_revision": ledger["revision"],
                            "state_digest": hashlib.sha256(raw).hexdigest(),
                        }
                    )
                    return 0
                raise CASConflict("divergent reconciliation replay")
            if reservation["status"] == "reserved" and args.execution_status != "unknown":
                raise ContractError(
                    "an unclaimed reservation cannot record known execution"
                )
            if reservation["status"] not in {"reserved", "claimed"}:
                raise CASConflict("reservation is not reconcilable")
            if reservation["task_id"] != args.task_id:
                raise ContractError("reservation does not bind the exact task")
            task = _find_task(state, args.task_id)
            package_errors, package_details = _package_checks(root)
            if package_errors:
                raise ContractError(
                    "static package is not trusted: {}".format(
                        "; ".join(package_errors)
                    )
                )
            activation, activation_errors = _runtime_activation(
                state,
                args.role,
                args.task_id,
                now,
                root,
                package_details.get(
                    "configured_concurrency", MAX_CONFIGURED_CONCURRENCY
                ),
            )
            if activation != "pass":
                ticket_only = (
                    activation == "fail"
                    and activation_errors
                    and all("ticket_digest" in item for item in activation_errors)
                )
                selected_for_snapshot = _selected_permission_attestation(
                    state, args.role, args.task_id, now
                )
                snapshot_digest = reservation["extensions"].get(
                    "ticket_digest"
                )
                if not (
                    ticket_only
                    and _canonical_digest(str(snapshot_digest)) is not None
                    and _digests_equal(
                        str(snapshot_digest),
                        selected_for_snapshot["ticket_digest"],
                    )
                ):
                    code = 2 if activation == "unverified" else 1
                    payload = _atomic_error_payload(
                        "runtime activation {}: {}".format(
                            activation, "; ".join(activation_errors)
                        ),
                        code,
                    )[1]
                    _json_output(payload)
                    return code
            selected_attestation = _selected_permission_attestation(
                state, args.role, args.task_id, now
            )
            trusted_kind, trusted_effect, capability_id = _trusted_action_metadata(
                task, reservation["action"]
            )
            if (
                trusted_kind != reservation["action_kind"]
                or trusted_effect != reservation["effect"]
                or capability_id != reservation["capability_id"]
            ):
                raise ContractError(
                    "reservation capability binding is no longer exact"
                )
            owner_instance, owner_error = _effective_owner_instance(
                state, task, args.role, now
            )
            if owner_error or owner_instance != reservation["owner_instance_id"]:
                raise ContractError(
                    owner_error or "reservation owner instance no longer matches"
                )
            actual = (
                dict(reservation["reserved"])
                if args.execution_status == "unknown"
                else supplied_actual
            )
            overrun = any(
                actual[key] > reservation["reserved"][key]
                for key in ACCOUNTING_FIELDS
            )
            recovery_required = args.execution_status == "unknown" or overrun
            for accounting in (task["accounting"], state["accounting"]):
                for key in ACCOUNTING_FIELDS:
                    accounting["usage"][key] += actual[key]
                accounting["updated_at"] = _format_utc(now)
                ratios = []
                for key, limit_key in ACCOUNTING_FIELDS.items():
                    limit = accounting["budget"][limit_key]
                    if limit is not None and key != "action_chain_steps":
                        ratios.append(
                            float("inf")
                            if limit == 0 and accounting["usage"][key] > 0
                            else (
                                0.0
                                if limit == 0
                                else float(accounting["usage"][key]) / float(limit)
                            )
                        )
                if ratios and max(ratios) >= 0.7:
                    accounting["notified_at_70_percent"] = True
                    accounting["reestimated_at_70_percent"] = True
            reservation["actual"] = actual
            reservation["status"] = (
                "recovery_required" if recovery_required else "reconciled"
            )
            reservation["outcome_digest"] = outcome
            reservation["reconciliation_id"] = args.reconciliation_id
            reservation["extensions"]["execution_status"] = args.execution_status
            reservation["extensions"]["reconcile_request"] = request
            reservation["extensions"]["overrun"] = overrun
            reservation["extensions"]["reconciled_at"] = _format_utc(now)
            reservation["extensions"][
                "reconciliation_permission_attestation_id"
            ] = selected_attestation["id"]
            reservation["extensions"][
                "reconciliation_owner_instance_id"
            ] = owner_instance
            ledger["revision"] += 1
            state["state"]["revision"] += 1
            state["state"]["updated_at"] = _format_utc(now)
            post_errors = validate_json_schema(state, schema)
            post_errors.extend(_semantic_state_errors(state))
            if post_errors:
                raise ContractError(
                    "reconciled state would violate contract: {}".format(
                        "; ".join(post_errors)
                    )
                )
            new_digest = _durable_replace_json(state_path, state)
        _json_output(
            {
                "contract_version": "2.0",
                "result": "pass",
                "errors": [],
                "replayed": False,
                "authorizes_consequential_action": False,
                "reservation_status": reservation["status"],
                "reconciliation_id": args.reconciliation_id,
                "recovery_required": recovery_required,
                "state_revision": state["state"]["revision"],
                "ledger_revision": ledger["revision"],
                "state_digest": new_digest,
            }
        )
        return 0
    except CASConflict as exc:
        code, payload = _atomic_error_payload(str(exc), 3)
    except ContractError as exc:
        code = 2 if "legacy state has no action_ledger" in str(exc) else 1
        code, payload = _atomic_error_payload(str(exc), code)
    except (OSError, ValueError) as exc:
        code, payload = _atomic_error_payload(
            "atomic reconciliation failed: {}".format(exc), 1
        )
    _json_output(payload)
    return code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    package = subparsers.add_parser("check-package", help="check static package and optional runtime activation")
    package.add_argument("--root", default=".")
    package.add_argument("--state")
    package.add_argument("--role", default="meva_orchestrator")
    package.add_argument("--task-id")
    package.add_argument("--now")
    package.set_defaults(func=command_check_package)

    release = subparsers.add_parser(
        "check-release",
        help="check installed package and Validation-owned release evidence",
    )
    release.add_argument("--root", default=".")
    release.set_defaults(func=command_check_release)

    state = subparsers.add_parser("validate-state", help="validate JSON state and semantic invariants")
    state.add_argument("state")
    state.add_argument("--schema", default="contracts/meva.schema.json")
    state.set_defaults(func=command_validate_state)

    handoff = subparsers.add_parser(
        "validate-handoff", help="validate a compact handoff object encoded as JSON"
    )
    handoff.add_argument("handoff")
    handoff.add_argument("--schema", default="contracts/meva.schema.json")
    handoff.set_defaults(func=command_validate_handoff)

    approval = subparsers.add_parser("verify-approval", help="verify exact trusted approval use")
    approval.add_argument("--state", required=True)
    approval.add_argument("--schema", default="contracts/meva.schema.json")
    approval.add_argument("--approval-id", required=True)
    approval.add_argument("--action", required=True)
    approval.add_argument("--scope", action="append", default=[])
    approval.add_argument("--environment", required=True)
    approval.add_argument("--limits-json", required=True)
    approval.add_argument("--now")
    approval.set_defaults(func=command_verify_approval)

    preflight = subparsers.add_parser("preflight", help="fail-closed action-boundary authorization and accounting check")
    preflight.add_argument("--state", required=True)
    preflight.add_argument("--schema", default="contracts/meva.schema.json")
    preflight.add_argument("--root", default=".")
    preflight.add_argument("--task-id", required=True)
    preflight.add_argument("--role", required=True)
    preflight.add_argument("--action", required=True)
    preflight.add_argument("--action-kind", default="ordinary", choices=sorted({
        "ordinary", "essential", "nonessential", "fanout", "cleanup", "emergency_safe_stop"
    }))
    preflight.add_argument("--path")
    preflight.add_argument("--target-expected-digest")
    preflight.add_argument("--target-expected-absent", action="store_true")
    preflight.add_argument("--environment", required=True)
    preflight.add_argument("--cost", type=float, default=0)
    preflight.add_argument("--compute-units", type=float, default=0)
    preflight.add_argument("--wall-time-seconds", type=float, default=0)
    preflight.add_argument("--external-calls", type=int, default=0)
    preflight.add_argument("--worker-fanout", type=int, default=0)
    preflight.add_argument("--delegation-depth", type=int)
    preflight.add_argument("--retry-count", type=int)
    preflight.add_argument("--alternative-attempts", type=int)
    preflight.add_argument("--action-chain-steps", type=int)
    preflight.add_argument("--now")
    preflight.set_defaults(func=command_preflight)

    review = subparsers.add_parser("evaluate-review", help="evaluate review without letting priority weaken blockers")
    review.add_argument("--state", required=True)
    review.add_argument("--schema", default="contracts/meva.schema.json")
    review.add_argument("--root", default=".")
    review.add_argument("--now")
    review.set_defaults(func=command_evaluate_review)

    reserve = subparsers.add_parser(
        "reserve-action",
        help="atomically authorize and reserve one consequential action",
    )
    reserve.add_argument("--state", required=True)
    reserve.add_argument("--schema", default="contracts/meva.schema.json")
    reserve.add_argument("--root", default=".")
    reserve.add_argument("--trusted-state-root")
    reserve.add_argument("--idempotency-key", required=True)
    reserve.add_argument("--task-id", required=True)
    reserve.add_argument("--role", required=True)
    reserve.add_argument("--action", required=True)
    reserve.add_argument(
        "--action-kind",
        required=True,
        choices=sorted(
            {
                "ordinary",
                "essential",
                "nonessential",
                "fanout",
                "cleanup",
                "emergency_safe_stop",
            }
        ),
    )
    reserve.add_argument(
        "--effect",
        required=True,
        choices=[
            "project_read",
            "project_write",
            "external_read",
            "external_mutation",
            "physical",
        ],
    )
    reserve.add_argument("--target-kind", required=True)
    reserve.add_argument("--target-id", required=True)
    reserve.add_argument("--path")
    reserve.add_argument("--target-expected-revision", type=int)
    reserve.add_argument("--target-expected-digest")
    reserve.add_argument("--environment", required=True)
    reserve.add_argument("--cost", type=float, default=0)
    reserve.add_argument("--compute-units", type=float, default=0)
    reserve.add_argument("--wall-time-seconds", type=float, default=0)
    reserve.add_argument("--external-calls", type=int, default=0)
    reserve.add_argument("--worker-fanout", type=int, default=0)
    reserve.add_argument("--expected-state-revision", type=int, required=True)
    reserve.add_argument("--expected-ledger-revision", type=int, required=True)
    reserve.add_argument("--expected-state-digest", required=True)
    reserve.add_argument("--expires-at", required=True)
    reserve.add_argument("--now")
    reserve.set_defaults(func=command_reserve_action)

    claim = subparsers.add_parser(
        "claim-action",
        help="atomically consume one reservation before one adapter execution",
    )
    claim.add_argument("--state", required=True)
    claim.add_argument("--schema", default="contracts/meva.schema.json")
    claim.add_argument("--root", default=".")
    claim.add_argument("--trusted-state-root")
    claim.add_argument("--task-id", required=True)
    claim.add_argument("--role", required=True)
    claim.add_argument("--reservation-token", required=True)
    claim.add_argument("--expected-request-digest")
    claim.add_argument("--expected-state-revision", type=int, required=True)
    claim.add_argument("--expected-ledger-revision", type=int, required=True)
    claim.add_argument("--expected-state-digest", required=True)
    claim.add_argument("--claim-id")
    claim.add_argument("--now")
    claim.set_defaults(func=command_claim_action)

    reconcile = subparsers.add_parser(
        "reconcile-action",
        help="atomically reconcile one previously reserved action",
    )
    reconcile.add_argument("--state", required=True)
    reconcile.add_argument("--schema", default="contracts/meva.schema.json")
    reconcile.add_argument("--root", default=".")
    reconcile.add_argument("--trusted-state-root")
    reconcile.add_argument("--task-id", required=True)
    reconcile.add_argument("--role", required=True)
    reconcile.add_argument("--reservation-token", required=True)
    reconcile.add_argument("--expected-request-digest")
    reconcile.add_argument("--reconciliation-id", required=True)
    reconcile.add_argument(
        "--execution-status",
        required=True,
        choices=["succeeded", "failed", "unknown"],
    )
    reconcile.add_argument("--actual-cost", type=float, default=0)
    reconcile.add_argument("--actual-compute-units", type=float, default=0)
    reconcile.add_argument("--actual-wall-time-seconds", type=float, default=0)
    reconcile.add_argument("--actual-external-calls", type=int, default=0)
    reconcile.add_argument("--actual-worker-fanout", type=int, default=0)
    reconcile.add_argument("--outcome-digest", default="unknown")
    reconcile.add_argument("--expected-state-revision", type=int)
    reconcile.add_argument("--expected-ledger-revision", type=int)
    reconcile.add_argument("--expected-state-digest")
    reconcile.add_argument("--now")
    reconcile.set_defaults(func=command_reconcile_action)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return int(args.func(args))
    except ContractError as exc:
        _json_output({"contract_version": "2.0", "result": "fail", "errors": [str(exc)]})
        return 1


if __name__ == "__main__":
    sys.exit(main())
