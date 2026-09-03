"""Independent stdlib-only conformance tests for MEVA contract v2.

Product files are treated as immutable inputs. Mutation cases operate only on
deep copies or temporary package trees.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "tools" / "meva_check.py"
SCHEMA_PATH = ROOT / "contracts" / "meva.schema.json"
TEMPLATE_PATH = ROOT / "templates" / "project-state.json"
PROTOCOL_PATH = ROOT / "tests" / "conformance" / "protocol.v1.json"
PROTOCOL_LOCK_PATH = ROOT / "tests" / "conformance" / "protocol.v1.sha256"
EXPECTED_PROTOCOL_DIGEST = (
    "c529f598c93217d262b5de29b8af29044213ef065b438905532452eb42d97c4d"
)
ZERO_DIGEST = "0" * 64
POLICY_DIGEST = "2" * 64


def file_digest(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

_SPEC = importlib.util.spec_from_file_location("meva_check", CHECKER_PATH)
assert _SPEC and _SPEC.loader
CHECK = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(CHECK)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


SCHEMA = load_json(SCHEMA_PATH)
TEMPLATE = load_json(TEMPLATE_PATH)


def accounting(limit=100, used=0):
    return {
        "budget": {
            "max_cost": limit,
            "max_compute_units": limit,
            "max_wall_time_seconds": limit,
            "max_external_calls": limit,
            "max_worker_fanout": 4,
            "max_delegation_depth": 2,
            "max_retries_per_operation": 1,
            "max_alternative_attempts": 1,
            "max_action_chain_steps": 10,
        },
        "usage": {
            "cost": used,
            "compute_units": 0,
            "wall_time_seconds": 0,
            "external_calls": 0,
            "worker_fanout": 0,
            "delegation_depth": 0,
            "retries_current_operation": 0,
            "alternative_attempts": 0,
            "action_chain_steps": 0,
        },
        "notified_at_70_percent": used >= 70,
        "reestimated_at_70_percent": used >= 70,
        "updated_at": "2030-01-01T00:00:00Z",
    }


def valid_task(role="implementation_engineer", task_id="TASK-001"):
    read_only = role in {"planner", "reviewer"}
    return {
        "id": task_id,
        "objective": "Exercise the accepted checker contract.",
        "accountable_owner": role,
        "risk_tier": "R1",
        "scope": ["contract validation"],
        "out_of_scope": [],
        "inputs": [{"artifact": "package", "version": "test"}],
        "dependencies": [],
        "writable_scope": [] if read_only else ["src"],
        "required_outputs": ["evidence"],
        "acceptance_checks": ["checker returns expected result"],
        "constraints": ["local only"],
        "data_classification": "internal",
        "physical_safety_tier": "not_applicable",
        "target_environment": "local",
        "allowed_actions": ["inspect"] if read_only else ["edit_assigned_files"],
        "status": "in_progress",
        "changed_paths": [],
        "authored_artifact_ids": [],
        "accounting": accounting(),
        "rollback_or_recovery": "Discard temporary state.",
        "approvals_required": [],
        "extensions": {"allowed_environments": ["local"]},
    }


def valid_attestation(role="implementation_engineer", task_id="TASK-001"):
    read_only = role in {"planner", "reviewer"}
    action = "inspect" if read_only else "edit_assigned_files"
    return {
        "id": "ATT-001",
        "source": "runtime-control-plane",
        "source_kind": "runtime_owned",
        "status": "current",
        "project_id": "validation-project",
        "fresh_session": True,
        "role": role,
        "task_id": task_id,
        "runtime": "codex-test-runtime",
        "model": "test-model",
        "provider": "test-provider",
        "policy_digest": POLICY_DIGEST,
        "config_digest": file_digest(ROOT / ".codex/config.toml"),
        "manual_digest": file_digest(ROOT / "Agent.md"),
        "schema_digest": file_digest(SCHEMA_PATH),
        "role_digest": file_digest(ROOT / ".codex/agents" / (role + ".toml")),
        "ticket_digest": hashlib.sha256(
            json.dumps(
                valid_task(role, task_id), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest(),
        "effective_permissions": {
            "writable_scopes": [] if read_only else ["src"],
            "actions": [action],
            "environments": ["local"],
            "external_calls": False,
            "max_concurrency": 4,
        },
        "observed_at": "2030-01-01T00:00:00Z",
        "expires_at": "2031-01-01T00:00:00Z",
        "extensions": {},
    }


def valid_state(role="implementation_engineer"):
    state = copy.deepcopy(TEMPLATE)
    state["project"].update(
        {
            "id": "validation-project",
            "goal": "Validate contract behavior.",
            "risk_tier": "R1",
            "risk_rationale": "Local deterministic contract validation.",
        }
    )
    state["state"] = {
        "revision": 3,
        "status": "building",
        "current_invalidation_revision": 0,
        "updated_at": "2030-01-01T00:00:00Z",
        "history": [
            {
                "revision": 1,
                "from": "intake",
                "to": "design",
                "actor": "primary",
                "at": "2030-01-01T00:00:00Z",
                "reason": "intake complete",
                "evidence_ids": [],
            },
            {
                "revision": 2,
                "from": "design",
                "to": "ready",
                "actor": "primary",
                "at": "2030-01-01T00:00:01Z",
                "reason": "design accepted",
                "evidence_ids": [],
            },
            {
                "revision": 3,
                "from": "ready",
                "to": "building",
                "actor": "primary",
                "at": "2030-01-01T00:00:02Z",
                "reason": "build started",
                "evidence_ids": [],
            },
        ],
    }
    state["authority"] = {
        "source": "human-ticket-system",
        "source_kind": "runtime_owned",
        "allowed_actions": ["inspect"]
        if role in {"planner", "reviewer"}
        else ["edit_assigned_files"],
        "scopes": [] if role in {"planner", "reviewer"} else ["src"],
        "environments": ["local"],
        "expires_at": "2031-01-01T00:00:00Z",
        "extensions": {},
    }
    state["tasks"] = [valid_task(role)]
    state["accounting"] = accounting()
    state["permission_attestations"] = [valid_attestation(role)]
    state["provenance"] = {
        "runtime": "codex-test-runtime",
        "model": "test-model",
        "provider": "test-provider",
        "permission_mode": "managed",
        "sandbox_mode": "read_only"
        if role in {"planner", "reviewer"}
        else "workspace_write",
        "policy_digest": POLICY_DIGEST,
        "config_digest": file_digest(ROOT / ".codex/config.toml"),
        "manual_digest": file_digest(ROOT / "Agent.md"),
        "schema_digest": file_digest(SCHEMA_PATH),
        "role_digest": file_digest(ROOT / ".codex/agents" / (role + ".toml")),
        "ticket_digest": hashlib.sha256(
            json.dumps(
                valid_task(role), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest(),
        "artifact_digests": {},
        "attestation_source": "runtime-control-plane",
    }
    return state


def approval(approval_id="APP-001"):
    return {
        "approval_id": approval_id,
        "approved_by": "authorized-human",
        "action": "deploy_release",
        "scope": ["service/api"],
        "environment": "staging",
        "limits": {
            "max_cost": None,
            "max_compute_units": None,
            "max_wall_time_seconds": 600,
            "max_external_calls": 0,
            "max_action_chain_steps": 10,
            "physical_envelope": {},
            "extensions": {},
        },
        "status": "active",
        "issued_at": "2030-01-01T00:00:00Z",
        "expires_at": "2031-01-01T00:00:00Z",
        "verification": {
            "source": "approval-resolver",
            "source_kind": "trusted_external",
            "status": "verified",
            "verified_at": "2030-01-01T00:00:01Z",
        },
        "extensions": {},
    }


def finding(
    finding_id="FIND-001",
    severity="high",
    priority="P1",
    disposition="open",
):
    return {
        "id": finding_id,
        "severity": severity,
        "priority": priority,
        "category": "correctness",
        "title": "Contract defect",
        "location": "test fixture",
        "evidence": "deterministic fixture",
        "impact": "Gate semantics could be weakened.",
        "trigger": "The finding is evaluated.",
        "required_action": "Repair and rerun.",
        "owner": "implementation_engineer",
        "disposition": disposition,
        "gate": "implementation",
        "approval_id": "",
        "duplicate_of": "",
        "rationale": "",
        "original_evidence": [],
        "resolution_evidence_ids": [],
        "extensions": {},
    }


def valid_handoff(role="validation_engineer"):
    return {
        "contract_version": "2.0",
        "task_id": "TASK-001",
        "role": role,
        "status": "complete",
        "summary": "Validation completed.",
        "scope": {"inspected": ["package"], "changed": [], "excluded": []},
        "provenance": copy.deepcopy(valid_state()["provenance"]),
        "decisions": [],
        "evidence": [],
        "risks": [],
        "open_questions": [],
        "next_actions": [],
        "human_approval": {
            "required": False,
            "approval_id": "",
            "approved_by": "",
            "action": "",
            "scope": [],
            "environment": "",
            "limits": {},
            "expires_at": "",
            "reason": "",
            "verification_source": "",
            "verification_status": "",
        },
        "extensions": {},
    }


def schema_errors(instance, definition):
    return CHECK.validate_json_schema(instance, SCHEMA["$defs"][definition], SCHEMA)


def write_json(directory: Path, value, name="state.json"):
    path = directory / name
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def run_checker(args, checker=CHECKER_PATH, cwd=ROOT):
    process = subprocess.run(
        [sys.executable, str(checker)] + list(args),
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            "checker did not emit JSON: rc={!r}, stdout={!r}, stderr={!r}".format(
                process.returncode, process.stdout, process.stderr
            )
        ) from exc
    return process.returncode, payload


def copy_package(destination: Path):
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "validation-report.json", ".meva"
        ),
    )


class FrozenProtocolTests(unittest.TestCase):
    def test_protocol_digest_is_frozen(self):
        actual = hashlib.sha256(PROTOCOL_PATH.read_bytes()).hexdigest()
        locked = PROTOCOL_LOCK_PATH.read_text(encoding="utf-8").split()[0]
        self.assertEqual(EXPECTED_PROTOCOL_DIGEST, actual)
        self.assertEqual(actual, locked)

    def test_protocol_digest_mutation_fails_static_package(self):
        with tempfile.TemporaryDirectory() as raw:
            package = Path(raw) / "package"
            copy_package(package)
            protocol = package / "tests/conformance/protocol.v1.json"
            protocol.write_text(protocol.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            _, payload = run_checker(["check-package", "--root", str(package)])
            self.assertEqual("fail", payload["static_package"])
            self.assertTrue(
                any("protocol digest mismatch" in item for item in payload["static_errors"])
            )


class PackageConformanceTests(unittest.TestCase):
    def test_static_package_passes_and_runtime_is_separate_unverified(self):
        rc, payload = run_checker(["check-package", "--root", "."])
        self.assertEqual(0, rc)
        self.assertEqual("pass", payload["static_package"])
        self.assertEqual("unverified", payload["runtime_activation"])

    def test_exactly_five_workers_and_primary_bootstrap(self):
        role_files = sorted((ROOT / ".codex/agents").glob("*.toml"))
        self.assertEqual(5, len(role_files))
        self.assertFalse((ROOT / ".codex/agents/meva_orchestrator.toml").exists())
        bootstrap = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        manual = (ROOT / "Agent.md").read_text(encoding="utf-8")
        self.assertIn("primary MEVA Orchestrator", bootstrap)
        self.assertIn("not a spawnable custom role", bootstrap)
        self.assertIn("automatically activated primary agent", manual)

    def test_custom_orchestrator_role_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            package = Path(raw) / "package"
            copy_package(package)
            source = package / ".codex/agents/planner.toml"
            target = package / ".codex/agents/meva_orchestrator.toml"
            target.write_text(
                source.read_text(encoding="utf-8").replace(
                    'name = "planner"', 'name = "meva_orchestrator"', 1
                ),
                encoding="utf-8",
            )
            _, payload = run_checker(["check-package", "--root", str(package)])
            self.assertEqual("fail", payload["static_package"])

    def test_config_supported_keys_only(self):
        _, baseline = run_checker(["check-package", "--root", "."])
        self.assertEqual("pass", baseline["static_package"])
        forbidden = [
            "max_depth = 2",
            "max_threads = 4",
            "[features]\nmulti_agent = true",
        ]
        for addition in forbidden:
            with self.subTest(addition=addition), tempfile.TemporaryDirectory() as raw:
                package = Path(raw) / "package"
                copy_package(package)
                config = package / ".codex/config.toml"
                config.write_text(
                    config.read_text(encoding="utf-8") + "\n" + addition + "\n",
                    encoding="utf-8",
                )
                _, payload = run_checker(["check-package", "--root", str(package)])
                self.assertEqual("fail", payload["static_package"])


class SchemaAndVocabularyTests(unittest.TestCase):
    def test_canonical_vocabulary_sets(self):
        expected = {
            "workerRole": {
                "planner",
                "implementation_engineer",
                "platform_engineer",
                "validation_engineer",
                "reviewer",
            },
            "lifecycleState": {
                "intake",
                "design",
                "ready",
                "building",
                "validating",
                "reviewing",
                "awaiting_human",
                "releasing",
                "complete",
                "blocked",
            },
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
            "environment": {
                "unit",
                "local",
                "ci",
                "replay",
                "simulation",
                "staging",
                "hardware_in_loop",
                "controlled_hardware",
                "edge",
                "production",
            },
        }
        for name, values in expected.items():
            with self.subTest(definition=name):
                self.assertEqual(values, set(SCHEMA["$defs"][name]["enum"]))

    def test_aliases_are_rejected(self):
        state = valid_state()
        mutations = [
            ("environment", lambda item: item["project"].update(
                {"target_environments": ["hardware-in-loop"]}
            )),
            ("gate", lambda item: item["gates"].append(
                {
                    "id": "GATE-001",
                    "gate": "release",
                    "result": "pass",
                    "evidence_ids": [],
                    "depends_on": [],
                    "invalidation_revision": 0,
                    "extensions": {},
                }
            )),
            ("recommendation", lambda item: item["review"].update(
                {"recommendation": "conditional pass"}
            )),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                candidate = copy.deepcopy(state)
                mutate(candidate)
                self.assertTrue(CHECK.validate_json_schema(candidate, SCHEMA))

    def test_valid_template_and_json_restart(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            first = write_json(directory, valid_state())
            state, _, errors = CHECK.validate_state(first, SCHEMA_PATH)
            self.assertEqual([], errors)
            restarted = write_json(directory, json.loads(json.dumps(state)), "restart.json")
            _, _, restart_errors = CHECK.validate_state(restarted, SCHEMA_PATH)
            self.assertEqual([], restart_errors)

    def test_duplicate_and_unknown_json_fields_reject_extensions_allow(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            duplicate = directory / "duplicate.json"
            duplicate.write_text('{"contract_version":"2.0","contract_version":"2.0"}', encoding="utf-8")
            rc, payload = run_checker(["validate-state", str(duplicate)])
            self.assertNotEqual(0, rc)
            self.assertTrue(any("duplicate JSON key" in item for item in payload["errors"]))

            unknown = valid_state()
            unknown["unexpected"] = True
            path = write_json(directory, unknown, "unknown.json")
            rc, payload = run_checker(["validate-state", str(path)])
            self.assertNotEqual(0, rc)
            self.assertTrue(any("unknown field" in item for item in payload["errors"]))

            extended = valid_state()
            extended["extensions"]["future_contract_field"] = {"enabled": True}
            path = write_json(directory, extended, "extended.json")
            rc, payload = run_checker(["validate-state", str(path)])
            self.assertEqual(0, rc, payload)

    def test_required_state_and_handoff_fields_reject(self):
        state = valid_state()
        del state["provenance"]
        self.assertTrue(CHECK.validate_json_schema(state, SCHEMA))

        handoff = valid_handoff()
        self.assertEqual([], schema_errors(handoff, "handoff"))
        missing = copy.deepcopy(handoff)
        del missing["task_id"]
        self.assertTrue(schema_errors(missing, "handoff"))
        unknown = copy.deepcopy(handoff)
        unknown["unexpected"] = True
        self.assertTrue(schema_errors(unknown, "handoff"))

    def test_read_only_handoff_changed_scope_rejects(self):
        for role in ("planner", "reviewer"):
            with self.subTest(role=role):
                handoff = valid_handoff(role)
                handoff["scope"]["changed"] = ["product.py"]
                self.assertTrue(
                    schema_errors(handoff, "handoff"),
                    "read-only handoff with changed paths must be invalid",
                )


class AuthorityAndIndependenceTests(unittest.TestCase):
    def preflight(self, state, extra=None, role="implementation_engineer"):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            args = [
                "preflight",
                "--state",
                str(path),
                "--task-id",
                "TASK-001",
                "--role",
                role,
                "--action",
                "inspect" if role in {"planner", "reviewer"} else "edit_assigned_files",
                "--environment",
                "local",
                "--now",
                "2030-06-01T00:00:00Z",
            ]
            if extra:
                args.extend(extra)
            return run_checker(args)

    def test_valid_authority_intersection_and_scope_escape(self):
        rc, payload = self.preflight(valid_state(), ["--path", "src/service.py"])
        self.assertEqual(0, rc, payload)
        rc, payload = self.preflight(valid_state(), ["--path", "other/service.py"])
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])

    def test_broader_runtime_permission_fails_closed(self):
        state = valid_state()
        state["permission_attestations"][0]["effective_permissions"][
            "writable_scopes"
        ] = ["."]
        rc, payload = self.preflight(state, ["--path", "src/service.py"])
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])

    def test_planner_and_reviewer_require_empty_writable_scope(self):
        for role in ("planner", "reviewer"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as raw:
                state = valid_state(role)
                state["tasks"][0]["writable_scope"] = ["docs"]
                path = write_json(Path(raw), state)
                rc, payload = run_checker(["validate-state", str(path)])
                self.assertNotEqual(0, rc)
                self.assertTrue(
                    any("read-only task" in item for item in payload["errors"])
                )

    def test_reviewer_authorship_conflict_rejects(self):
        state = valid_state("reviewer")
        state["artifacts"] = [
            {
                "id": "ART-001",
                "location": "src/service.py",
                "digest": ZERO_DIGEST,
                "authors": ["review-agent"],
                "owner": "implementation_engineer",
                "depends_on": [],
                "status": "current",
                "extensions": {},
            }
        ]
        state["review"] = {
            "reviewer": "review-agent",
            "target_artifact_ids": ["ART-001"],
            "target_evidence_ids": [],
            "independence_conflicts": [],
            "recommendation": "pass",
            "extensions": {},
        }
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload = run_checker(["validate-state", str(path)])
            self.assertNotEqual(0, rc)
            self.assertTrue(any("authorship overlap" in item for item in payload["errors"]))

    def test_overlapping_active_writers_reject(self):
        state = valid_state()
        second = valid_task("platform_engineer", "TASK-002")
        second["writable_scope"] = ["src"]
        state["tasks"].append(second)
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload = run_checker(["validate-state", str(path)])
            self.assertNotEqual(
                0, rc, "two active task owners may not hold overlapping writable scopes"
            )


class ApprovalTests(unittest.TestCase):
    def verify(self, state, approval_id="APP-001", action="deploy_release",
               scope=None, environment="staging", limits=None,
               now="2030-06-01T00:00:00Z"):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            args = [
                "verify-approval",
                "--state",
                str(path),
                "--approval-id",
                approval_id,
                "--action",
                action,
                "--environment",
                environment,
                "--limits-json",
                json.dumps(limits if limits is not None else approval()["limits"]),
                "--now",
                now,
            ]
            for item in scope if scope is not None else ["service/api"]:
                args.extend(["--scope", item])
            return run_checker(args)

    def test_valid_approval_and_unknown_id(self):
        state = valid_state()
        state["approvals"] = [approval()]
        rc, payload = self.verify(state)
        self.assertEqual(0, rc, payload)
        rc, payload = self.verify(state, approval_id="UNKNOWN")
        self.assertNotEqual(0, rc)

    def test_untrusted_expired_and_exact_mismatches_reject(self):
        base = valid_state()
        base["approvals"] = [approval()]
        cases = []
        self_asserted = copy.deepcopy(base)
        self_asserted["approvals"][0]["verification"]["source_kind"] = "self_asserted"
        cases.append(("self_asserted", self_asserted, {}))
        expired = copy.deepcopy(base)
        expired["approvals"][0]["expires_at"] = "2030-05-01T00:00:00Z"
        cases.append(("expired", expired, {}))
        cases.append(("scope", base, {"scope": ["service"]}))
        cases.append(("environment", base, {"environment": "production"}))
        wrong_limits = copy.deepcopy(approval()["limits"])
        wrong_limits["max_wall_time_seconds"] = 601
        cases.append(("limits", base, {"limits": wrong_limits}))
        for label, state, kwargs in cases:
            with self.subTest(label=label):
                rc, payload = self.verify(state, **kwargs)
                self.assertNotEqual(0, rc)
                self.assertEqual("fail", payload["result"])

    def test_exact_expiry_boundary_rejects(self):
        state = valid_state()
        state["approvals"] = [approval()]
        rc, payload = self.verify(state, now="2031-01-01T00:00:00Z")
        self.assertNotEqual(0, rc)
        self.assertTrue(any("expired" in item for item in payload["errors"]))


class AccountingTests(unittest.TestCase):
    def preflight_cost(self, used, increment, action_kind="ordinary", flags=None):
        state = valid_state()
        state["tasks"][0]["accounting"] = accounting(100, used)
        state["accounting"] = accounting(100, used)
        if flags:
            state["tasks"][0]["accounting"].update(flags)
            state["accounting"].update(flags)
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            return run_checker(
                [
                    "preflight",
                    "--state",
                    str(path),
                    "--task-id",
                    "TASK-001",
                    "--role",
                    "implementation_engineer",
                    "--action",
                    "edit_assigned_files",
                    "--action-kind",
                    action_kind,
                    "--path",
                    "src/service.py",
                    "--environment",
                    "local",
                    "--cost",
                    str(increment),
                    "--now",
                    "2030-06-01T00:00:00Z",
                ]
            )

    def test_70_percent_boundary(self):
        rc, payload = self.preflight_cost(69, 0.9)
        self.assertEqual(0, rc, payload)
        rc, payload = self.preflight_cost(
            69,
            1,
            flags={
                "notified_at_70_percent": False,
                "reestimated_at_70_percent": False,
            },
        )
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])
        rc, payload = self.preflight_cost(70, 0)
        self.assertEqual(0, rc, payload)
        self.assertTrue(any("70%" in item for item in payload["notices"]))

    def test_90_and_100_percent_boundaries(self):
        rc, payload = self.preflight_cost(90, 0, "fanout")
        self.assertNotEqual(0, rc)
        rc, payload = self.preflight_cost(90, 0, "ordinary")
        self.assertEqual(0, rc, payload)
        rc, payload = self.preflight_cost(100, 0, "ordinary")
        self.assertNotEqual(0, rc)
        rc, payload = self.preflight_cost(100, 0, "cleanup")
        self.assertEqual(0, rc, payload)
        rc, payload = self.preflight_cost(100, 0, "emergency_safe_stop")
        self.assertEqual(0, rc, payload)

    def test_hard_limits_depth_retry_alternative_and_chain(self):
        flags = [
            ("--delegation-depth", "3"),
            ("--retry-count", "2"),
            ("--alternative-attempts", "2"),
            ("--action-chain-steps", "11"),
        ]
        for flag, value in flags:
            with self.subTest(flag=flag):
                state = valid_state()
                with tempfile.TemporaryDirectory() as raw:
                    path = write_json(Path(raw), state)
                    rc, payload = run_checker(
                        [
                            "preflight",
                            "--state",
                            str(path),
                            "--task-id",
                            "TASK-001",
                            "--role",
                            "implementation_engineer",
                            "--action",
                            "edit_assigned_files",
                            "--path",
                            "src/service.py",
                            "--environment",
                            "local",
                            flag,
                            value,
                            "--now",
                            "2030-06-01T00:00:00Z",
                        ]
                    )
                    self.assertNotEqual(0, rc)
                    self.assertEqual("fail", payload["result"])

    def test_invalid_declared_depth_and_retry_limits_reject(self):
        mutations = [
            ("max_delegation_depth", 3),
            ("max_retries_per_operation", 2),
            ("max_alternative_attempts", 2),
        ]
        for key, value in mutations:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as raw:
                state = valid_state()
                state["tasks"][0]["accounting"]["budget"][key] = value
                path = write_json(Path(raw), state)
                rc, payload = run_checker(["validate-state", str(path)])
                self.assertNotEqual(0, rc)


class LifecycleAndInvalidationTests(unittest.TestCase):
    def test_legal_lifecycle_r0_fast_path_and_invalid_transitions(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            legal = valid_state()
            path = write_json(directory, legal, "legal.json")
            self.assertEqual(0, run_checker(["validate-state", str(path)])[0])

            fast = copy.deepcopy(TEMPLATE)
            fast["state"].update(
                {
                    "revision": 1,
                    "status": "complete",
                    "history": [
                        {
                            "revision": 1,
                            "from": "intake",
                            "to": "complete",
                            "actor": "primary",
                            "at": "2030-01-01T00:00:00Z",
                            "reason": "R0 no-delegation fast path",
                            "evidence_ids": [],
                        }
                    ],
                }
            )
            path = write_json(directory, fast, "fast.json")
            self.assertEqual(0, run_checker(["validate-state", str(path)])[0])

            skipped = valid_state()
            skipped["state"]["history"][0]["to"] = "building"
            path = write_json(directory, skipped, "skipped.json")
            self.assertNotEqual(0, run_checker(["validate-state", str(path)])[0])

            terminal = valid_state()
            terminal["state"]["history"] = [
                {
                    "revision": 1,
                    "from": "intake",
                    "to": "complete",
                    "actor": "primary",
                    "at": "2030-01-01T00:00:00Z",
                    "reason": "done",
                    "evidence_ids": [],
                },
                {
                    "revision": 2,
                    "from": "complete",
                    "to": "design",
                    "actor": "primary",
                    "at": "2030-01-01T00:00:01Z",
                    "reason": "invalid resume",
                    "evidence_ids": [],
                },
            ]
            terminal["state"].update({"revision": 2, "status": "design"})
            path = write_json(directory, terminal, "terminal.json")
            self.assertNotEqual(0, run_checker(["validate-state", str(path)])[0])

    def test_task_dependency_cycles_reject(self):
        state = valid_state()
        state["tasks"][0]["dependencies"] = ["TASK-002"]
        second = valid_task("platform_engineer", "TASK-002")
        second["writable_scope"] = ["platform"]
        second["dependencies"] = ["TASK-001"]
        state["tasks"].append(second)
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload = run_checker(["validate-state", str(path)])
            self.assertNotEqual(0, rc)
            self.assertTrue(any("cycle" in item for item in payload["errors"]))

    def invalidation_state(self, resolved=False):
        state = valid_state()
        state["requirements"] = [
            {
                "id": "REQ-001",
                "statement": "Changed behavior contract.",
                "source": "accepted design",
                "depends_on": [],
                "status": "active",
                "extensions": {},
            }
        ]
        state["artifacts"] = [
            {
                "id": "ART-001",
                "location": "src/service.py",
                "digest": ZERO_DIGEST,
                "authors": ["implementer"],
                "owner": "implementation_engineer",
                "depends_on": ["REQ-001"],
                "status": "current" if resolved else "invalidated",
                "extensions": {},
            },
            {
                "id": "ART-UNRELATED",
                "location": "docs/unrelated.md",
                "digest": ZERO_DIGEST,
                "authors": ["writer"],
                "owner": "implementation_engineer",
                "depends_on": [],
                "status": "current",
                "extensions": {},
            },
        ]
        state["evidence"] = [
            {
                "id": "EVID-001",
                "claim": "Changed behavior is valid.",
                "source": "test",
                "environment": "unit",
                "result": "pass",
                "observation": "deterministic",
                "authors": ["validator"],
                "depends_on": ["ART-001"],
                "status": "current" if resolved else "invalidated",
                "invalidation_revision": 1 if resolved else 0,
                "extensions": {},
            }
        ]
        state["gates"] = [
            {
                "id": "GATE-001",
                "gate": "validation",
                "result": "pass" if resolved else "unverified",
                "evidence_ids": ["EVID-001"],
                "depends_on": [],
                "invalidation_revision": 1 if resolved else 0,
                "extensions": {},
            }
        ]
        state["state"]["current_invalidation_revision"] = 1
        state["invalidations"] = [
            {
                "id": "INV-001",
                "revision": 1,
                "changed_ids": ["REQ-001"],
                "affected_artifact_ids": ["ART-001"],
                "affected_evidence_ids": ["EVID-001"],
                "affected_gate_ids": ["GATE-001"],
                "required_owners": ["implementation_engineer", "validation_engineer"],
                "acknowledgements": [
                    {
                        "owner": "implementation_engineer",
                        "revision": 1,
                        "acknowledged_at": "2030-01-01T00:00:00Z",
                    },
                    {
                        "owner": "validation_engineer",
                        "revision": 1,
                        "acknowledged_at": "2030-01-01T00:00:00Z",
                    },
                ]
                if resolved
                else [],
                "rerun_evidence_ids": ["EVID-001"] if resolved else [],
                "status": "resolved" if resolved else "open",
                "reason": "Requirement changed.",
                "extensions": {},
            }
        ]
        return state

    def test_transitive_invalidation_and_unrelated_evidence(self):
        for resolved in (False, True):
            with self.subTest(resolved=resolved), tempfile.TemporaryDirectory() as raw:
                state = self.invalidation_state(resolved)
                path = write_json(Path(raw), state)
                rc, payload = run_checker(["validate-state", str(path)])
                self.assertEqual(0, rc, payload)
                self.assertEqual("current", state["artifacts"][1]["status"])

    def test_partial_stale_and_incomplete_invalidation_reject(self):
        cases = []
        incomplete = self.invalidation_state(False)
        incomplete["invalidations"][0]["affected_evidence_ids"] = []
        cases.append(("incomplete", incomplete))
        stale = self.invalidation_state(True)
        stale["invalidations"][0]["acknowledgements"][0]["revision"] = 2
        cases.append(("stale", stale))
        partial = self.invalidation_state(True)
        partial["invalidations"][0]["acknowledgements"].pop()
        cases.append(("partial", partial))
        missing_rerun = self.invalidation_state(True)
        missing_rerun["invalidations"][0]["rerun_evidence_ids"] = []
        cases.append(("rerun", missing_rerun))
        for label, state in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                path = write_json(Path(raw), state)
                rc, payload = run_checker(["validate-state", str(path)])
                self.assertNotEqual(0, rc)


class ReviewTests(unittest.TestCase):
    def evaluate(self, state):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            return run_checker(
                [
                    "evaluate-review",
                    "--state",
                    str(path),
                    "--now",
                    "2030-06-01T00:00:00Z",
                ]
            )

    def test_priority_does_not_weaken_high_blocker(self):
        for priority in ("P0", "P1"):
            with self.subTest(priority=priority):
                state = valid_state("reviewer")
                state["findings"] = [finding(priority=priority)]
                state["review"].update(
                    {"reviewer": "independent-reviewer", "recommendation": "fail"}
                )
                rc, payload = self.evaluate(state)
                self.assertNotEqual(0, rc)
                self.assertEqual("fail", payload["recommendation"])
                self.assertEqual(["FIND-001"], payload["blocking_findings"])

    def test_invalid_critical_and_high_priorities_reject(self):
        cases = [("critical", "P1"), ("high", "P2"), ("high", "P3")]
        for severity, priority in cases:
            with self.subTest(severity=severity, priority=priority), tempfile.TemporaryDirectory() as raw:
                state = valid_state("reviewer")
                state["findings"] = [finding(severity=severity, priority=priority)]
                state["review"]["reviewer"] = "independent-reviewer"
                path = write_json(Path(raw), state)
                rc, payload = run_checker(["validate-state", str(path)])
                self.assertNotEqual(0, rc)

    def test_gate_outcomes_ignore_nonblocking_priority(self):
        for priority in ("P0", "P1", "P2", "P3"):
            with self.subTest(priority=priority):
                state = valid_state("reviewer")
                state["findings"] = [
                    finding(severity="medium", priority=priority, disposition="open")
                ]
                state["review"].update(
                    {
                        "reviewer": "independent-reviewer",
                        "recommendation": "conditional",
                    }
                )
                rc, payload = self.evaluate(state)
                self.assertEqual(0, rc, payload)
                self.assertEqual("conditional", payload["recommendation"])

    def test_dispositions_and_gate_results(self):
        empty = valid_state("reviewer")
        empty["review"].update(
            {"reviewer": "independent-reviewer", "recommendation": "pass"}
        )
        self.assertEqual("pass", self.evaluate(empty)[1]["recommendation"])

        resolved = valid_state("reviewer")
        resolved["evidence"] = [
            {
                "id": "EVID-RES",
                "claim": "Finding fixed.",
                "source": "rerun",
                "environment": "unit",
                "result": "pass",
                "observation": "fixed",
                "authors": ["validator"],
                "depends_on": [],
                "status": "current",
                "invalidation_revision": 0,
                "extensions": {},
            }
        ]
        item = finding(disposition="resolved")
        item["resolution_evidence_ids"] = ["EVID-RES"]
        resolved["findings"] = [item]
        resolved["review"].update(
            {"reviewer": "independent-reviewer", "recommendation": "pass"}
        )
        self.assertEqual("pass", self.evaluate(resolved)[1]["recommendation"])

        duplicate = valid_state("reviewer")
        canonical = finding("FIND-CAN", severity="medium", priority="P2", disposition="resolved")
        duplicate["evidence"] = copy.deepcopy(resolved["evidence"])
        canonical["resolution_evidence_ids"] = ["EVID-RES"]
        copy_finding = finding("FIND-DUP", severity="medium", priority="P3", disposition="duplicate")
        copy_finding.update(
            {
                "duplicate_of": "FIND-CAN",
                "original_evidence": ["original trace"],
                "rationale": "Same root cause.",
            }
        )
        duplicate["findings"] = [canonical, copy_finding]
        duplicate["review"].update(
            {"reviewer": "independent-reviewer", "recommendation": "pass"}
        )
        self.assertEqual("pass", self.evaluate(duplicate)[1]["recommendation"])

        withdrawn = valid_state("reviewer")
        item = finding(severity="medium", priority="P2", disposition="withdrawn")
        item.update(
            {
                "original_evidence": ["original trace"],
                "rationale": "Pinned evidence disproved the claim.",
            }
        )
        withdrawn["findings"] = [item]
        withdrawn["review"].update(
            {"reviewer": "independent-reviewer", "recommendation": "pass"}
        )
        self.assertEqual("pass", self.evaluate(withdrawn)[1]["recommendation"])

    def test_valid_and_invalid_risk_acceptance(self):
        state = valid_state("reviewer")
        app = approval("APP-RISK")
        app["action"] = "accept_finding:FIND-001"
        state["approvals"] = [app]
        item = finding(disposition="risk_accepted")
        item["approval_id"] = "APP-RISK"
        state["findings"] = [item]
        state["review"].update(
            {"reviewer": "independent-reviewer", "recommendation": "pass"}
        )
        rc, payload = self.evaluate(state)
        self.assertEqual(0, rc, payload)
        self.assertEqual("pass", payload["recommendation"])

        invalid = copy.deepcopy(state)
        invalid["approvals"][0]["verification"]["source_kind"] = "self_asserted"
        rc, payload = self.evaluate(invalid)
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["recommendation"])


class RuntimeActivationTests(unittest.TestCase):
    def check_activation(self, state, role="implementation_engineer", task_id="TASK-001"):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            path = write_json(directory, state)
            return run_checker(
                [
                    "check-package",
                    "--root",
                    ".",
                    "--state",
                    str(path),
                    "--role",
                    role,
                    "--task-id",
                    task_id,
                    "--now",
                    "2030-06-01T00:00:00Z",
                ]
            )

    def test_valid_runtime_activation(self):
        rc, payload = self.check_activation(valid_state())
        self.assertEqual(0, rc, payload)
        self.assertEqual("pass", payload["static_package"])
        self.assertEqual("pass", payload["runtime_activation"])

    def test_missing_self_asserted_and_stale_activation(self):
        missing = valid_state()
        missing["permission_attestations"] = []
        self.assertEqual("unverified", self.check_activation(missing)[1]["runtime_activation"])

        for field, value in (("source_kind", "self_asserted"), ("status", "stale")):
            with self.subTest(field=field):
                state = valid_state()
                state["permission_attestations"][0][field] = value
                rc, payload = self.check_activation(state)
                self.assertNotEqual(0, rc)
                self.assertEqual("fail", payload["runtime_activation"])

    def test_unknown_provenance_is_unverified(self):
        state = valid_state()
        state["provenance"]["model"] = "unknown"
        rc, payload = self.check_activation(state)
        self.assertEqual(0, rc)
        self.assertEqual("unverified", payload["runtime_activation"])

    def test_wrong_task_is_unverified(self):
        _, payload = self.check_activation(valid_state(), task_id="TASK-OTHER")
        self.assertEqual("unverified", payload["runtime_activation"])

    def test_mismatched_provenance_digest_rejects(self):
        state = valid_state()
        state["permission_attestations"][0]["manual_digest"] = "1" * 64
        rc, payload = self.check_activation(state)
        self.assertNotEqual(
            0, rc, "attested package digests must bind to canonical state/package digests"
        )
        self.assertEqual("fail", payload["runtime_activation"])

    def test_excess_concurrency_rejects_activation(self):
        state = valid_state()
        state["permission_attestations"][0]["effective_permissions"]["max_concurrency"] = 5
        rc, payload = self.check_activation(state)
        self.assertNotEqual(0, rc, "runtime concurrency above configured four must reject")
        self.assertEqual("fail", payload["runtime_activation"])

    def test_broader_runtime_scope_rejects_activation(self):
        state = valid_state()
        state["permission_attestations"][0]["effective_permissions"][
            "writable_scopes"
        ] = ["."]
        rc, payload = self.check_activation(state)
        self.assertNotEqual(
            0, rc, "runtime activation must apply authority intersection, not defer it"
        )
        self.assertEqual("fail", payload["runtime_activation"])


class RiskAndTeamCompositionTests(unittest.TestCase):
    def test_consequence_rules_and_no_fold_are_normative(self):
        manual = (ROOT / "Agent.md").read_text(encoding="utf-8")
        self.assertIn("Keyword-only escalation", manual)
        self.assertIn("R0 no-delegation fast path", manual)
        self.assertIn("They are never folded into one another", manual)

    def test_r1_cannot_use_intake_complete_fast_path(self):
        state = valid_state()
        state["state"]["history"] = [
            {
                "revision": 1,
                "from": "intake",
                "to": "complete",
                "actor": "primary",
                "at": "2030-01-01T00:00:00Z",
                "reason": "invalid non-R0 shortcut",
                "evidence_ids": [],
            }
        ]
        state["state"].update({"revision": 1, "status": "complete"})
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload = run_checker(["validate-state", str(path)])
            self.assertNotEqual(0, rc)
            self.assertTrue(any("R0" in item for item in payload["errors"]))

    def test_keywords_alone_do_not_escalate_r0(self):
        state = copy.deepcopy(TEMPLATE)
        state["project"].update(
            {
                "goal": "Document authentication, production, and restricted-data terminology.",
                "risk_tier": "R0",
                "risk_rationale": "Documentation-only, local, reversible, and non-consequential.",
            }
        )
        state["state"].update(
            {
                "revision": 1,
                "status": "complete",
                "history": [
                    {
                        "revision": 1,
                        "from": "intake",
                        "to": "complete",
                        "actor": "primary",
                        "at": "2030-01-01T00:00:00Z",
                        "reason": "R0 keyword-only documentation fast path",
                        "evidence_ids": [],
                    }
                ],
            }
        )
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload = run_checker(["validate-state", str(path)])
            self.assertEqual(0, rc, payload)


if __name__ == "__main__":
    unittest.main()
