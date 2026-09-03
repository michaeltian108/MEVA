import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from tests.conformance import test_contracts as base


ROOT = Path(__file__).resolve().parents[2]


def core_local_state():
    state = base.valid_state()
    state["project"]["risk_tier"] = "R0"
    state["project"]["data_classification"] = "internal"
    state["permission_attestations"] = []
    state["authority"].update(
        {
            "source": "current-user-thread",
            "source_kind": "trusted_external",
            "expires_at": "unknown",
            "extensions": {
                "external_effect": "none",
                "core_local_authority": True,
            },
        }
    )
    task = state["tasks"][0]
    task["risk_tier"] = "R0"
    task["accounting"]["budget"]["max_external_calls"] = 0
    state["accounting"]["budget"]["max_external_calls"] = 0
    task["extensions"]["trusted_capability_metadata"] = {
        "action": "edit_assigned_files",
        "trusted_action_kind": "ordinary",
        "effect": "project_write",
        "capability_id": "CAP-CORE-LOCAL-WRITE",
    }
    task["extensions"]["core_local_rollback"] = "restore_preimage"
    return state


def run_preflight(
    state,
    root,
    target="src/service.py",
    extra=None,
    role="implementation_engineer",
):
    state_path = base.write_json(root, state)
    target_path = root / target
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text("before\n", encoding="utf-8")
    target_digest = hashlib.sha256(target_path.read_bytes()).hexdigest()
    arguments = [
        "preflight",
        "--root",
        str(root),
        "--state",
        str(state_path),
        "--schema",
        str(base.SCHEMA_PATH),
        "--task-id",
        "TASK-001",
        "--role",
        role,
        "--action",
        "edit_assigned_files",
        "--action-kind",
        "ordinary",
        "--path",
        target,
        "--target-expected-digest",
        target_digest,
        "--environment",
        "local",
        "--now",
        "2030-06-01T00:00:00Z",
    ]
    if extra:
        arguments.extend(extra)
    return base.run_checker(arguments)


class CoreLocalActivationFallbackTests(unittest.TestCase):
    def test_missing_attestation_allows_only_bounded_core_local_write(self):
        with tempfile.TemporaryDirectory() as raw:
            rc, payload = run_preflight(core_local_state(), Path(raw))
        self.assertEqual(0, rc, payload)
        self.assertEqual("pass", payload["result"])
        self.assertEqual("core_local", payload["execution_mode"])
        self.assertTrue(payload["local_execution_eligible"])
        self.assertFalse(payload["authorizes_consequential_action"])
        self.assertEqual("unverified", payload["runtime_activation"])
        self.assertEqual(
            "current_human_plus_host_cas", payload["authorization_boundary"]
        )
        self.assertEqual(3, payload["local_action_binding"]["state_revision"])
        self.assertEqual("TASK-001", payload["local_action_binding"]["task_id"])
        self.assertEqual(
            payload["local_action_binding"]["target_expected_digest"],
            hashlib.sha256(b"before\n").hexdigest(),
        )
        self.assertTrue(
            any("activation is unverified" in item for item in payload["notices"])
        )

    def test_missing_session_marker_or_bad_preimage_denies(self):
        missing_marker = core_local_state()
        missing_marker["authority"]["extensions"].pop("core_local_authority")
        with tempfile.TemporaryDirectory() as raw:
            rc, payload = run_preflight(missing_marker, Path(raw))
        self.assertNotEqual(0, rc)
        self.assertEqual("unverified", payload["result"])
        self.assertFalse(payload["local_execution_eligible"])

        with tempfile.TemporaryDirectory() as raw:
            rc, payload = run_preflight(
                core_local_state(),
                Path(raw),
                extra=["--target-expected-digest", "f" * 64],
            )
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])
        self.assertFalse(payload["local_execution_eligible"])

    def test_stale_attestation_never_falls_back(self):
        state = core_local_state()
        attestation = base.valid_attestation()
        attestation["status"] = "stale"
        state["permission_attestations"] = [attestation]
        with tempfile.TemporaryDirectory() as raw:
            rc, payload = run_preflight(state, Path(raw))
        self.assertNotEqual(0, rc)
        self.assertIn(payload["result"], {"fail", "unverified"})
        self.assertEqual("denied", payload["execution_mode"])
        self.assertFalse(payload["local_execution_eligible"])

    def test_consequential_boundaries_never_use_core_local_fallback(self):
        cases = []

        r2 = core_local_state()
        r2["project"]["risk_tier"] = "R2"
        r2["tasks"][0]["risk_tier"] = "R2"
        cases.append(("r2", r2, []))

        r1 = core_local_state()
        r1["project"]["risk_tier"] = "R1"
        r1["tasks"][0]["risk_tier"] = "R1"
        cases.append(("r1", r1, []))

        external_capacity = core_local_state()
        external_capacity["accounting"]["budget"]["max_external_calls"] = 1
        external_capacity["tasks"][0]["accounting"]["budget"][
            "max_external_calls"
        ] = 1
        cases.append(("external_capacity", external_capacity, []))

        required_approval = core_local_state()
        required_approval["tasks"][0]["approvals_required"] = ["APP-MISSING"]
        cases.append(("required_approval", required_approval, []))

        physical = core_local_state()
        physical["project"]["physical_safety_tier"] = "E1"
        physical["tasks"][0]["physical_safety_tier"] = "E1"
        cases.append(("physical", physical, []))

        protected = core_local_state()
        protected["project"]["data_classification"] = "restricted"
        protected["tasks"][0]["data_classification"] = "restricted"
        cases.append(("protected", protected, []))

        for label, state, extra in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                rc, payload = run_preflight(state, Path(raw), extra=extra)
                self.assertNotEqual(0, rc)
                self.assertEqual("unverified", payload["result"])
                self.assertFalse(payload["local_execution_eligible"])

    def test_scope_escape_and_symlink_target_deny(self):
        state = core_local_state()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            rc, payload = run_preflight(state, root, target="other/service.py")
            self.assertNotEqual(0, rc)
            self.assertEqual("fail", payload["result"])

        if hasattr(Path, "symlink_to"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                state_path = base.write_json(root, state)
                source = root / "source.py"
                source.write_text("before\n", encoding="utf-8")
                target = root / "src" / "service.py"
                target.parent.mkdir(parents=True)
                target.symlink_to(source)
                digest = hashlib.sha256(source.read_bytes()).hexdigest()
                rc, payload = base.run_checker(
                    [
                        "preflight",
                        "--root",
                        str(root),
                        "--state",
                        str(state_path),
                        "--schema",
                        str(base.SCHEMA_PATH),
                        "--task-id",
                        "TASK-001",
                        "--role",
                        "implementation_engineer",
                        "--action",
                        "edit_assigned_files",
                        "--path",
                        "src/service.py",
                        "--target-expected-digest",
                        digest,
                        "--environment",
                        "local",
                        "--now",
                        "2030-06-01T00:00:00Z",
                    ]
                )
                self.assertNotEqual(0, rc)
                self.assertEqual("fail", payload["result"])

    def test_existing_attested_preflight_behavior_is_unchanged(self):
        state = copy.deepcopy(base.valid_state())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            rc, payload = run_preflight(state, root)
        self.assertEqual(0, rc, payload)
        self.assertEqual("attestation_present_preflight", payload["execution_mode"])
        self.assertFalse(payload["local_execution_eligible"])
        self.assertEqual("reserve-action", payload["authorization_boundary"])

    def test_trapped_primary_can_use_the_same_bounded_core_lane(self):
        state = core_local_state()
        state["tasks"][0]["accountable_owner"] = "meva_orchestrator"
        with tempfile.TemporaryDirectory() as raw:
            rc, payload = run_preflight(
                state,
                Path(raw),
                role="meva_orchestrator",
            )
        self.assertEqual(0, rc, payload)
        self.assertTrue(payload["local_execution_eligible"])
        self.assertEqual(
            "current_human_plus_host_cas", payload["authorization_boundary"]
        )
        self.assertEqual("unverified", payload["runtime_activation"])

    def test_new_file_and_metered_or_chained_work_deny(self):
        cases = [
            ["--target-expected-absent"],
            ["--cost", "0.01"],
            ["--wall-time-seconds", "1"],
            ["--action-chain-steps", "1"],
            ["--retry-count", "1"],
        ]
        for extra in cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as raw:
                rc, payload = run_preflight(
                    core_local_state(), Path(raw), extra=extra
                )
                self.assertNotEqual(0, rc)
                self.assertIn(payload["result"], {"fail", "unverified"})
                self.assertFalse(payload["local_execution_eligible"])

    def test_state_outside_root_denies(self):
        state = core_local_state()
        with tempfile.TemporaryDirectory() as raw_root, tempfile.TemporaryDirectory() as raw_state:
            root = Path(raw_root)
            state_path = base.write_json(Path(raw_state), state)
            target = root / "src" / "service.py"
            target.parent.mkdir(parents=True)
            target.write_text("before\n", encoding="utf-8")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            rc, payload = base.run_checker(
                [
                    "preflight",
                    "--root",
                    str(root),
                    "--state",
                    str(state_path),
                    "--schema",
                    str(base.SCHEMA_PATH),
                    "--task-id",
                    "TASK-001",
                    "--role",
                    "implementation_engineer",
                    "--action",
                    "edit_assigned_files",
                    "--path",
                    "src/service.py",
                    "--target-expected-digest",
                    digest,
                    "--environment",
                    "local",
                    "--now",
                    "2030-06-01T00:00:00Z",
                ]
            )
        self.assertNotEqual(0, rc)
        self.assertEqual("unverified", payload["result"])
        self.assertFalse(payload["local_execution_eligible"])


if __name__ == "__main__":
    unittest.main()
