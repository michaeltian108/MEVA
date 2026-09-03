import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.conformance import test_assurance_contracts as assurance
from tests.conformance import test_contracts as base
from tests.conformance import test_review_contracts as rv2


PROTOCOL = ROOT / "tests/conformance/final_review_protocol.v1.json"
LOCK = ROOT / "tests/conformance/final_review_protocol.v1.sha256"
EXPECTED_PROTOCOL_DIGEST = (
    "b08e03780d2af87bf2e7f35765e2a941544e502f71f02f9b46545b738f81767a"
)
EXPECTED_UPSTREAM = {
    "tests/conformance/protocol.v1.json":
        "c529f598c93217d262b5de29b8af29044213ef065b438905532452eb42d97c4d",
    "tests/conformance/test_contracts.py":
        "95190be27f34dd6f0731ce0c30a6ff7b5a95f1a176b94b2f1069c5d92a14d8fb",
    "tests/conformance/review_protocol.v1.json":
        "32e5a7a9eb1695aacd0c3f1ed6a807f14aac35528a10c3435e897120aa9aed6d",
    "tests/conformance/test_review_contracts.py":
        "83e034831410bc910c28e4badce1aba802df84ad7e440fef36c9b4d00ea41726",
    "tests/conformance/assurance_protocol.v1.json":
        "07baa7f12b50155ba449532ce24bd49a3c009adc4f430425c73c88ca46aa8e15",
    "tests/conformance/test_assurance_contracts.py":
        "ee2544f8b6f4915e76cfc38bd749ba6cd6538dd4e419596c5d8e9d05eda7cf70",
}
SUPERSEDED_TEST_IDS = frozenset(
    {
        "tests.conformance.test_review_contracts.RV2LifecycleTests."
        "test_ac003_positive_r1_current_validation_and_review_gates",
        "tests.conformance.test_assurance_contracts.SemanticLifecycleTests."
        "test_exact_independent_completion_passes",
        "tests.conformance.test_assurance_contracts.SemanticFormalReviewTests."
        "test_exact_formal_review_passes",
    }
)


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def setUpModule():
    if _digest(PROTOCOL) != EXPECTED_PROTOCOL_DIGEST:
        raise AssertionError("final-review protocol digest changed")
    if LOCK.read_text(encoding="utf-8").split()[0] != EXPECTED_PROTOCOL_DIGEST:
        raise AssertionError("final-review protocol lock changed")
    for relative, expected in EXPECTED_UPSTREAM.items():
        if _digest(ROOT / relative) != expected:
            raise AssertionError("upstream frozen artifact changed: " + relative)


def _payload(testcase, result):
    testcase.assertIsNotNone(result[1], result[2] + result[3])
    return result[1]


def _assert_rejects(testcase, result):
    payload = _payload(testcase, result)
    testcase.assertNotEqual(0, result[0], payload)
    testcase.assertFalse(payload.get("authorizes_consequential_action", False))
    testcase.assertFalse(payload.get("gate_eligible", False))
    return payload


def _bind_task_attestation_digest(state, task_id):
    task = next(item for item in state["tasks"] if item["id"] == task_id)
    value = hashlib.sha256(
        json.dumps(
            task, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()
    for attestation in state["permission_attestations"]:
        if (
            attestation["role"] == task["accountable_owner"]
            and attestation["task_id"] == task["id"]
        ):
            attestation["ticket_digest"] = value


def _review_targets(state):
    artifact = {
        "id": "FR-ART-TARGET",
        "location": "Agent.md",
        "digest": _digest(ROOT / "Agent.md"),
        "authors": ["implementation-owner"],
        "owner": "implementation_engineer",
        "depends_on": [],
        "status": "current",
        "extensions": {},
    }
    evidence = {
        "id": "FR-EVID-TARGET",
        "claim": "The exact formal review target is current.",
        "source": "independent Validation fixture",
        "environment": "local",
        "result": "pass",
        "observation": "Current real target.",
        "authors": ["validation-owner"],
        "depends_on": ["FR-ART-TARGET"],
        "status": "current",
        "invalidation_revision":
            state["state"]["current_invalidation_revision"],
        "extensions": {"state_revision": state["state"]["revision"]},
    }
    state["artifacts"] = [
        item for item in state["artifacts"] if item["id"] != artifact["id"]
    ] + [artifact]
    state["evidence"] = [
        item for item in state["evidence"] if item["id"] != evidence["id"]
    ] + [evidence]
    state["review"]["target_artifact_ids"] = [artifact["id"]]
    state["review"]["target_evidence_ids"] = [evidence["id"]]
    return state


def _formal_completion_state(risk_tier):
    state = rv2.completion_state(True)
    state["project"]["risk_tier"] = risk_tier
    state["project"]["risk_rationale"] = (
        "Completion requires current independent formal review proof."
    )
    state["tasks"][0]["risk_tier"] = risk_tier
    state = _review_targets(state)
    state["review"].update(
        {
            "reviewer": "review-owner-1",
            "recommendation": "pass",
            "extensions": {
                "mode": "formal",
                "gate_result_emitted": True,
                "state_revision": state["state"]["revision"],
                "invalidation_revision":
                    state["state"]["current_invalidation_revision"],
            },
        }
    )
    review_task = base.valid_task("reviewer", "TASK-REVIEW")
    review_task["owner_instance_id"] = "review-owner-1"
    review_task["objective"] = "Formally review the exact completion targets."
    review_task["status"] = "complete"
    review_task["inputs"] = [
        {"artifact": "FR-ART-TARGET", "version": "current"}
    ]
    state["tasks"].append(review_task)
    attestation = base.valid_attestation("reviewer", "TASK-REVIEW")
    attestation["id"] = "ATT-FORMAL-REVIEW"
    attestation["project_id"] = state["project"]["id"]
    attestation["observed_at"] = "2030-06-01T00:00:00Z"
    attestation["effective_permissions"].update(
        {
            "writable_scopes": [],
            "actions": ["inspect"],
            "environments": ["local"],
            "external_calls": False,
        }
    )
    state["permission_attestations"].append(attestation)
    assurance.refresh_ticket_digest(state)
    _bind_task_attestation_digest(state, "TASK-REVIEW")
    return state


def _production_action_state(role="implementation_engineer"):
    state = assurance.action_state(role=role)
    task = state["tasks"][0]
    state["project"].update(
        {
            "risk_tier": "R2",
            "risk_rationale": "Production project write is consequential.",
            "target_environments": ["production"],
        }
    )
    task.update(
        {
            "risk_tier": "R2",
            "target_environment": "production",
            "allowed_actions": ["edit_assigned_files"],
            "writable_scope": ["Agent.md"],
            "approvals_required": ["APP-PRODUCTION-WRITE"],
        }
    )
    task["extensions"]["allowed_environments"] = ["production"]
    task["extensions"]["trusted_capability_metadata"].update(
        {
            "action": "edit_assigned_files",
            "trusted_action_kind": "ordinary",
            "effect": "project_write",
            "capability_id": "CAP-PRODUCTION-WRITE",
        }
    )
    state["authority"].update(
        {
            "allowed_actions": ["edit_assigned_files"],
            "scopes": ["Agent.md"],
            "environments": ["production"],
        }
    )
    attestation = state["permission_attestations"][0]
    attestation["effective_permissions"].update(
        {
            "writable_scopes": ["Agent.md"],
            "actions": ["edit_assigned_files"],
            "environments": ["production"],
        }
    )
    approval = base.approval("APP-PRODUCTION-WRITE")
    approval.update(
        {
            "action": "edit_assigned_files",
            "scope": ["Agent.md"],
            "environment": "production",
        }
    )
    state["approvals"] = [approval]
    assurance.refresh_ticket_digest(state)
    return state


def _production_reserve_args(path, trusted_root, key, expected, role):
    arguments = assurance.reserve_args(
        path,
        trusted_root,
        key,
        expected,
        cost=1,
        role=role,
        action="edit_assigned_files",
        effect="project_write",
        target_path="Agent.md",
    )
    environment_index = arguments.index("--environment") + 1
    arguments[environment_index] = "production"
    return arguments


def _ordered_attestation_state(newest_allows):
    state = assurance.action_state()
    permissive = copy.deepcopy(state["permission_attestations"][0])
    permissive.update(
        {
            "id": "ATT-NEWEST" if newest_allows else "ATT-OLDER",
            "observed_at":
                "2030-06-01T00:00:01Z"
                if newest_allows
                else "2030-06-01T00:00:00Z",
        }
    )
    denying = copy.deepcopy(permissive)
    denying.update(
        {
            "id": "ATT-OLDER" if newest_allows else "ATT-NEWEST",
            "observed_at":
                "2030-06-01T00:00:00Z"
                if newest_allows
                else "2030-06-01T00:00:01Z",
        }
    )
    denying["effective_permissions"]["writable_scopes"] = []
    denying["effective_permissions"]["actions"] = []
    state["permission_attestations"] = [permissive, denying]
    assurance.refresh_ticket_digest(state)
    return state


def _safety_evidence(evidence_id, claim):
    return {
        "id": evidence_id,
        "claim": claim,
        "source": "controlled-hardware safety verification",
        "environment": "controlled_hardware",
        "result": "pass",
        "observation": "Current and passing.",
        "authors": ["independent-safety-validator"],
        "depends_on": [],
        "status": "current",
        "invalidation_revision": 0,
        "extensions": {"state_revision": 6},
    }


def _embodied_completion_state():
    state = _formal_completion_state("R2")
    state["project"].update(
        {
            "physical_safety_tier": "E2",
            "target_environments": ["controlled_hardware"],
        }
    )
    task = state["tasks"][0]
    task.update(
        {
            "physical_safety_tier": "E2",
            "target_environment": "controlled_hardware",
            "approvals_required": ["APP-E2-START"],
        }
    )
    envelope = {
        "workspace": {
            "x_min_m": 0.0,
            "x_max_m": 1.0,
            "y_min_m": 0.0,
            "y_max_m": 1.0,
            "z_min_m": 0.0,
            "z_max_m": 0.5,
        },
        "max_speed_mps": 0.1,
        "max_force_newtons": 10.0,
        "max_duration_seconds": 60,
        "min_proximity_meters": 0.5,
    }
    task["extensions"]["embodied_safety"] = {
        "operator_id": "operator-001",
        "physical_envelope": envelope,
        "hardware_emergency_stop_evidence_id": "E2-HW-ESTOP",
        "software_emergency_stop_evidence_id": "E2-SW-ESTOP",
        "watchdog_evidence_id": "E2-WATCHDOG",
        "heartbeat_timeout_evidence_id": "E2-HEARTBEAT",
        "telemetry_evidence_id": "E2-TELEMETRY",
        "bounded_command_rate_hz": 5,
        "hazard_controls": [
            "collision_avoidance",
            "geofence",
            "joint_limits",
            "thermal_limits",
            "battery_limits",
            "communication_loss_stop",
        ],
        "dry_run_evidence_id": "E2-DRY-RUN",
        "start_approval_id": "APP-E2-START",
        "stop_conditions": [
            "unexpected_motion",
            "safety_anomaly",
            "sensor_integrity_failure",
            "lost_telemetry",
            "emergency_stop",
        ],
        "incident_recovery": "Stop without auto-resume and require investigation.",
        "deterministic_command_validation": True,
    }
    safety_records = [
        ("E2-HW-ESTOP", "Hardware emergency stop was tested."),
        ("E2-SW-ESTOP", "Software emergency stop was tested."),
        ("E2-WATCHDOG", "Watchdog and timeout behavior were tested."),
        ("E2-HEARTBEAT", "Heartbeat loss triggers deterministic stop."),
        ("E2-TELEMETRY", "Telemetry and stop visibility were tested."),
        ("E2-DRY-RUN", "A same-interface dry run passed."),
    ]
    state["evidence"].extend(
        _safety_evidence(evidence_id, claim)
        for evidence_id, claim in safety_records
    )
    for evidence in state["evidence"]:
        if evidence["id"] in {"RV2-EVID-VAL", "RV2-EVID-REV"}:
            evidence["environment"] = "controlled_hardware"
    approval = base.approval("APP-E2-START")
    approval.update(
        {
            "action": "start_controlled_hardware",
            "scope": ["cell/a"],
            "environment": "controlled_hardware",
        }
    )
    approval["limits"]["physical_envelope"] = copy.deepcopy(envelope)
    state["approvals"] = [approval]
    state["authority"]["environments"] = ["controlled_hardware"]
    for attestation in state["permission_attestations"]:
        attestation["effective_permissions"]["environments"] = [
            "controlled_hardware"
        ]
    assurance.refresh_ticket_digest(state)
    _bind_task_attestation_digest(state, "TASK-REVIEW")
    return state


def _provenance_invalidation_state():
    state = base.LifecycleAndInvalidationTests().invalidation_state(True)
    invalidation = state["invalidations"][0]
    invalidation.update(
        {
            "changed_ids": ["PROVENANCE-config_digest"],
            "reason": "The behavior-affecting configuration digest changed.",
            "extensions": {
                "behavior_input_ids": ["PROVENANCE-config_digest"],
                "provenance_fields": ["config_digest"],
            },
        }
    )
    state["artifacts"][0]["extensions"] = {
        "behavior_input_ids": ["PROVENANCE-config_digest"]
    }
    state["evidence"][0]["extensions"] = {
        "state_revision": state["state"]["revision"],
        "behavior_input_ids": ["PROVENANCE-config_digest"],
        "provenance_digest": state["provenance"]["config_digest"],
    }
    state["gates"][0]["extensions"] = {
        "state_revision": state["state"]["revision"],
        "behavior_input_ids": ["PROVENANCE-config_digest"],
    }
    return state


class FinalReviewLifecycleTests(unittest.TestCase):
    def test_completion_without_formal_runtime_proof_rejects(self):
        for risk_tier in ("R1", "R2"):
            with self.subTest(risk_tier=risk_tier):
                state = _formal_completion_state(risk_tier)
                state["review"]["extensions"] = {}
                state["permission_attestations"] = [
                    item
                    for item in state["permission_attestations"]
                    if item["role"] != "reviewer"
                ]
                result = assurance.validate_state(state)
                _assert_rejects(self, result)

    def test_completion_with_exact_formal_runtime_proof_passes(self):
        for risk_tier in ("R1", "R2"):
            with self.subTest(risk_tier=risk_tier):
                result = assurance.validate_state(
                    _formal_completion_state(risk_tier)
                )
                payload = _payload(self, result)
                self.assertEqual(0, result[0], payload)
                self.assertEqual("pass", payload["result"])


class FinalReviewTargetTests(unittest.TestCase):
    def test_formal_review_with_empty_targets_rejects(self):
        result = assurance.evaluate_review(assurance.formal_review_state())
        payload = _assert_rejects(self, result)
        self.assertEqual("fail", payload["recommendation"])

    def test_formal_review_with_exact_targets_passes(self):
        state = _review_targets(assurance.formal_review_state())
        result = assurance.evaluate_review(state)
        payload = _payload(self, result)
        self.assertEqual(0, result[0], payload)
        self.assertEqual("pass", payload["recommendation"])
        self.assertTrue(payload["gate_eligible"])


class FinalReviewProductionAuthorityTests(unittest.TestCase):
    def test_missing_required_approval_or_role_maximum_rejects(self):
        missing = _production_action_state()
        missing["approvals"] = []
        reviewer = _production_action_state("reviewer")
        for label, state, role in (
            ("missing_required_approval", missing, "implementation_engineer"),
            ("reviewer_role_maximum", reviewer, "reviewer"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                path = assurance.write_json(raw, state)
                result = assurance.run_checker(
                    _production_reserve_args(
                        path, raw, "WP6-PROD-" + label, assurance.cas(path), role
                    )
                )
                _assert_rejects(self, result)

    def test_exact_required_production_approval_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            path = assurance.write_json(raw, _production_action_state())
            result = assurance.run_checker(
                _production_reserve_args(
                    path,
                    raw,
                    "WP6-PROD-APPROVED",
                    assurance.cas(path),
                    "implementation_engineer",
                )
            )
            reservation = _payload(self, result)
            self.assertEqual(0, result[0], reservation)
            self.assertFalse(reservation["authorizes_consequential_action"])
            claim = assurance.run_checker(
                assurance.claim_args(
                    path,
                    raw,
                    reservation["reservation_token"],
                    assurance.cas(path),
                )
            )
            claim_payload = _payload(self, claim)
            self.assertEqual(0, claim[0], claim_payload)
            self.assertTrue(claim_payload["authorizes_consequential_action"])


class FinalReviewRiskAcceptanceTests(unittest.TestCase):
    def test_structured_high_revoked_approval_rejects(self):
        state = rv2.exact_risk_state(False)
        state["approvals"][0]["status"] = "revoked"
        result = assurance.evaluate_review(state)
        payload = _assert_rejects(self, result)
        self.assertEqual("fail", payload["recommendation"])

    def test_structured_high_active_approval_passes(self):
        result = assurance.evaluate_review(rv2.exact_risk_state(False))
        payload = _payload(self, result)
        self.assertEqual(0, result[0], payload)
        self.assertEqual("pass", payload["recommendation"])


class FinalReviewAttestationSelectionTests(unittest.TestCase):
    def test_older_permissive_newer_denial_rejects(self):
        with tempfile.TemporaryDirectory() as raw:
            path = assurance.write_json(raw, _ordered_attestation_state(False))
            result = assurance.run_checker(
                assurance.reserve_args(
                    path,
                    raw,
                    "WP6-ATTEST-DENY",
                    assurance.cas(path),
                    cost=1,
                )
            )
            _assert_rejects(self, result)

    def test_unique_newest_permissive_attestation_passes(self):
        with tempfile.TemporaryDirectory() as raw:
            path = assurance.write_json(raw, _ordered_attestation_state(True))
            result = assurance.run_checker(
                assurance.reserve_args(
                    path,
                    raw,
                    "WP6-ATTEST-ALLOW",
                    assurance.cas(path),
                    cost=1,
                )
            )
            reservation = _payload(self, result)
            self.assertEqual(0, result[0], reservation)
            self.assertEqual(
                "ATT-NEWEST", reservation["permission_attestation_id"]
            )
            claim = assurance.run_checker(
                assurance.claim_args(
                    path,
                    raw,
                    reservation["reservation_token"],
                    assurance.cas(path),
                )
            )
            claim_payload = _payload(self, claim)
            self.assertEqual(0, claim[0], claim_payload)
            self.assertTrue(claim_payload["authorizes_consequential_action"])


class FinalReviewExternalAccountingTests(unittest.TestCase):
    def test_external_read_with_zero_reserved_calls_rejects(self):
        with tempfile.TemporaryDirectory() as raw:
            path = assurance.write_json(raw, assurance.reviewer_external_state())
            result = assurance.run_checker(
                assurance.reserve_args(
                    path,
                    raw,
                    "WP6-EXTERNAL-ZERO",
                    assurance.cas(path),
                    role="reviewer",
                    action="inspect",
                    effect="external_read",
                    target_kind="repository",
                    target_id="example/project",
                    target_path=None,
                    external_calls=0,
                )
            )
            _assert_rejects(self, result)

    def test_external_read_reserves_one_call_and_claims(self):
        with tempfile.TemporaryDirectory() as raw:
            path = assurance.write_json(raw, assurance.reviewer_external_state())
            result = assurance.run_checker(
                assurance.reserve_args(
                    path,
                    raw,
                    "WP6-EXTERNAL-ONE",
                    assurance.cas(path),
                    role="reviewer",
                    action="inspect",
                    effect="external_read",
                    target_kind="repository",
                    target_id="example/project",
                    target_path=None,
                    external_calls=1,
                )
            )
            reservation = _payload(self, result)
            self.assertEqual(0, result[0], reservation)
            stored = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                1,
                stored["action_ledger"]["reservations"][0]["reserved"][
                    "external_calls"
                ],
            )
            claim = assurance.run_checker(
                assurance.claim_args(
                    path,
                    raw,
                    reservation["reservation_token"],
                    assurance.cas(path),
                    role="reviewer",
                )
            )
            claim_payload = _payload(self, claim)
            self.assertEqual(0, claim[0], claim_payload)
            self.assertTrue(claim_payload["authorizes_consequential_action"])


class FinalReviewEmbodiedSafetyTests(unittest.TestCase):
    def test_e2_completion_missing_required_control_rejects(self):
        variants = (
            "operator_id",
            "physical_envelope",
            "hardware_emergency_stop_evidence_id",
            "software_emergency_stop_evidence_id",
            "watchdog_evidence_id",
            "start_approval_id",
        )
        for missing in variants:
            with self.subTest(missing=missing):
                state = _embodied_completion_state()
                del state["tasks"][0]["extensions"]["embodied_safety"][missing]
                if missing == "start_approval_id":
                    state["approvals"] = []
                assurance.refresh_ticket_digest(state)
                _bind_task_attestation_digest(state, "TASK-REVIEW")
                result = assurance.validate_state(state)
                _assert_rejects(self, result)

    def test_e2_completion_with_complete_controls_passes(self):
        result = assurance.validate_state(_embodied_completion_state())
        payload = _payload(self, result)
        self.assertEqual(0, result[0], payload)
        self.assertEqual("pass", payload["result"])


class FinalReviewProvenanceInvalidationTests(unittest.TestCase):
    def test_resolved_config_invalidation_without_evidence_or_gate_rejects(self):
        state = _provenance_invalidation_state()
        invalidation = state["invalidations"][0]
        invalidation["affected_evidence_ids"] = []
        invalidation["affected_gate_ids"] = []
        invalidation["rerun_evidence_ids"] = []
        result = assurance.validate_state(state)
        _assert_rejects(self, result)

    def test_resolved_config_invalidation_with_exact_closure_passes(self):
        result = assurance.validate_state(_provenance_invalidation_state())
        payload = _payload(self, result)
        self.assertEqual(0, result[0], payload)
        self.assertEqual("pass", payload["result"])


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


def _corrected_aggregate_suite():
    loader = unittest.defaultTestLoader
    prior = loader.loadTestsFromNames(
        [
            "tests.conformance.test_contracts",
            "tests.conformance.test_review_contracts",
            "tests.conformance.test_assurance_contracts",
        ]
    )
    prior_tests = list(_flatten(prior))
    selected = [
        test for test in prior_tests if test.id() not in SUPERSEDED_TEST_IDS
    ]
    excluded = {test.id() for test in prior_tests} - {
        test.id() for test in selected
    }
    if len(prior_tests) != 111:
        raise AssertionError("expected 111 immutable prior tests")
    if excluded != SUPERSEDED_TEST_IDS:
        raise AssertionError("superseded prior test inventory changed")
    new_tests = list(_flatten(loader.loadTestsFromModule(sys.modules[__name__])))
    if len(selected) != 108 or len(new_tests) != 16:
        raise AssertionError("corrected aggregate count changed")
    return unittest.TestSuite(selected + new_tests)


if __name__ == "__main__":
    if sys.argv[1:] == ["--corrected-aggregate"]:
        outcome = unittest.TextTestRunner(verbosity=2).run(
            _corrected_aggregate_suite()
        )
        raise SystemExit(0 if outcome.wasSuccessful() else 1)
    unittest.main()
