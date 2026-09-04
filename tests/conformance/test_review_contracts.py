"""Independent RV2 Reviewer-contract acceptance tests.

The protocol digest below is an independent literal trust anchor. Product and
frozen artifacts are never modified; mutation cases use temporary copies.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.conformance import test_contracts as base


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tools" / "meva_check.py"
SCHEMA = ROOT / "contracts" / "meva.schema.json"
REVIEW_PROTOCOL = ROOT / "tests/conformance/review_protocol.v1.json"
REVIEW_LOCK = ROOT / "tests/conformance/review_protocol.v1.sha256"
EXPECTED_REVIEW_PROTOCOL_DIGEST = (
    "bf9fbb45811e6edb7f1e796d53df564c1e57ae4330da659c6991e060510f02e1"
)
EXPECTED_ORIGINAL_PROTOCOL_DIGEST = (
    "444bf9b0db6cea89afda56781de2f8279250dc4024a9db982ab6cee7ac38472b"
)
EXPECTED_ORIGINAL_HARNESS_DIGEST = (
    "95fba374856aa37e02e907d5c141d70c3b643cc1a4789808fc67d2e72631292b"
)
NOW = "2030-06-01T00:00:00Z"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(directory: Path, value, name: str = "state.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def run_checker(args, root=ROOT):
    process = subprocess.run(
        [sys.executable, "-B", str(CHECKER)] + list(args),
        cwd=str(root),
        text=True,
        capture_output=True,
        check=False,
    )
    payload = None
    if process.stdout.strip().startswith("{"):
        payload = json.loads(process.stdout)
    return process.returncode, payload, process.stdout, process.stderr


def validate_state(state):
    with tempfile.TemporaryDirectory() as raw:
        path = write_json(Path(raw), state)
        return run_checker(["validate-state", str(path)])


def refresh_ticket_digest(state):
    task = state["tasks"][0]
    value = hashlib.sha256(
        json.dumps(task, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    state["provenance"]["ticket_digest"] = value
    state["permission_attestations"][0]["ticket_digest"] = value


def review_finding(disposition="open", severity="high", priority="P1"):
    return base.finding(
        finding_id="RV2-FIND-001",
        severity=severity,
        priority=priority,
        disposition=disposition,
    )


def exact_risk_state(non_waivable=False):
    state = base.valid_state("reviewer")
    finding = review_finding("risk_accepted")
    finding["approval_id"] = "RV2-APP-001"
    finding["extensions"] = {
        "finding_revision": 2,
        "waivability": "non_waivable" if non_waivable else "waivable",
        "required_controls": ["authorization"],
        "affected_operation": {
            "action_kind": "deploy_release",
            "structured_target": {"kind": "service", "id": "api"},
            "scope": ["service/api"],
            "environment": "staging",
            "limits": {"max_external_calls": 0},
        },
    }
    approval = base.approval("RV2-APP-001")
    approval["action"] = (
        "accept_finding:RV2-FIND-001"
        if non_waivable
        else "risk_accept_finding"
    )
    approval["extensions"] = {
        "finding_id": "RV2-FIND-001",
        "finding_revision": 2,
        "affected_operation": copy.deepcopy(
            finding["extensions"]["affected_operation"]
        ),
    }
    state["findings"] = [finding]
    state["approvals"] = [approval]
    state["review"].update(
        {"reviewer": "independent-reviewer", "recommendation": "pass"}
    )
    return state


def resolution_state():
    state = base.valid_state("reviewer")
    state["artifacts"] = [
        {
            "id": "RV2-ART-001",
            "location": "src/service.py",
            "digest": base.ZERO_DIGEST,
            "authors": ["implementation-owner"],
            "owner": "implementation_engineer",
            "depends_on": [],
            "status": "current",
            "extensions": {},
        }
    ]
    state["evidence"] = [
        {
            "id": "RV2-EVID-001",
            "claim": "The finding trigger and required action are covered.",
            "source": "independent rerun",
            "environment": "unit",
            "result": "pass",
            "observation": "current and passing",
            "authors": ["independent-validator"],
            "depends_on": ["RV2-ART-001"],
            "status": "current",
            "invalidation_revision": 0,
            "extensions": {
                "state_revision": 3,
                "coverage": {
                    "finding_id": "RV2-FIND-001",
                    "trigger": True,
                    "required_action": True,
                    "artifact_ids": ["RV2-ART-001"],
                    "environment": "unit",
                },
                "provenance_digest": base.ZERO_DIGEST,
            },
        }
    ]
    finding = review_finding("resolved")
    finding["resolution_evidence_ids"] = ["RV2-EVID-001"]
    state["findings"] = [finding]
    state["review"].update(
        {
            "reviewer": "independent-reviewer",
            "target_artifact_ids": ["RV2-ART-001"],
            "target_evidence_ids": ["RV2-EVID-001"],
            "recommendation": "pass",
        }
    )
    return state


def completion_state(include_gates=True):
    state = base.valid_state()
    state["tasks"][0]["status"] = "complete"
    state["state"] = {
        "revision": 6,
        "status": "complete",
        "current_invalidation_revision": 0,
        "updated_at": "2030-01-01T00:00:06Z",
        "history": [
            {
                "revision": index + 1,
                "from": source,
                "to": target,
                "actor": "primary",
                "at": "2030-01-01T00:00:0{}Z".format(index + 1),
                "reason": "accepted transition",
                "evidence_ids": [],
            }
            for index, (source, target) in enumerate(
                [
                    ("intake", "design"),
                    ("design", "ready"),
                    ("ready", "building"),
                    ("building", "validating"),
                    ("validating", "reviewing"),
                    ("reviewing", "complete"),
                ]
            )
        ],
    }
    state["review"].update(
        {"reviewer": "review-owner-1", "recommendation": "pass"}
    )
    if include_gates:
        state["evidence"] = [
            {
                "id": "RV2-EVID-VAL",
                "claim": "Validation gate evidence.",
                "source": "validator",
                "environment": "unit",
                "result": "pass",
                "observation": "current",
                "authors": ["validation-owner-1"],
                "depends_on": [],
                "status": "current",
                "invalidation_revision": 0,
                "extensions": {"state_revision": 6},
            },
            {
                "id": "RV2-EVID-REV",
                "claim": "Independent review evidence.",
                "source": "reviewer",
                "environment": "local",
                "result": "pass",
                "observation": "current",
                "authors": ["review-owner-1"],
                "depends_on": [],
                "status": "current",
                "invalidation_revision": 0,
                "extensions": {"state_revision": 6},
            },
        ]
        state["gates"] = [
            {
                "id": "RV2-GATE-VAL",
                "gate": "validation",
                "result": "pass",
                "evidence_ids": ["RV2-EVID-VAL"],
                "depends_on": [],
                "invalidation_revision": 0,
                "extensions": {"owner_instance_id": "validation-owner-1"},
            },
            {
                "id": "RV2-GATE-REV",
                "gate": "independent_review",
                "result": "pass",
                "evidence_ids": ["RV2-EVID-REV"],
                "depends_on": [],
                "invalidation_revision": 0,
                "extensions": {"owner_instance_id": "review-owner-1"},
            },
        ]
    return state


class RV2ProtocolAnchorTests(unittest.TestCase):
    def test_review_protocol_literal_digest_and_lock(self):
        self.assertEqual(EXPECTED_REVIEW_PROTOCOL_DIGEST, digest(REVIEW_PROTOCOL))
        self.assertEqual(
            EXPECTED_REVIEW_PROTOCOL_DIGEST,
            REVIEW_LOCK.read_text(encoding="utf-8").split()[0],
        )

    def test_protocol_and_lock_codrift_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            package = Path(raw) / "package"
            base.copy_package(package)
            protocol = package / "tests/conformance/review_protocol.v1.json"
            protocol.write_text(
                protocol.read_text(encoding="utf-8") + "\n", encoding="utf-8"
            )
            changed = digest(protocol)
            (package / "tests/conformance/review_protocol.v1.sha256").write_text(
                changed + "  review_protocol.v1.json\n", encoding="utf-8"
            )
            _, payload, _, _ = run_checker(
                ["check-package", "--root", str(package)]
            )
            self.assertEqual(
                "fail",
                payload["static_package"],
                "co-drift must fail against the embedded literal anchor",
            )


class RV2RiskAcceptanceTests(unittest.TestCase):
    def test_ac001_positive_exact_structured_risk_acceptance(self):
        rc, payload, _, _ = self._evaluate(exact_risk_state(False))
        self.assertEqual(0, rc, payload)
        self.assertEqual("pass", payload["recommendation"])

    def test_ac001_negative_nonwaivable_finding_rejects(self):
        rc, payload, _, _ = self._evaluate(exact_risk_state(True))
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["recommendation"])

    def _evaluate(self, state):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            return run_checker(
                ["evaluate-review", "--state", str(path), "--now", NOW]
            )


class RV2ResolutionEvidenceTests(unittest.TestCase):
    def test_ac002_positive_current_independent_resolution_evidence(self):
        rc, payload, _, _ = validate_state(resolution_state())
        self.assertEqual(0, rc, payload)

    def test_ac002_negative_missing_resolution_evidence_id_rejects(self):
        state = resolution_state()
        state["findings"][0]["resolution_evidence_ids"] = ["RV2-EVID-MISSING"]
        rc, payload, _, _ = validate_state(state)
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])

    def test_ac002_negative_remediation_author_evidence_rejects(self):
        state = resolution_state()
        state["evidence"][0]["authors"] = ["implementation_engineer"]
        rc, payload, _, _ = validate_state(state)
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])


class RV2LifecycleTests(unittest.TestCase):
    def test_ac003_positive_r1_current_validation_and_review_gates(self):
        rc, payload, _, _ = validate_state(completion_state(True))
        self.assertEqual(0, rc, payload)

    def test_ac003_negative_r1_completion_without_gates_rejects(self):
        rc, payload, _, _ = validate_state(completion_state(False))
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])


class RV2AtomicAccountingTests(unittest.TestCase):
    def test_ac004_positive_reserve_action_public_interface_exists(self):
        process = subprocess.run(
            [sys.executable, "-B", str(CHECKER), "reserve-action", "--help"],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, process.returncode, process.stderr)

    def test_ac004_positive_reconcile_action_public_interface_exists(self):
        process = subprocess.run(
            [sys.executable, "-B", str(CHECKER), "reconcile-action", "--help"],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, process.returncode, process.stderr)

    def test_ac004_negative_nan_json_rejects_at_parse(self):
        with tempfile.TemporaryDirectory() as raw:
            text = json.dumps(base.valid_state()).replace('"cost": 0', '"cost": NaN', 1)
            path = Path(raw) / "nan.json"
            path.write_text(text, encoding="utf-8")
            rc, payload, _, _ = run_checker(["validate-state", str(path)])
            self.assertNotEqual(0, rc)
            self.assertEqual("fail", payload["result"])

    def test_ac004_negative_increment_rejects(self):
        state = base.valid_state()
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload, _, _ = run_checker(
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
                    "ordinary",
                    "--path",
                    "src/service.py",
                    "--environment",
                    "local",
                    "--cost",
                    "-1",
                    "--now",
                    NOW,
                ]
            )
            self.assertNotEqual(0, rc)
            self.assertEqual("fail", payload["result"])

    def test_ac004_negative_write_without_structured_target_rejects(self):
        state = base.valid_state()
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload, _, _ = run_checker(
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
                    "ordinary",
                    "--environment",
                    "local",
                    "--now",
                    NOW,
                ]
            )
            self.assertNotEqual(0, rc)
            self.assertEqual("fail", payload["result"])

    def test_ac004_negative_action_kind_relabel_rejects(self):
        state = base.valid_state()
        state["tasks"][0]["accounting"] = base.accounting(100, 100)
        state["accounting"] = base.accounting(100, 100)
        state["tasks"][0]["extensions"]["trusted_capability_metadata"] = {
            "action": "edit_assigned_files",
            "effect": "project_write",
            "trusted_action_kind": "ordinary",
            "caller_label": "cleanup",
        }
        refresh_ticket_digest(state)
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload, _, _ = run_checker(
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
                    "cleanup",
                    "--path",
                    "src/service.py",
                    "--environment",
                    "local",
                    "--now",
                    NOW,
                ]
            )
            self.assertNotEqual(0, rc)
            self.assertEqual("fail", payload["result"])

    def test_ac004_negative_noncanonical_path_rejects(self):
        state = base.valid_state()
        state["tasks"][0]["writable_scope"] = ["src/./service"]
        rc, payload, _, _ = validate_state(state)
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])


class RV2InvalidationTests(unittest.TestCase):
    def test_ac005_positive_transitive_resolved_invalidation(self):
        state = base.LifecycleAndInvalidationTests().invalidation_state(True)
        rc, payload, _, _ = validate_state(state)
        self.assertEqual(0, rc, payload)

    def test_ac005_negative_provenance_change_without_closure_rejects(self):
        state = base.LifecycleAndInvalidationTests().invalidation_state(True)
        state["state"]["revision"] += 1
        state["provenance"]["manual_digest"] = "3" * 64
        rc, payload, _, _ = validate_state(state)
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])


class RV2OwnershipTests(unittest.TestCase):
    def test_ac006_positive_same_role_nonoverlapping_owner_instances(self):
        state = base.valid_state()
        state["tasks"][0]["extensions"]["owner_instance_id"] = "impl-owner-1"
        second = base.valid_task("implementation_engineer", "TASK-002")
        second["writable_scope"] = ["platform"]
        second["extensions"]["owner_instance_id"] = "impl-owner-2"
        state["tasks"].append(second)
        rc, payload, _, _ = validate_state(state)
        self.assertEqual(0, rc, payload)

    def test_ac006_negative_same_role_overlap_rejects(self):
        state = base.valid_state()
        state["tasks"][0]["extensions"]["owner_instance_id"] = "impl-owner-1"
        second = base.valid_task("implementation_engineer", "TASK-002")
        second["writable_scope"] = ["src/service"]
        second["extensions"]["owner_instance_id"] = "impl-owner-2"
        state["tasks"].append(second)
        rc, payload, _, _ = validate_state(state)
        self.assertNotEqual(0, rc)
        self.assertEqual("fail", payload["result"])

    def test_ac006_negative_empty_owner_instance_cannot_activate(self):
        required = base.SCHEMA["$defs"]["task"]["required"]
        self.assertNotIn(
            "owner_instance_id",
            required,
            "legacy contract-2.0 state must remain structurally parseable",
        )
        state = base.valid_state()
        self.assertNotIn("owner_instance_id", state["tasks"][0])
        state["tasks"][0]["extensions"]["owner_instance_id"] = ""
        refresh_ticket_digest(state)
        self.assertNotEqual(state, base.valid_state())
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            _, payload, _, _ = run_checker(
                [
                    "check-package",
                    "--root",
                    ".",
                    "--state",
                    str(path),
                    "--role",
                    "implementation_engineer",
                    "--task-id",
                    "TASK-001",
                    "--now",
                    NOW,
                ]
            )
            self.assertIn(payload["runtime_activation"], {"fail", "unverified"})
            self.assertTrue(
                any(
                    "owner" in item.lower()
                    and ("identity" in item.lower() or "instance" in item.lower())
                    for item in payload["activation_observations"]
                ),
                payload,
            )


class RV2PackageBindingTests(unittest.TestCase):
    def test_ac007_positive_all_artifacts_and_original_count_are_bound(self):
        protocol = json.loads(REVIEW_PROTOCOL.read_text(encoding="utf-8"))
        for relative in protocol["required_artifacts"].values():
            self.assertTrue((ROOT / relative).is_file(), relative)
        self.assertEqual(
            EXPECTED_ORIGINAL_PROTOCOL_DIGEST,
            digest(ROOT / "tests/conformance/protocol.v1.json"),
        )
        self.assertEqual(
            EXPECTED_ORIGINAL_HARNESS_DIGEST,
            digest(ROOT / "tests/conformance/test_contracts.py"),
        )
        self.assertEqual(
            43,
            unittest.defaultTestLoader.loadTestsFromModule(base).countTestCases(),
        )
        process = subprocess.run(
            [sys.executable, "-B", str(CHECKER), "check-release", "--help"],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, process.returncode, process.stderr)


class RV2ProvenanceTests(unittest.TestCase):
    def test_ac008_positive_raw_and_prefixed_digests_compare_equal(self):
        canonical = getattr(base.CHECK, "_canonical_digest", None)
        self.assertTrue(callable(canonical), "checker needs canonical digest parser")
        self.assertEqual("a" * 64, canonical("a" * 64))
        self.assertEqual("a" * 64, canonical("sha256:" + "a" * 64))

    def test_ac008_negative_agents_digest_mismatch_rejects_activation(self):
        state = base.valid_state()
        state["provenance"]["artifact_digests"]["AGENTS.md"] = "3" * 64
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload, _, _ = run_checker(
                [
                    "check-package",
                    "--root",
                    ".",
                    "--state",
                    str(path),
                    "--role",
                    "implementation_engineer",
                    "--task-id",
                    "TASK-001",
                    "--now",
                    NOW,
                ]
            )
            self.assertNotEqual(0, rc)
            self.assertEqual("fail", payload["runtime_activation"])


class RV2OverlayTests(unittest.TestCase):
    def test_ac009_positive_unrelated_overlay_and_lower_cap(self):
        with tempfile.TemporaryDirectory() as raw:
            package = Path(raw) / "package"
            base.copy_package(package)
            config = package / ".codex/config.toml"
            original = config.read_text(encoding="utf-8")
            config.write_text(
                'model = "approved-model"\n[projects.demo]\ntrusted = true\n'
                + original.replace(
                    "max_concurrent_threads_per_session = 4",
                    "max_concurrent_threads_per_session = 2",
                ),
                encoding="utf-8",
            )
            before = config.read_bytes()
            _, payload, _, _ = run_checker(
                ["check-package", "--root", str(package)]
            )
            self.assertEqual("pass", payload["static_package"], payload)
            self.assertEqual(before, config.read_bytes())

    def test_ac009_negative_duplicate_required_key_rejects(self):
        with tempfile.TemporaryDirectory() as raw:
            package = Path(raw) / "package"
            base.copy_package(package)
            config = package / ".codex/config.toml"
            config.write_text(
                config.read_text(encoding="utf-8") + "\nenabled = true\n",
                encoding="utf-8",
            )
            _, payload, _, _ = run_checker(
                ["check-package", "--root", str(package)]
            )
            self.assertEqual("fail", payload["static_package"])


class RV2ReadOnlyExternalTests(unittest.TestCase):
    def external_reviewer_state(self):
        state = base.valid_state("reviewer")
        state["tasks"][0]["accounting"]["budget"]["max_external_calls"] = 1
        state["tasks"][0]["extensions"].update(
            {
                "allow_external_calls": True,
                "external_effect": "read_only",
                "structured_external_targets": [
                    {"kind": "repository", "id": "example/project"}
                ],
            }
        )
        state["authority"]["extensions"].update(
            {"allow_external_calls": True, "external_effect": "read_only"}
        )
        state["permission_attestations"][0]["effective_permissions"][
            "external_calls"
        ] = True
        refresh_ticket_digest(state)
        return state

    def test_ac010_positive_budgeted_reviewer_external_read(self):
        state = self.external_reviewer_state()
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload, _, _ = run_checker(
                [
                    "check-package",
                    "--root",
                    ".",
                    "--state",
                    str(path),
                    "--role",
                    "reviewer",
                    "--task-id",
                    "TASK-001",
                    "--now",
                    NOW,
                ]
            )
            self.assertEqual(0, rc, payload)
            self.assertEqual("pass", payload["runtime_activation"])

    def test_ac010_negative_mutation_relabelled_as_inspect_rejects(self):
        state = self.external_reviewer_state()
        state["tasks"][0]["extensions"]["trusted_capability_metadata"] = {
            "effect": "external_mutation",
            "caller_label": "inspect",
        }
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload, _, _ = run_checker(
                [
                    "check-package",
                    "--root",
                    ".",
                    "--state",
                    str(path),
                    "--role",
                    "reviewer",
                    "--task-id",
                    "TASK-001",
                    "--now",
                    NOW,
                ]
            )
            self.assertNotEqual(0, rc)
            self.assertEqual("fail", payload["runtime_activation"])


class RV2FormalReviewTests(unittest.TestCase):
    def test_ac011_positive_advisory_review_is_nongating(self):
        state = base.valid_state("reviewer")
        state["review"].update(
            {
                "reviewer": "advisory-reviewer",
                "recommendation": "pass",
                "extensions": {"mode": "advisory", "gate_result_emitted": False},
            }
        )
        rc, payload, _, _ = validate_state(state)
        self.assertEqual(0, rc, payload)

    def test_ac011_negative_formal_review_without_runtime_proof_rejects(self):
        state = base.valid_state("reviewer")
        state["permission_attestations"] = []
        state["review"].update(
            {
                "reviewer": "formal-reviewer",
                "recommendation": "pass",
                "extensions": {"mode": "formal", "gate_result_emitted": True},
            }
        )
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(Path(raw), state)
            rc, payload, _, _ = run_checker(
                ["evaluate-review", "--state", str(path), "--now", NOW]
            )
            self.assertNotEqual(0, rc)
            self.assertEqual("fail", payload["recommendation"])


if __name__ == "__main__":
    unittest.main()
