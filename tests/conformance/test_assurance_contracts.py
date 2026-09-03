"""Frozen WP5 assurance addendum.

All mutations occur in temporary directories. Product files, canonical state,
upstream frozen protocols/harnesses, and final Validation reports are read-only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.conformance import test_contracts as base
from tests.conformance import test_review_contracts as rv2


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tools/meva_check.py"
SCHEMA = ROOT / "contracts/meva.schema.json"
PROTOCOL = ROOT / "tests/conformance/assurance_protocol.v1.json"
LOCK = ROOT / "tests/conformance/assurance_protocol.v1.sha256"
EXPECTED_ASSURANCE_PROTOCOL_DIGEST = (
    "07baa7f12b50155ba449532ce24bd49a3c009adc4f430425c73c88ca46aa8e15"
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
}
ORIGINAL_COMMAND = "python3 -B -m unittest -v tests.conformance.test_contracts"
RV2_COMMAND = (
    "python3 -B -m unittest -v tests.conformance.test_review_contracts"
)
ORIGINAL_RV2_COMMAND = (
    "python3 -B -m unittest -v tests.conformance.test_contracts "
    "tests.conformance.test_review_contracts"
)
ASSURANCE_COMMAND = (
    "python3 -B -m unittest -v tests.conformance.test_assurance_contracts"
)
ALL_COMMAND = (
    "python3 -B -m unittest -v tests.conformance.test_contracts "
    "tests.conformance.test_review_contracts "
    "tests.conformance.test_assurance_contracts"
)
APPROVAL_NOW = "2030-06-01T00:00:00Z"
ATOMIC_EXPIRY = "2030-12-01T00:00:00Z"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(directory, value, name="state.json"):
    path = Path(directory) / name
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return path


def run_checker(arguments, root=ROOT):
    checker = Path(root) / "tools/meva_check.py"
    process = subprocess.run(
        [sys.executable, "-B", str(checker)] + list(arguments),
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
        path = write_json(raw, state)
        return run_checker(["validate-state", str(path)])


def refresh_ticket_digest(state):
    task = state["tasks"][0]
    value = hashlib.sha256(
        json.dumps(
            task, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()
    state["provenance"]["ticket_digest"] = value
    for attestation in state["permission_attestations"]:
        if (
            attestation["role"] == task["accountable_owner"]
            and attestation["task_id"] == task["id"]
        ):
            attestation["ticket_digest"] = value


def formal_review_state():
    state = base.valid_state("reviewer")
    state["tasks"][0]["owner_instance_id"] = "formal-review-owner"
    refresh_ticket_digest(state)
    state["review"].update(
        {
            "reviewer": "formal-review-owner",
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
    return state


def evaluate_review(state, root=ROOT):
    with tempfile.TemporaryDirectory() as raw:
        path = write_json(raw, state)
        return run_checker(
            [
                "evaluate-review",
                "--state",
                str(path),
                "--root",
                str(root),
                "--now",
                APPROVAL_NOW,
            ],
            root=root,
        )


def approval_check(state, now):
    approval = state["approvals"][0]
    with tempfile.TemporaryDirectory() as raw:
        path = write_json(raw, state)
        arguments = [
            "verify-approval",
            "--state",
            str(path),
            "--approval-id",
            approval["approval_id"],
            "--action",
            approval["action"],
            "--environment",
            approval["environment"],
            "--limits-json",
            json.dumps(approval["limits"], sort_keys=True),
            "--now",
            now,
        ]
        for scope in approval["scope"]:
            arguments.extend(["--scope", scope])
        return run_checker(arguments)


def action_state(
    used_cost=0,
    action_kind="ordinary",
    effect="project_write",
    role="implementation_engineer",
):
    state = base.valid_state(role)
    task = state["tasks"][0]
    task["owner_instance_id"] = "assurance-owner"
    task["accounting"] = base.accounting(100, used_cost)
    state["accounting"] = base.accounting(100, used_cost)
    action = "inspect" if role in {"planner", "reviewer"} else "edit_assigned_files"
    target_path = None if effect == "external_read" else "Agent.md"
    task["extensions"]["trusted_capability_metadata"] = {
        "action": action,
        "trusted_action_kind": action_kind,
        "effect": effect,
        "capability_id": "CAP-WP5-001",
    }
    task["extensions"]["target_revision"] = state["state"]["revision"]
    if target_path is not None:
        task["writable_scope"] = [target_path]
        state["authority"]["scopes"] = [target_path]
        state["permission_attestations"][0]["effective_permissions"][
            "writable_scopes"
        ] = [target_path]
    refresh_ticket_digest(state)
    return state


def reviewer_external_state(effect="external_read"):
    state = rv2.RV2ReadOnlyExternalTests().external_reviewer_state()
    task = state["tasks"][0]
    task["owner_instance_id"] = "reviewer-external-owner"
    task["extensions"]["trusted_capability_metadata"] = {
        "action": "inspect",
        "trusted_action_kind": "ordinary",
        "effect": effect,
        "capability_id": "CAP-REVIEW-READ",
    }
    task["accounting"]["budget"]["max_external_calls"] = 2
    state["accounting"]["budget"]["max_external_calls"] = 2
    refresh_ticket_digest(state)
    return state


def cas(path):
    state = json.loads(Path(path).read_text(encoding="utf-8"))
    return (
        state["state"]["revision"],
        state["action_ledger"]["revision"],
        digest(path),
    )


def reserve_args(
    path,
    trusted_root,
    key,
    expected,
    cost=0,
    role="implementation_engineer",
    action="edit_assigned_files",
    kind="ordinary",
    effect="project_write",
    target_kind="task",
    target_id="TASK-001",
    target_path="Agent.md",
    target_revision=None,
    target_digest=None,
    external_calls=0,
    root=ROOT,
    expiry=ATOMIC_EXPIRY,
):
    state_revision, ledger_revision, state_digest = expected
    arguments = [
        "reserve-action",
        "--state",
        str(path),
        "--root",
        str(root),
        "--trusted-state-root",
        str(trusted_root),
        "--idempotency-key",
        key,
        "--task-id",
        "TASK-001",
        "--role",
        role,
        "--action",
        action,
        "--action-kind",
        kind,
        "--effect",
        effect,
        "--target-kind",
        target_kind,
        "--target-id",
        target_id,
        "--environment",
        "local",
        "--cost",
        str(cost),
        "--external-calls",
        str(external_calls),
        "--expected-state-revision",
        str(state_revision),
        "--expected-ledger-revision",
        str(ledger_revision),
        "--expected-state-digest",
        state_digest,
        "--expires-at",
        expiry,
    ]
    if target_path is not None:
        arguments.extend(["--path", target_path])
    if target_revision is not None:
        arguments.extend(
            ["--target-expected-revision", str(target_revision)]
        )
    if target_digest is not None:
        arguments.extend(["--target-expected-digest", target_digest])
    return arguments


def claim_args(path, trusted_root, token, expected, role="implementation_engineer",
               root=ROOT, diagnostic_now=None):
    state_revision, ledger_revision, state_digest = expected
    arguments = [
        "claim-action",
        "--state",
        str(path),
        "--root",
        str(root),
        "--trusted-state-root",
        str(trusted_root),
        "--task-id",
        "TASK-001",
        "--role",
        role,
        "--reservation-token",
        token,
        "--expected-state-revision",
        str(state_revision),
        "--expected-ledger-revision",
        str(ledger_revision),
        "--expected-state-digest",
        state_digest,
    ]
    if diagnostic_now is not None:
        arguments.extend(["--now", diagnostic_now])
    return arguments


def reconcile_args(
    path,
    trusted_root,
    token,
    reconciliation_id,
    expected,
    execution_status="succeeded",
    actual_cost=0,
    outcome_digest="a" * 64,
    role="implementation_engineer",
    root=ROOT,
):
    state_revision, ledger_revision, state_digest = expected
    return [
        "reconcile-action",
        "--state",
        str(path),
        "--root",
        str(root),
        "--trusted-state-root",
        str(trusted_root),
        "--task-id",
        "TASK-001",
        "--role",
        role,
        "--reservation-token",
        token,
        "--reconciliation-id",
        reconciliation_id,
        "--execution-status",
        execution_status,
        "--actual-cost",
        str(actual_cost),
        "--outcome-digest",
        outcome_digest,
        "--expected-state-revision",
        str(state_revision),
        "--expected-ledger-revision",
        str(ledger_revision),
        "--expected-state-digest",
        state_digest,
    ]


def assert_json_payload(testcase, result):
    testcase.assertIsNotNone(result[1], result[2] + result[3])
    return result[1]


def reserve_once(testcase, path, directory, key, **kwargs):
    result = run_checker(
        reserve_args(path, directory, key, cas(path), **kwargs),
        root=kwargs.get("root", ROOT),
    )
    payload = assert_json_payload(testcase, result)
    testcase.assertEqual(0, result[0], payload)
    testcase.assertEqual("pass", payload["result"])
    testcase.assertFalse(payload["authorizes_consequential_action"])
    return payload


def claim_once(testcase, path, directory, token, role="implementation_engineer",
               root=ROOT):
    result = run_checker(
        claim_args(path, directory, token, cas(path), role=role, root=root),
        root=root,
    )
    payload = assert_json_payload(testcase, result)
    testcase.assertEqual(0, result[0], payload)
    testcase.assertTrue(payload["authorizes_consequential_action"])
    return payload


def package_digest_map(root):
    candidates = [
        "AGENTS.md",
        "Agent.md",
        "README.md",
        ".codex/config.toml",
        ".codex/agents/implementation_engineer.toml",
        ".codex/agents/planner.toml",
        ".codex/agents/platform_engineer.toml",
        ".codex/agents/reviewer.toml",
        ".codex/agents/validation_engineer.toml",
        "contracts/meva.schema.json",
        "templates/project-state.json",
        "tools/meva_check.py",
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
    ]
    return {
        relative: digest(Path(root) / relative)
        for relative in candidates
        if (Path(root) / relative).is_file()
    }


def passing_run(command, count):
    return {
        "command": command,
        "exit_code": 0,
        "tests_run": count,
        "passed": count,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "duration_seconds": 1.0,
        "output_summary": "Ran {} tests in 1.000s\n\nOK".format(count),
        "conclusion": "pass",
    }


def prepare_truthful_release(package):
    digests = package_digest_map(package)
    original_path = package / "tests/conformance/validation-report.json"
    review_path = package / "tests/conformance/review-validation-report.json"
    assurance_path = package / "tests/conformance/assurance-validation-report.json"
    original = {
        "report_version": "1.0",
        "task_id": "WP5-VALIDATION",
        "protocol": {
            "path": "tests/conformance/protocol.v1.json",
            "sha256": digests["tests/conformance/protocol.v1.json"],
            "lock_verified": True,
            "status": "frozen",
        },
        "post_wp4": {
            "implementation_digests": {
                key: value
                for key, value in digests.items()
                if not key.startswith("tests/conformance/")
            },
            "suite": passing_run(ORIGINAL_COMMAND, 43),
            "conclusion": {
                "frozen_static_and_fixture_checks": "pass",
                "result": "pass",
            },
        },
        "validation_artifact_digests": {
            key: value
            for key, value in digests.items()
            if key.startswith("tests/conformance/")
        },
        "command_output": "Ran 43 tests in 1.000s\n\nOK",
        "conclusion": "pass",
    }
    review = {
        "report_version": "1.0",
        "task_id": "WP5-VALIDATION",
        "phase": "post-WP5",
        "digests": digests,
        "runs": {
            "original": passing_run(ORIGINAL_COMMAND, 43),
            "rv2": passing_run(RV2_COMMAND, 30),
            "combined": passing_run(ORIGINAL_RV2_COMMAND, 73),
        },
        "conclusion": {
            "original_regression_gate": "pass",
            "rv2_static_package": "pass",
            "overall": "pass",
            "statement": "All recorded commands and exact outputs pass.",
        },
    }
    assurance = {
        "report_version": "1.0",
        "task_id": "WP5-VALIDATION",
        "phase": "post-WP5",
        "digests": digests,
        "runs": {
            "assurance": passing_run(ASSURANCE_COMMAND, 38),
            "combined": passing_run(ALL_COMMAND, 111),
        },
        "conclusion": {
            "assurance_gate": "pass",
            "overall": "pass",
            "statement": "All 38 assurance and 111 combined tests pass.",
        },
    }
    original_path.write_text(
        json.dumps(original, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    review_path.write_text(
        json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    assurance_path.write_text(
        json.dumps(assurance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return original_path, review_path, assurance_path


def release_package():
    raw = tempfile.TemporaryDirectory()
    package = Path(raw.name) / "package"
    shutil.copytree(
        ROOT,
        package,
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".meva"),
    )
    prepare_truthful_release(package)
    return raw, package


class AssuranceProtocolAnchorTests(unittest.TestCase):
    def test_assurance_protocol_literal_digest_and_lock(self):
        self.assertEqual(EXPECTED_ASSURANCE_PROTOCOL_DIGEST, digest(PROTOCOL))
        self.assertEqual(
            EXPECTED_ASSURANCE_PROTOCOL_DIGEST,
            LOCK.read_text(encoding="utf-8").split()[0],
        )

    def test_upstream_protocols_and_harnesses_remain_frozen(self):
        for relative, expected in EXPECTED_UPSTREAM.items():
            with self.subTest(relative=relative):
                self.assertEqual(expected, digest(ROOT / relative))


class SemanticRiskAcceptanceTests(unittest.TestCase):
    def test_exact_structured_waivable_acceptance_passes(self):
        result = evaluate_review(rv2.exact_risk_state(False))
        payload = assert_json_payload(self, result)
        self.assertEqual(0, result[0], payload)
        self.assertEqual("pass", payload["recommendation"])

    def test_legacy_critical_safety_generic_or_revoked_rejects(self):
        for variant in ("generic", "revoked"):
            with self.subTest(variant=variant):
                state = base.valid_state("reviewer")
                finding = base.finding(
                    finding_id="SAFE-001",
                    severity="critical",
                    priority="P0",
                    disposition="risk_accepted",
                )
                finding["category"] = "safety"
                finding["approval_id"] = "APP-SAFE"
                approval = base.approval("APP-SAFE")
                approval["action"] = (
                    "deploy_release"
                    if variant == "generic"
                    else "accept_finding:SAFE-001"
                )
                if variant == "revoked":
                    approval["status"] = "revoked"
                state["findings"] = [finding]
                state["approvals"] = [approval]
                state["review"].update(
                    {"reviewer": "independent", "recommendation": "pass"}
                )
                result = evaluate_review(state)
                payload = assert_json_payload(self, result)
                self.assertNotEqual(0, result[0])
                self.assertEqual("fail", payload["recommendation"])

    def test_structured_high_missing_waivability_or_revision_rejects(self):
        for key in ("waivability", "finding_revision"):
            with self.subTest(missing=key):
                state = rv2.exact_risk_state(False)
                del state["findings"][0]["extensions"][key]
                result = evaluate_review(state)
                payload = assert_json_payload(self, result)
                self.assertNotEqual(0, result[0])
                self.assertEqual("fail", payload["recommendation"])


class SemanticResolutionTests(unittest.TestCase):
    def test_current_independent_real_artifact_resolution_passes(self):
        result = validate_state(rv2.resolution_state())
        payload = assert_json_payload(self, result)
        self.assertEqual(0, result[0], payload)

    def test_resolution_independence_coverage_and_legacy_ids_reject(self):
        cases = []
        authored = rv2.resolution_state()
        authored["evidence"][0]["authors"] = ["implementation-owner"]
        cases.append(("remediation_author", authored))
        missing_artifact = rv2.resolution_state()
        missing_artifact["evidence"][0]["extensions"]["coverage"][
            "artifact_ids"
        ] = ["MISSING-ARTIFACT"]
        cases.append(("missing_coverage_artifact", missing_artifact))
        legacy = base.valid_state("reviewer")
        finding = base.finding(
            finding_id="LEGACY-HIGH",
            severity="high",
            priority="P1",
            disposition="resolved",
        )
        finding["resolution_evidence_ids"] = ["MISSING-EVIDENCE"]
        legacy["findings"] = [finding]
        cases.append(("legacy_missing_evidence", legacy))
        for label, state in cases:
            with self.subTest(label=label):
                result = validate_state(state)
                payload = assert_json_payload(self, result)
                self.assertNotEqual(0, result[0])
                self.assertEqual("fail", payload["result"])


class SemanticLifecycleTests(unittest.TestCase):
    def test_exact_independent_completion_passes(self):
        result = validate_state(rv2.completion_state(True))
        payload = assert_json_payload(self, result)
        self.assertEqual(0, result[0], payload)

    def test_advisory_failing_or_implementation_authored_review_rejects(self):
        cases = []
        advisory = rv2.completion_state(True)
        advisory["review"]["extensions"] = {
            "mode": "advisory",
            "gate_result_emitted": False,
        }
        cases.append(("advisory", advisory))
        failing = rv2.completion_state(True)
        failing["review"]["recommendation"] = "fail"
        cases.append(("failing", failing))
        authored = rv2.completion_state(True)
        authored["evidence"][1]["authors"] = ["implementation_engineer"]
        cases.append(("implementation_authored", authored))
        for label, state in cases:
            with self.subTest(label=label):
                result = validate_state(state)
                payload = assert_json_payload(self, result)
                self.assertNotEqual(0, result[0])
                self.assertEqual("fail", payload["result"])


class SemanticFormalReviewTests(unittest.TestCase):
    def test_exact_formal_review_passes(self):
        result = evaluate_review(formal_review_state())
        payload = assert_json_payload(self, result)
        self.assertEqual(0, result[0], payload)
        self.assertEqual("pass", payload["recommendation"])
        self.assertTrue(payload.get("gate_eligible"))

    def test_unknown_mode_mismatched_binding_or_broader_capability_rejects(self):
        cases = []
        unknown = formal_review_state()
        unknown["review"]["extensions"]["mode"] = "mystery"
        cases.append(("unknown_mode", unknown))
        wrong_project = formal_review_state()
        wrong_project["permission_attestations"][0]["project_id"] = "other-project"
        cases.append(("wrong_project", wrong_project))
        wrong_task = formal_review_state()
        wrong_task["permission_attestations"][0]["task_id"] = "TASK-OTHER"
        cases.append(("wrong_task", wrong_task))
        broader = formal_review_state()
        broader["permission_attestations"][0]["effective_permissions"][
            "max_concurrency"
        ] = 5
        cases.append(("broader_capability", broader))
        for label, state in cases:
            with self.subTest(label=label):
                result = evaluate_review(state)
                payload = assert_json_payload(self, result)
                self.assertNotEqual(0, result[0])
                self.assertEqual("fail", payload["recommendation"])
                self.assertFalse(payload.get("gate_eligible", False))


class SemanticApprovalTests(unittest.TestCase):
    def test_approval_issued_exactly_at_use_passes(self):
        state = base.valid_state()
        approval = base.approval("APP-TIME")
        approval["issued_at"] = APPROVAL_NOW
        state["approvals"] = [approval]
        result = approval_check(state, APPROVAL_NOW)
        payload = assert_json_payload(self, result)
        self.assertEqual(0, result[0], payload)

    def test_future_issued_approval_rejects(self):
        state = base.valid_state()
        approval = base.approval("APP-FUTURE")
        approval["issued_at"] = "2030-06-01T00:00:01Z"
        state["approvals"] = [approval]
        result = approval_check(state, APPROVAL_NOW)
        payload = assert_json_payload(self, result)
        self.assertNotEqual(0, result[0])
        self.assertEqual("fail", payload["result"])


class SemanticReleaseTruthTests(unittest.TestCase):
    def test_truthful_three_report_release_passes(self):
        raw, package = release_package()
        try:
            result = run_checker(["check-release", "--root", str(package)], root=package)
            payload = assert_json_payload(self, result)
            self.assertEqual(0, result[0], payload)
            self.assertEqual("pass", payload["release_integrity"])
        finally:
            raw.cleanup()

    def test_false_original_command_output_or_conclusion_rejects(self):
        for field in ("command", "output_summary", "conclusion"):
            with self.subTest(field=field):
                raw, package = release_package()
                try:
                    path = package / "tests/conformance/validation-report.json"
                    report = json.loads(path.read_text(encoding="utf-8"))
                    if field == "command":
                        report["post_wp4"]["suite"]["command"] = "false"
                    elif field == "output_summary":
                        report["post_wp4"]["suite"][
                            "output_summary"
                        ] = "FAILED (failures=1)"
                    else:
                        report["post_wp4"]["conclusion"]["result"] = "fail"
                    path.write_text(
                        json.dumps(report, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    result = run_checker(
                        ["check-release", "--root", str(package)], root=package
                    )
                    payload = assert_json_payload(self, result)
                    self.assertNotEqual(0, result[0])
                    self.assertEqual("fail", payload["release_integrity"])
                finally:
                    raw.cleanup()

    def test_false_rv2_or_assurance_evidence_rejects(self):
        for report_name in (
            "review-validation-report.json",
            "assurance-validation-report.json",
        ):
            with self.subTest(report=report_name):
                raw, package = release_package()
                try:
                    path = package / "tests/conformance" / report_name
                    report = json.loads(path.read_text(encoding="utf-8"))
                    first_run = next(iter(report["runs"].values()))
                    first_run["output_summary"] = "FAILED (failures=1)"
                    report["conclusion"]["overall"] = "fail"
                    path.write_text(
                        json.dumps(report, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    result = run_checker(
                        ["check-release", "--root", str(package)], root=package
                    )
                    payload = assert_json_payload(self, result)
                    self.assertNotEqual(0, result[0])
                    self.assertEqual("fail", payload["release_integrity"])
                finally:
                    raw.cleanup()


def approval_invalidation_state(complete=True):
    state = base.valid_state()
    approval = base.approval("APP-INV")
    finding = base.finding(
        finding_id="FIND-INV",
        severity="high",
        priority="P1",
        disposition="risk_accepted",
    )
    finding["approval_id"] = "APP-INV"
    finding["extensions"] = {
        "finding_revision": 1,
        "waivability": "waivable",
        "required_controls": [],
        "affected_operation": {
            "action_kind": "deploy_release",
            "structured_target": {"kind": "service", "id": "api"},
            "scope": ["service/api"],
            "environment": "staging",
            "limits": {"max_external_calls": 0},
        },
    }
    approval["action"] = "risk_accept_finding"
    approval["extensions"] = {
        "finding_id": "FIND-INV",
        "finding_revision": 1,
        "affected_operation": copy.deepcopy(
            finding["extensions"]["affected_operation"]
        ),
    }
    state["approvals"] = [approval]
    state["findings"] = [finding]
    state["state"]["current_invalidation_revision"] = 1
    state["invalidations"] = [
        {
            "id": "INV-ASSURANCE",
            "revision": 1,
            "changed_ids": ["APP-INV"],
            "affected_artifact_ids": [],
            "affected_evidence_ids": [],
            "affected_gate_ids": [],
            "required_owners": [],
            "acknowledgements": [],
            "rerun_evidence_ids": [],
            "status": "open",
            "reason": "Approval changed.",
            "extensions": {
                "affected_approval_ids": ["APP-INV"],
                "affected_finding_ids": ["FIND-INV"] if complete else [],
                "affected_task_ids": [],
                "behavior_input_ids": ["approval:APP-INV"],
            },
        }
    ]
    return state


class SemanticInvalidationUniverseTests(unittest.TestCase):
    def test_complete_approval_finding_closure_passes(self):
        result = validate_state(approval_invalidation_state(True))
        payload = assert_json_payload(self, result)
        self.assertEqual(0, result[0], payload)

    def test_approval_or_task_provenance_omission_rejects(self):
        omitted_finding = approval_invalidation_state(False)
        omitted_task = base.valid_state()
        omitted_task["state"]["current_invalidation_revision"] = 1
        omitted_task["invalidations"] = [
            {
                "id": "INV-TASK",
                "revision": 1,
                "changed_ids": ["TASK-001"],
                "affected_artifact_ids": [],
                "affected_evidence_ids": [],
                "affected_gate_ids": [],
                "required_owners": [],
                "acknowledgements": [],
                "rerun_evidence_ids": [],
                "status": "open",
                "reason": "Ticket and provenance changed.",
                "extensions": {
                    "affected_task_ids": [],
                    "behavior_input_ids": [],
                },
            }
        ]
        for label, state in (
            ("omitted_finding", omitted_finding),
            ("omitted_task_provenance", omitted_task),
        ):
            with self.subTest(label=label):
                result = validate_state(state)
                payload = assert_json_payload(self, result)
                self.assertNotEqual(0, result[0])
                self.assertEqual("fail", payload["result"])


class AtomicAuthorizationTests(unittest.TestCase):
    def test_preflight_is_diagnostic_and_never_emits_token(self):
        state = action_state()
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, state)
            result = run_checker(
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
                    "Agent.md",
                    "--environment",
                    "local",
                ]
            )
            payload = assert_json_payload(self, result)
            self.assertEqual(0, result[0], payload)
            self.assertFalse(payload["authorizes_consequential_action"])
            self.assertNotIn("reservation_token", payload)

    def test_reserve_and_exact_replay_are_nonauthorizing(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            arguments = reserve_args(
                path, raw, "IDEM-REPLAY", cas(path), cost=1
            )
            first = run_checker(arguments)
            first_payload = assert_json_payload(self, first)
            self.assertEqual(0, first[0], first_payload)
            self.assertFalse(first_payload["authorizes_consequential_action"])
            before = path.read_bytes()
            replay = run_checker(arguments)
            replay_payload = assert_json_payload(self, replay)
            self.assertEqual(0, replay[0], replay_payload)
            self.assertTrue(replay_payload["replayed"])
            self.assertFalse(replay_payload["authorizes_consequential_action"])
            self.assertEqual(
                first_payload["reservation_token"],
                replay_payload["reservation_token"],
            )
            self.assertEqual(before, path.read_bytes())

    def test_first_claim_is_only_authorizing_transition(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            reservation = reserve_once(
                self, path, raw, "IDEM-FIRST-CLAIM", cost=1
            )
            claim = claim_once(
                self, path, raw, reservation["reservation_token"]
            )
            self.assertTrue(claim["authorizes_consequential_action"])
            state = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                "claimed", state["action_ledger"]["reservations"][0]["status"]
            )

    def test_second_or_lost_response_claim_never_reauthorizes(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            reservation = reserve_once(
                self, path, raw, "IDEM-SECOND-CLAIM", cost=1
            )
            claim_once(self, path, raw, reservation["reservation_token"])
            before = path.read_bytes()
            second = run_checker(
                claim_args(
                    path, raw, reservation["reservation_token"], cas(path)
                )
            )
            payload = assert_json_payload(self, second)
            self.assertFalse(payload.get("authorizes_consequential_action", False))
            self.assertEqual(before, path.read_bytes())

    def test_concurrent_claim_has_exactly_one_authorizing_winner(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            reservation = reserve_once(
                self, path, raw, "IDEM-CONCURRENT-CLAIM", cost=1
            )
            arguments = claim_args(
                path, raw, reservation["reservation_token"], cas(path)
            )
            command = [sys.executable, "-B", str(CHECKER)] + arguments
            processes = [
                subprocess.Popen(
                    command,
                    cwd=str(ROOT),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                for _ in range(2)
            ]
            outcomes = []
            for process in processes:
                stdout, stderr = process.communicate()
                payload = (
                    json.loads(stdout) if stdout.strip().startswith("{") else {}
                )
                outcomes.append((process.returncode, payload, stderr))
            authorizing = [
                item
                for item in outcomes
                if item[1].get("authorizes_consequential_action") is True
            ]
            self.assertEqual(1, len(authorizing), outcomes)
            for item in outcomes:
                if item not in authorizing:
                    self.assertFalse(
                        item[1].get("authorizes_consequential_action", False)
                    )


class AtomicCapacityTests(unittest.TestCase):
    def test_zero_cost_reservation_at_action_chain_limit_rejects(self):
        state = action_state()
        for accounting in (state["accounting"], state["tasks"][0]["accounting"]):
            accounting["usage"]["action_chain_steps"] = accounting["budget"][
                "max_action_chain_steps"
            ]
        refresh_ticket_digest(state)
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, state)
            result = run_checker(
                reserve_args(path, raw, "IDEM-CHAIN-FULL", cas(path), cost=0)
            )
            payload = assert_json_payload(self, result)
            self.assertNotEqual(0, result[0])
            self.assertFalse(payload.get("authorizes_consequential_action", False))
            self.assertNotIn("reservation_token", payload)

    def test_one_remaining_action_chain_step_reserves_once(self):
        state = action_state()
        for accounting in (state["accounting"], state["tasks"][0]["accounting"]):
            accounting["usage"]["action_chain_steps"] = (
                accounting["budget"]["max_action_chain_steps"] - 1
            )
            accounting["notified_at_70_percent"] = True
            accounting["reestimated_at_70_percent"] = True
        refresh_ticket_digest(state)
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, state)
            reserve_once(self, path, raw, "IDEM-CHAIN-LAST", cost=0)
            stored = json.loads(path.read_text(encoding="utf-8"))
            reservation = stored["action_ledger"]["reservations"][0]
            self.assertEqual(1, reservation["reserved"]["action_chain_steps"])

    def test_pending_reservations_enforce_100_percent_ordinary_stop(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state(80))
            reserve_once(self, path, raw, "IDEM-PENDING-ONE", cost=10)
            second = run_checker(
                reserve_args(
                    path, raw, "IDEM-PENDING-TWO", cas(path), cost=10
                )
            )
            payload = assert_json_payload(self, second)
            self.assertNotEqual(0, second[0])
            self.assertFalse(payload.get("authorizes_consequential_action", False))
            state = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(1, len(state["action_ledger"]["reservations"]))


class AtomicTargetTests(unittest.TestCase):
    def test_current_target_revision_and_digest_reserve(self):
        state = action_state()
        state["tasks"][0]["extensions"]["target_revision"] = 3
        refresh_ticket_digest(state)
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, state)
            reserve_once(
                self,
                path,
                raw,
                "IDEM-TARGET-CURRENT",
                cost=1,
                target_revision=3,
                target_digest=digest(ROOT / "Agent.md"),
            )

    def test_stale_target_revision_rejects_without_mutation(self):
        state = action_state()
        state["tasks"][0]["extensions"]["target_revision"] = 3
        refresh_ticket_digest(state)
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, state)
            before = path.read_bytes()
            result = run_checker(
                reserve_args(
                    path,
                    raw,
                    "IDEM-TARGET-STALE",
                    cas(path),
                    cost=1,
                    target_revision=2,
                )
            )
            payload = assert_json_payload(self, result)
            self.assertNotEqual(0, result[0])
            self.assertFalse(payload.get("authorizes_consequential_action", False))
            self.assertEqual(before, path.read_bytes())

    def test_symlink_target_escape_rejects(self):
        raw = tempfile.TemporaryDirectory()
        try:
            package = Path(raw.name) / "package"
            shutil.copytree(
                ROOT,
                package,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".meva"),
            )
            outside = Path(raw.name) / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            link = package / "src/escape"
            link.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(str(outside), str(link))
            state = action_state()
            task = state["tasks"][0]
            task["writable_scope"] = ["src"]
            state["authority"]["scopes"] = ["src"]
            state["permission_attestations"][0]["effective_permissions"][
                "writable_scopes"
            ] = ["src"]
            refresh_ticket_digest(state)
            path = write_json(package, state, "assurance-state.json")
            result = run_checker(
                reserve_args(
                    path,
                    package,
                    "IDEM-SYMLINK",
                    cas(path),
                    cost=1,
                    target_path="src/escape",
                    root=package,
                ),
                root=package,
            )
            payload = assert_json_payload(self, result)
            self.assertNotEqual(0, result[0])
            self.assertFalse(payload.get("authorizes_consequential_action", False))
        finally:
            raw.cleanup()


class AtomicReconciliationTests(unittest.TestCase):
    def _reserve_and_claim(self, path, raw, key, cost=1):
        reservation = reserve_once(self, path, raw, key, cost=cost)
        claim_once(self, path, raw, reservation["reservation_token"])
        return reservation["reservation_token"]

    def test_two_outstanding_claims_reconcile_without_lost_update(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            first = self._reserve_and_claim(path, raw, "IDEM-OUT-ONE")
            second = self._reserve_and_claim(path, raw, "IDEM-OUT-TWO")
            for index, token in enumerate((first, second), 1):
                result = run_checker(
                    reconcile_args(
                        path,
                        raw,
                        token,
                        "RECON-OUT-{}".format(index),
                        cas(path),
                        actual_cost=1,
                    )
                )
                payload = assert_json_payload(self, result)
                self.assertEqual(0, result[0], payload)
            state = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(2, state["accounting"]["usage"]["cost"])
            self.assertEqual(
                ["reconciled", "reconciled"],
                [
                    item["status"]
                    for item in state["action_ledger"]["reservations"]
                ],
            )

    def test_equivalent_fresh_attestation_does_not_strand_claim(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            token = self._reserve_and_claim(path, raw, "IDEM-ROTATE")
            state = json.loads(path.read_text(encoding="utf-8"))
            state["permission_attestations"][0]["id"] = "ATT-ROTATED"
            state["permission_attestations"][0][
                "observed_at"
            ] = "2030-02-01T00:00:00Z"
            state["state"]["revision"] += 1
            path.write_text(
                json.dumps(state, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = run_checker(
                reconcile_args(
                    path,
                    raw,
                    token,
                    "RECON-ROTATE",
                    cas(path),
                    actual_cost=1,
                )
            )
            payload = assert_json_payload(self, result)
            self.assertEqual(0, result[0], payload)

    def test_overrun_is_valid_durable_recovery_state(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            token = self._reserve_and_claim(path, raw, "IDEM-OVERRUN")
            result = run_checker(
                reconcile_args(
                    path,
                    raw,
                    token,
                    "RECON-OVERRUN",
                    cas(path),
                    actual_cost=2,
                )
            )
            payload = assert_json_payload(self, result)
            self.assertEqual(0, result[0], payload)
            self.assertTrue(payload["recovery_required"])
            validated = run_checker(["validate-state", str(path)])
            validated_payload = assert_json_payload(self, validated)
            self.assertEqual(0, validated[0], validated_payload)
            state = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(2, state["accounting"]["usage"]["cost"])
            self.assertEqual(
                "recovery_required",
                state["action_ledger"]["reservations"][0]["status"],
            )

    def test_reconciliation_exact_replay_and_divergence(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            token = self._reserve_and_claim(path, raw, "IDEM-RECON-REPLAY")
            arguments = reconcile_args(
                path,
                raw,
                token,
                "RECON-REPLAY",
                cas(path),
                actual_cost=1,
            )
            first = run_checker(arguments)
            first_payload = assert_json_payload(self, first)
            self.assertEqual(0, first[0], first_payload)
            before = path.read_bytes()
            replay = run_checker(arguments)
            replay_payload = assert_json_payload(self, replay)
            self.assertEqual(0, replay[0], replay_payload)
            self.assertTrue(replay_payload["replayed"])
            self.assertEqual(before, path.read_bytes())
            divergent = run_checker(
                reconcile_args(
                    path,
                    raw,
                    token,
                    "RECON-REPLAY",
                    cas(path),
                    actual_cost=0,
                )
            )
            divergent_payload = assert_json_payload(self, divergent)
            self.assertNotEqual(0, divergent[0])
            self.assertFalse(
                divergent_payload.get("authorizes_consequential_action", False)
            )
            self.assertEqual(before, path.read_bytes())


class AtomicExpiryAndExternalTests(unittest.TestCase):
    def test_reservation_expiry_cannot_exceed_authority_or_attestation(self):
        state = action_state()
        state["authority"]["expires_at"] = "2030-07-01T00:00:00Z"
        state["permission_attestations"][0][
            "expires_at"
        ] = "2030-07-01T00:00:00Z"
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, state)
            result = run_checker(
                reserve_args(
                    path,
                    raw,
                    "IDEM-LONG-EXPIRY",
                    cas(path),
                    cost=1,
                    expiry="2030-07-01T00:00:01Z",
                )
            )
            payload = assert_json_payload(self, result)
            self.assertNotEqual(0, result[0])
            self.assertFalse(payload.get("authorizes_consequential_action", False))

    def test_expired_or_time_overridden_claim_never_authorizes(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            reservation = reserve_once(
                self,
                path,
                raw,
                "IDEM-TIME-OVERRIDE",
                cost=1,
                expiry=ATOMIC_EXPIRY,
            )
            result = run_checker(
                claim_args(
                    path,
                    raw,
                    reservation["reservation_token"],
                    cas(path),
                    diagnostic_now="2020-01-01T00:00:00Z",
                )
            )
            payload = assert_json_payload(self, result)
            self.assertNotEqual(0, result[0])
            self.assertFalse(payload.get("authorizes_consequential_action", False))

    def test_reviewer_exact_external_read_reserves_and_claims(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, reviewer_external_state())
            reservation = reserve_once(
                self,
                path,
                raw,
                "IDEM-EXTERNAL-READ",
                role="reviewer",
                action="inspect",
                effect="external_read",
                target_kind="repository",
                target_id="example/project",
                target_path=None,
                external_calls=1,
            )
            claim = claim_once(
                self,
                path,
                raw,
                reservation["reservation_token"],
                role="reviewer",
            )
            self.assertTrue(claim["authorizes_consequential_action"])

    def test_external_mutation_relabelled_inspect_rejects(self):
        state = reviewer_external_state("external_mutation")
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, state)
            result = run_checker(
                reserve_args(
                    path,
                    raw,
                    "IDEM-EXTERNAL-MUTATION",
                    cas(path),
                    role="reviewer",
                    action="inspect",
                    effect="external_mutation",
                    target_kind="repository",
                    target_id="example/project",
                    target_path=None,
                    external_calls=1,
                )
            )
            payload = assert_json_payload(self, result)
            self.assertNotEqual(0, result[0])
            self.assertFalse(payload.get("authorizes_consequential_action", False))


class AtomicRecoveryTests(unittest.TestCase):
    def test_unknown_execution_is_charged_valid_recovery_and_blocks_completion(self):
        with tempfile.TemporaryDirectory() as raw:
            path = write_json(raw, action_state())
            reservation = reserve_once(
                self, path, raw, "IDEM-UNKNOWN", cost=2
            )
            claim_once(self, path, raw, reservation["reservation_token"])
            result = run_checker(
                reconcile_args(
                    path,
                    raw,
                    reservation["reservation_token"],
                    "RECON-UNKNOWN",
                    cas(path),
                    execution_status="unknown",
                    actual_cost=0,
                    outcome_digest="unknown",
                )
            )
            payload = assert_json_payload(self, result)
            self.assertEqual(0, result[0], payload)
            self.assertTrue(payload["recovery_required"])
            validated = run_checker(["validate-state", str(path)])
            validated_payload = assert_json_payload(self, validated)
            self.assertEqual(0, validated[0], validated_payload)
            state = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(2, state["accounting"]["usage"]["cost"])
            state["tasks"][0]["status"] = "complete"
            state["state"]["status"] = "complete"
            blocked = validate_state(state)
            blocked_payload = assert_json_payload(self, blocked)
            self.assertNotEqual(0, blocked[0])
            self.assertEqual("fail", blocked_payload["result"])


if __name__ == "__main__":
    unittest.main()
