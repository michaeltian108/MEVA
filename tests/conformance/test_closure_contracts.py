"""Frozen eight-case closure addendum.

Do not execute this module before the product candidate is frozen. All fixture
mutations occur in temporary copies; product, state, and prior evidence remain
read-only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.conformance import test_assurance_contracts as assurance
from tests.conformance import test_final_review_contracts as final_review


PROTOCOL = ROOT / "tests/conformance/closure_protocol.v1.json"
LOCK = ROOT / "tests/conformance/closure_protocol.v1.sha256"
FINAL_REPORT = ROOT / "tests/conformance/final-review-validation-report.json"
CLOSURE_REPORT = ROOT / "tests/conformance/closure-validation-report.json"
EXPECTED_PROTOCOL_DIGEST = (
    "8aac0c9a6cc32b850b9b8961f5c7a35a447c0da9c11d79333ca6f7f38faff719"
)
EXPECTED_FROZEN = {
    "tests/conformance/test_contracts.py":
        "95190be27f34dd6f0731ce0c30a6ff7b5a95f1a176b94b2f1069c5d92a14d8fb",
    "tests/conformance/test_review_contracts.py":
        "83e034831410bc910c28e4badce1aba802df84ad7e440fef36c9b4d00ea41726",
    "tests/conformance/test_assurance_contracts.py":
        "ee2544f8b6f4915e76cfc38bd749ba6cd6538dd4e419596c5d8e9d05eda7cf70",
    "tests/conformance/test_final_review_contracts.py":
        "3bdee70b3483f1f7fae2b0c06f229719e2fbd801e734229e60a7b3bf5892560a",
    "tests/conformance/final-review-validation-report.json":
        "2c73e72031c9f86323ed9975fea75819a7840009c8a151f49df297e3c3e1f0cc",
}
RAW_COMMAND = [
    "-m", "unittest", "-v",
    "tests.conformance.test_contracts",
    "tests.conformance.test_review_contracts",
    "tests.conformance.test_assurance_contracts",
]
CORRECTED_PRECLOSURE_COMMAND = [
    "tests/conformance/test_final_review_contracts.py",
    "--corrected-aggregate",
]


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def setUpModule():
    if _digest(PROTOCOL) != EXPECTED_PROTOCOL_DIGEST:
        raise AssertionError("closure protocol digest changed")
    if LOCK.read_text(encoding="utf-8").split()[0] != EXPECTED_PROTOCOL_DIGEST:
        raise AssertionError("closure protocol lock changed")
    for relative, expected in EXPECTED_FROZEN.items():
        if _digest(ROOT / relative) != expected:
            raise AssertionError("frozen upstream changed: " + relative)


def _run_python(arguments, root=ROOT):
    process = subprocess.run(
        [sys.executable, "-B"] + list(arguments),
        cwd=str(root),
        text=True,
        capture_output=True,
        check=False,
    )
    return process, process.stdout + process.stderr


def _raw_observation():
    process, output = _run_python(RAW_COMMAND)
    ran = re.search(r"Ran ([0-9]+) tests? in", output)
    failures = {
        class_id + "." + method_id
        for method_id, class_id in re.findall(
            r"^FAIL: ([^ ]+) \(([^)]+)\)$", output, re.MULTILINE
        )
    }
    errors = {
        class_id + "." + method_id
        for method_id, class_id in re.findall(
            r"^ERROR: ([^ ]+) \(([^)]+)\)$", output, re.MULTILINE
        )
    }
    return {
        "exit_code": process.returncode,
        "tests_run": int(ran.group(1)) if ran else -1,
        "failure_test_ids": failures,
        "error_test_ids": errors,
        "output": output,
    }


def _raw_is_exact(observation):
    return (
        observation["exit_code"] == 1
        and observation["tests_run"] == 111
        and observation["failure_test_ids"]
        == final_review.SUPERSEDED_TEST_IDS
        and observation["error_test_ids"] == set()
        and "FAILED (failures=3)" in observation["output"]
        and "skipped=" not in observation["output"]
    )


def _assert_corrected_preclosure(testcase):
    process, output = _run_python(CORRECTED_PRECLOSURE_COMMAND)
    testcase.assertEqual(0, process.returncode, output)
    testcase.assertIn("Ran 124 tests", output)
    testcase.assertRegex(output, r"\nOK\s*$")


def _check_release(root=ROOT):
    process, output = _run_python(
        ["tools/meva_check.py", "check-release", "--root", str(root)],
        root=root,
    )
    payload = json.loads(process.stdout) if process.stdout.strip() else {}
    return process, payload, output


def _temporary_package():
    raw = tempfile.TemporaryDirectory()
    package = Path(raw.name) / "package"
    shutil.copytree(
        ROOT,
        package,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
    )
    return raw, package


class ClosureReleaseTruthTests(unittest.TestCase):
    def test_unexpected_raw_or_stale_corrected_count_rejects(self):
        observed = _raw_observation()
        self.assertTrue(_raw_is_exact(observed), observed["output"])
        stale = copy.deepcopy(observed)
        stale["failure_test_ids"].add(
            "tests.conformance.test_assurance_contracts."
            "SemanticReleaseTruthTests.test_truthful_three_report_release_passes"
        )
        stale["output"] = "Ran 111 tests in 1.000s\n\nFAILED (failures=4)"
        self.assertFalse(_raw_is_exact(stale))

    def test_exact_counts_and_content_stable_release_pass(self):
        _assert_corrected_preclosure(self)
        before = _digest(FINAL_REPORT)
        process, payload, output = _check_release()
        self.assertEqual(0, process.returncode, output)
        self.assertEqual([], payload["errors"])
        self.assertEqual("pass", payload["release_integrity"])
        self.assertEqual(before, _digest(FINAL_REPORT))


class ClosureLifecycleLineageTests(unittest.TestCase):
    def test_post_validation_behavior_drift_rejects(self):
        raw, package = _temporary_package()
        try:
            state_path = package / ".meva/state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["provenance"]["config_digest"] = "0" * 64
            state_path.write_text(
                json.dumps(state, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            process, payload, output = _check_release(package)
            self.assertNotEqual(0, process.returncode, output)
            self.assertEqual("fail", payload["release_integrity"])
        finally:
            raw.cleanup()

    def test_review_only_monotonic_lineage_passes(self):
        process, payload, output = _check_release()
        self.assertEqual(0, process.returncode, output)
        self.assertEqual([], payload["errors"])
        self.assertEqual("pass", payload["release_integrity"])


def _embodied_state(tier):
    state = final_review._embodied_completion_state()
    state["project"]["physical_safety_tier"] = tier
    state["tasks"][0]["physical_safety_tier"] = tier
    assurance.refresh_ticket_digest(state)
    final_review._bind_task_attestation_digest(state, "TASK-REVIEW")
    return state


class ClosureEmbodiedSafetyTests(unittest.TestCase):
    def test_e1_e2_missing_manual_control_rejects(self):
        required = (
            "heartbeat_timeout_evidence_id",
            "telemetry_evidence_id",
            "bounded_command_rate_hz",
            "hazard_controls",
            "dry_run_evidence_id",
            "stop_conditions",
            "incident_recovery",
            "deterministic_command_validation",
        )
        for tier in ("E1", "E2"):
            for missing in required:
                with self.subTest(tier=tier, missing=missing):
                    state = _embodied_state(tier)
                    del state["tasks"][0]["extensions"]["embodied_safety"][
                        missing
                    ]
                    assurance.refresh_ticket_digest(state)
                    final_review._bind_task_attestation_digest(
                        state, "TASK-REVIEW"
                    )
                    result = assurance.validate_state(state)
                    final_review._assert_rejects(self, result)

    def test_e1_e2_complete_manual_controls_pass(self):
        for tier in ("E1", "E2"):
            with self.subTest(tier=tier):
                result = assurance.validate_state(_embodied_state(tier))
                payload = final_review._payload(self, result)
                self.assertEqual(0, result[0], payload)
                self.assertEqual("pass", payload["result"])
                self.assertFalse(
                    payload.get("authorizes_consequential_action", False)
                )


def _two_artifact_review_state(target_both):
    state = final_review._formal_completion_state("R2")
    second = copy.deepcopy(
        next(item for item in state["artifacts"] if item["id"] == "FR-ART-TARGET")
    )
    second.update(
        {
            "id": "FR-ART-SECOND",
            "location": "README.md",
            "digest": _digest(ROOT / "README.md"),
        }
    )
    state["artifacts"].append(second)
    task = next(item for item in state["tasks"] if item["id"] == "TASK-REVIEW")
    task["inputs"].append({"artifact": "FR-ART-SECOND", "version": "current"})
    if target_both:
        state["review"]["target_artifact_ids"].append("FR-ART-SECOND")
    final_review._bind_task_attestation_digest(state, "TASK-REVIEW")
    return state


class ClosureFormalReviewCoverageTests(unittest.TestCase):
    def test_declared_artifact_omission_rejects(self):
        result = assurance.validate_state(_two_artifact_review_state(False))
        final_review._assert_rejects(self, result)

    def test_all_declared_artifacts_targeted_pass(self):
        result = assurance.validate_state(_two_artifact_review_state(True))
        payload = final_review._payload(self, result)
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
    prior = list(
        _flatten(
            loader.loadTestsFromNames(
                [
                    "tests.conformance.test_contracts",
                    "tests.conformance.test_review_contracts",
                    "tests.conformance.test_assurance_contracts",
                ]
            )
        )
    )
    selected = [
        test for test in prior
        if test.id() not in final_review.SUPERSEDED_TEST_IDS
    ]
    wp6 = list(
        _flatten(
            loader.loadTestsFromModule(
                sys.modules["tests.conformance.test_final_review_contracts"]
            )
        )
    )
    closure = list(_flatten(loader.loadTestsFromModule(sys.modules[__name__])))
    if len(prior) != 111 or len(selected) != 108:
        raise AssertionError("immutable prior or supersession count changed")
    if len(wp6) != 16 or len(closure) != 8:
        raise AssertionError("WP6 or closure count changed")
    return unittest.TestSuite(selected + wp6 + closure)


def _final_content_stable_release():
    if not CLOSURE_REPORT.is_file():
        raise AssertionError("closure report is required")
    before = _digest(CLOSURE_REPORT)
    raw = _raw_observation()
    if not _raw_is_exact(raw):
        raise AssertionError(raw["output"])
    outcome = unittest.TextTestRunner(verbosity=2).run(
        _corrected_aggregate_suite()
    )
    if not outcome.wasSuccessful():
        raise AssertionError("corrected 132-case aggregate failed")
    process, payload, output = _check_release()
    if (
        process.returncode != 0
        or payload.get("errors") != []
        or payload.get("release_integrity") != "pass"
    ):
        raise AssertionError(output)
    if before != _digest(CLOSURE_REPORT):
        raise AssertionError("closure report changed across release rerun")
    print(
        json.dumps(
            {
                "raw_prior": "108_plus_3_declared",
                "corrected_aggregate": "132_of_132",
                "report_sha256": before,
                "release_integrity": "pass",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    if sys.argv[1:] == ["--corrected-aggregate"]:
        result = unittest.TextTestRunner(verbosity=2).run(
            _corrected_aggregate_suite()
        )
        raise SystemExit(0 if result.wasSuccessful() else 1)
    if sys.argv[1:] == ["--final-content-stable-release"]:
        _final_content_stable_release()
        raise SystemExit(0)
    unittest.main()
