"""Focused conformance tests for the compact response handoff envelope."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tools" / "meva_check.py"
SCHEMA = json.loads((ROOT / "contracts/meva.schema.json").read_text(encoding="utf-8"))
SPEC = importlib.util.spec_from_file_location("meva_check", CHECKER)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def handoff(role: str = "implementation_engineer", status: str = "complete") -> dict:
    value = {
        "contract_version": "2.0",
        "task_id": "TASK-001",
        "role": role,
        "status": status,
        "summary": "One precise outcome.",
        "changed": ["contracts/meva.schema.json"]
        if role == "implementation_engineer"
        else [],
        "refs": ["E-001"],
    }
    if status != "complete":
        value["open"] = "Resolve the remaining condition."
    return value


class CompactHandoffTests(unittest.TestCase):
    def errors(self, value: dict):
        return CHECK.validate_json_schema(
            value, SCHEMA["$defs"]["compactHandoff"], SCHEMA
        )

    def test_exact_shape_and_legacy_detail_rejects(self):
        value = handoff()
        self.assertEqual([], self.errors(value))
        self.assertTrue(self.errors({**value, "provenance": {}}))
        self.assertTrue(self.errors({**value, "extensions": {}}))

    def test_status_controls_one_actionable_open_condition(self):
        complete = handoff()
        self.assertEqual([], self.errors({**complete, "open": ""}))
        for status in ("partial", "blocked", "needs_human", "unverified"):
            with self.subTest(status=status):
                pending = handoff(status=status)
                self.assertEqual([], self.errors(pending))
                missing = dict(pending)
                del missing["open"]
                self.assertTrue(self.errors(missing))
                empty = dict(pending)
                empty["open"] = ""
                self.assertTrue(self.errors(empty))

    def test_bounds_and_read_only_roles(self):
        value = handoff()
        too_long = dict(value)
        too_long["summary"] = "x" * 241
        self.assertTrue(self.errors(too_long))
        too_many = dict(value)
        too_many["refs"] = ["R{}".format(index) for index in range(9)]
        self.assertTrue(self.errors(too_many))
        too_long_item = dict(value)
        too_long_item["changed"] = ["x" * 161]
        self.assertTrue(self.errors(too_long_item))
        for role in ("planner", "reviewer"):
            with self.subTest(role=role):
                read_only = handoff(role=role)
                self.assertEqual([], self.errors(read_only))
                read_only["changed"] = ["unexpected-change"]
                self.assertTrue(self.errors(read_only))

    def test_checker_enforces_hard_transport_limit(self):
        oversized = handoff()
        oversized["changed"] = ["x" * 160 for _ in range(8)]
        oversized["refs"] = ["R" * 160 for _ in range(8)]
        errors, _, size = CHECK.validate_handoff(oversized, SCHEMA)
        self.assertGreater(size, CHECK.HANDOFF_HARD_LIMIT_BYTES)
        self.assertTrue(any("hard compact limit" in item for item in errors))

        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "handoff.json"
            path.write_text(json.dumps(oversized), encoding="utf-8")
            process = subprocess.run(
                [sys.executable, str(CHECKER), "validate-handoff", str(path)],
                cwd=str(ROOT),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(0, process.returncode)
            result = json.loads(process.stdout)
            self.assertEqual("fail", result["result"])


if __name__ == "__main__":
    unittest.main()
