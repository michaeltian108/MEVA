"""Smoke tests for the public MEVA install and uninstall entry points."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ScriptSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name) / "local project"
        self.target.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_script(self, name: str, *arguments: str):
        result = subprocess.run(
            [str(ROOT / name), *arguments],
            cwd=str(ROOT), capture_output=True, text=True,
        )
        payload = (json.loads(result.stdout) if result.stdout.strip() else None)
        return result, payload

    def test_preview_is_read_only_and_excludes_archives(self):
        before = sorted(path.relative_to(self.target).as_posix()
                        for path in self.target.rglob("*"))

        result, payload = self.run_script("install.sh", "--preview", str(self.target))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(payload["preview"])
        self.assertIn("AGENTS.md", payload["changed"])
        self.assertFalse(any("archive" in item for item in payload["changed"]))
        after = sorted(path.relative_to(self.target).as_posix()
                       for path in self.target.rglob("*"))
        self.assertEqual(before, after)

    def test_install_is_idempotent_and_normal_uninstall_preserves_state(self):
        result, first = self.run_script("install.sh", str(self.target))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(first["noop"])

        result, second = self.run_script("install.sh", str(self.target))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(second["noop"])

        state = self.target / ".meva/state.json"
        state_body = json.loads(state.read_text(encoding="utf-8"))
        state_body["project"]["goal"] = "A user-owned beta goal."
        state.write_text(json.dumps(state_body, indent=2) + "\n", encoding="utf-8")

        result, removed = self.run_script("uninstall.sh", str(self.target))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(removed["noop"])
        self.assertTrue(state.is_file())
        self.assertFalse((self.target / ".meva/install-manifest.json").exists())
        self.assertEqual([".meva/state.json"], [
            path.relative_to(self.target).as_posix()
            for path in self.target.rglob("*") if path.is_file()
        ])

    def test_purge_removes_created_state(self):
        result, _ = self.run_script("install.sh", str(self.target))
        self.assertEqual(0, result.returncode, result.stderr)

        result, payload = self.run_script(
            "uninstall.sh", "--preview", "--purge-state", str(self.target))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(payload["preview"])
        self.assertIn(".meva/state.json", payload["changed"])
        self.assertTrue((self.target / ".meva/state.json").is_file())

        result, payload = self.run_script(
            "uninstall.sh", "--purge-state", str(self.target))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("purged", payload["state"])
        self.assertEqual([], list(self.target.iterdir()))

    def test_existing_bootstrap_files_are_preserved_and_reported(self):
        agents = self.target / "AGENTS.md"
        agents.write_text("# Existing project rules\n", encoding="utf-8")
        config_dir = self.target / ".codex"
        config_dir.mkdir()
        config = config_dir / "config.toml"
        config.write_text("[project]\nname = \"local\"\n", encoding="utf-8")

        result, payload = self.run_script("install.sh", str(self.target))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([".codex/config.toml", "AGENTS.md"],
                         payload["manual_merge"])
        self.assertEqual("# Existing project rules\n", agents.read_text())
        self.assertEqual("[project]\nname = \"local\"\n", config.read_text())

        result, _ = self.run_script("uninstall.sh", str(self.target))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(agents.is_file())
        self.assertTrue(config.is_file())
        self.assertTrue((self.target / ".meva/state.json").is_file())

    def test_conflict_fails_without_mutation(self):
        schema = self.target / "contracts"
        schema.mkdir()
        schema_file = schema / "meva.schema.json"
        schema_file.write_text("user content\n", encoding="utf-8")
        before = schema_file.read_bytes()

        result, payload = self.run_script("install.sh", str(self.target))

        self.assertEqual(2, result.returncode)
        self.assertIsNone(payload)
        self.assertIn("no changes made", result.stderr)
        self.assertEqual(before, schema_file.read_bytes())
        self.assertEqual([schema_file], [
            path for path in self.target.rglob("*") if path.is_file()
        ])


if __name__ == "__main__":
    unittest.main()
