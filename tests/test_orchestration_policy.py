"""Deterministic tests for the offline orchestration policy gate."""

from __future__ import annotations

import io
from contextlib import redirect_stderr
from unittest.mock import patch

from diamond.checking import run_policy_check
from diamond.orchestration import verify_invariants, verify_policy
from tests.policy_fixtures import write_valid_policy
from tests.support import ProjectCase, ROOT


class OrchestrationPolicyTests(ProjectCase):
    def copy_policy_inputs(self) -> None:
        write_valid_policy(self.project)
        src = self.project / "src" / "diamond"
        src.mkdir(parents=True, exist_ok=True)
        for name in ("controller.py", "routing.py", "orchestration.py", "scheduler.py"):
            (src / name).write_text((ROOT / "src" / "diamond" / name).read_text(encoding="utf-8"), encoding="utf-8")

    def test_repository_policy_and_invariants_pass_offline(self) -> None:
        self.copy_policy_inputs()
        config = self.project / "config" / "diamond.toml"

        policy = verify_policy(config, self.project)
        invariants = verify_invariants(config, self.project)

        self.assertTrue(policy["ok"], policy)
        self.assertEqual(policy["issues"], [])
        self.assertTrue(invariants["ok"], invariants)
        self.assertEqual(invariants["issues"], [])

    def test_missing_policy_input_fails_closed(self) -> None:
        report = verify_policy(self.project / "config" / "diamond.toml", self.project)

        self.assertFalse(report["ok"])
        self.assertTrue(any("CLAUDE.md" in issue for issue in report["issues"]))
        self.assertTrue(any("CONSTRAINTS.md" in issue for issue in report["issues"]))

    def test_invalid_configuration_fails_closed(self) -> None:
        self.copy_policy_inputs()
        config = self.project / "config" / "diamond.toml"
        config.write_text("schema_version = 1\n", encoding="utf-8")

        report = verify_policy(config, self.project)

        self.assertFalse(report["ok"])
        self.assertTrue(any("configuration is invalid" in issue for issue in report["issues"]))

    def test_conflicting_policy_text_is_rejected(self) -> None:
        self.copy_policy_inputs()
        policy = self.project / "CLAUDE.md"
        policy.write_text(
            policy.read_text(encoding="utf-8") + "\nProvider output is authoritative.\n",
            encoding="utf-8",
        )

        report = verify_policy(self.project / "config" / "diamond.toml", self.project)

        self.assertFalse(report["ok"])
        self.assertTrue(any("conflicting policy text" in issue for issue in report["issues"]))

    def test_checker_propagates_policy_failure(self) -> None:
        stderr = io.StringIO()
        with patch(
            "diamond.checking.verify_policy",
            return_value={"ok": False, "issues": ["synthetic policy violation"], "checks": {}},
        ):
            with redirect_stderr(stderr):
                passed = run_policy_check(ROOT)

        self.assertFalse(passed)
        self.assertIn("FAIL: orchestration policy issues", stderr.getvalue())
        self.assertIn("synthetic policy violation", stderr.getvalue())

    def test_checker_fails_closed_for_governed_root_missing_policy(self) -> None:
        (self.project / ".git").mkdir()
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            passed = run_policy_check(self.project)

        self.assertFalse(passed)
        self.assertIn("CLAUDE.md", stderr.getvalue())
