#!/usr/bin/env python3
"""Unit tests verifying safety preconditions and validation in postgres_recovery_drill.sh."""

import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRILL_SCRIPT = ROOT / "scripts" / "postgres_recovery_drill.sh"


class PostgresRecoveryDrillPreconditionsTest(unittest.TestCase):
    def run_drill(self, env: dict[str, str]) -> subprocess.CompletedProcess:
        # Run in clean env with only provided keys plus PATH
        run_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        run_env.update(env)
        return subprocess.run(
            ["sh", str(DRILL_SCRIPT)],
            cwd=ROOT,
            env=run_env,
            capture_output=True,
            text=True,
        )

    def test_fails_when_source_dsn_missing(self):
        res = self.run_drill({})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("ENUMSCAN_POSTGRES_DSN", res.stderr)

    def test_fails_when_recovery_dsn_missing(self):
        res = self.run_drill({"ENUMSCAN_POSTGRES_DSN": "postgres://localhost/primary"})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("ENUMSCAN_POSTGRES_RECOVERY_DSN", res.stderr)

    def test_fails_when_source_and_recovery_dsn_are_identical(self):
        dsn = "postgres://localhost/recovery_db"
        res = self.run_drill({
            "ENUMSCAN_POSTGRES_DSN": dsn,
            "ENUMSCAN_POSTGRES_RECOVERY_DSN": dsn,
        })
        self.assertEqual(res.returncode, 2)
        self.assertIn("source and recovery DSNs must differ", res.stderr)

    def test_fails_when_recovery_dsn_does_not_contain_recovery(self):
        res = self.run_drill({
            "ENUMSCAN_POSTGRES_DSN": "postgres://localhost/prod",
            "ENUMSCAN_POSTGRES_RECOVERY_DSN": "postgres://localhost/other_prod",
        })
        self.assertEqual(res.returncode, 2)
        self.assertIn("must identify a database containing 'recovery'", res.stderr)

    def test_fails_when_confirmation_env_is_missing(self):
        res = self.run_drill({
            "ENUMSCAN_POSTGRES_DSN": "postgres://localhost/prod",
            "ENUMSCAN_POSTGRES_RECOVERY_DSN": "postgres://localhost/prod_recovery",
        })
        self.assertEqual(res.returncode, 2)
        self.assertIn("RESTORE_ENUMSCAN_RECOVERY", res.stderr)


if __name__ == "__main__":
    unittest.main()
