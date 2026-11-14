import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


class SyncToolboxTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.project = self.root / "project"
        self.buildbox = self.project / "buildbox"
        self.credentials = self.root / "home" / ".credentials"
        self.origin = self.root / "origin.git"
        self.source = self.root / "source"
        self.buildbox.mkdir(parents=True)
        self.credentials.mkdir(parents=True)
        source_buildbox = Path(__file__).parent
        for name in ("sync-toolbox.sh", "verify-toolbox.sh"):
            shutil.copy2(source_buildbox / name, self.buildbox / name)
        self.run_git("init", "--bare", str(self.origin), cwd=self.root)
        self.run_git("init", str(self.source), cwd=self.root)
        self.run_git("config", "user.email", "ci@example.com", cwd=self.source)
        self.run_git("config", "user.name", "CI", cwd=self.source)
        (self.source / "deploy-Beta.sh").write_text("printf 'approved\\n'\n")
        (self.source / "notify-ci-failure.sh").write_text("printf 'failed\\n'\n")
        (self.source / ".gitignore").write_text("rogue-helper\n")
        self.run_git("add", ".", cwd=self.source)
        self.run_git("commit", "-m", "Approved toolbox", cwd=self.source)
        self.approved_revision = self.run_git("rev-parse", "HEAD", cwd=self.source).stdout.strip()
        self.run_git("push", str(self.origin), "HEAD:master", cwd=self.source)
        self.environment = dict(os.environ)
        self.environment["HOME"] = str(self.root / "home")
        self.environment["PATH"] = f"{self.environment['PATH']}:{self.credentials}"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def run_git(self, *arguments, cwd):
        return subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True)

    def write_variables(self, revision=None):
        values = [f"deploy_repository={shlex.quote(str(self.origin))}"]
        if revision is not None:
            values.append(f"deploy_revision={shlex.quote(revision)}")
        (self.credentials / "variables.sh").write_text("\n".join(values) + "\n")

    def run_sync(self):
        return subprocess.run(
            ["bash", str(self.buildbox / "sync-toolbox.sh")],
            cwd=self.project,
            env=self.environment,
            capture_output=True,
            text=True,
        )

    def test_missing_revision_fails_before_checkout(self):
        self.write_variables()
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deploy_revision must be set", result.stderr)
        self.assertFalse((self.root / "deploy").exists())

    def test_mutable_revision_is_rejected(self):
        self.write_variables("master")
        result = self.run_sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("lowercase hexadecimal commit object ID", result.stderr)
        self.assertFalse((self.root / "deploy").exists())

    def test_exact_revision_is_used_after_branch_advances(self):
        (self.source / "deploy-Beta.sh").write_text("printf 'unreviewed\\n'\n")
        self.run_git("add", "deploy-Beta.sh", cwd=self.source)
        self.run_git("commit", "-m", "Advance mutable branch", cwd=self.source)
        self.run_git("push", str(self.origin), "HEAD:master", cwd=self.source)
        self.write_variables(self.approved_revision)
        result = self.run_sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        checked_out_revision = self.run_git("rev-parse", "HEAD", cwd=self.root / "deploy").stdout.strip()
        self.assertEqual(checked_out_revision, self.approved_revision)
        self.assertEqual((self.root / "deploy" / "deploy-Beta.sh").read_text(), "printf 'approved\\n'\n")
        self.assertIn(self.approved_revision, result.stdout)

    def test_existing_checkout_and_metadata_are_replaced(self):
        self.write_variables(self.approved_revision)
        first_result = self.run_sync()
        self.assertEqual(first_result.returncode, 0, first_result.stderr)
        deploy = self.root / "deploy"
        (deploy / "deploy-Beta.sh").write_text("printf 'modified\\n'\n")
        (deploy / "rogue-helper").write_text("printf 'rogue\\n'\n")
        hook_marker = self.root / "hook-ran"
        post_checkout_hook = deploy / ".git" / "hooks" / "post-checkout"
        post_checkout_hook.write_text(f"#!/bin/sh\nprintf stale > {shlex.quote(str(hook_marker))}\n")
        post_checkout_hook.chmod(0o755)
        second_result = self.run_sync()
        self.assertEqual(second_result.returncode, 0, second_result.stderr)
        self.assertEqual((deploy / "deploy-Beta.sh").read_text(), "printf 'approved\\n'\n")
        self.assertFalse((deploy / "rogue-helper").exists())
        self.assertFalse(hook_marker.exists())

    def test_verifier_rejects_modified_checkout(self):
        self.write_variables(self.approved_revision)
        sync_result = self.run_sync()
        self.assertEqual(sync_result.returncode, 0, sync_result.stderr)
        (self.root / "deploy" / "deploy-Beta.sh").write_text("printf 'modified\\n'\n")
        result = subprocess.run(
            ["sh", str(self.buildbox / "verify-toolbox.sh"), str(self.root / "deploy")],
            cwd=self.project,
            env=self.environment,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked changes", result.stderr)


if __name__ == "__main__":
    unittest.main()

