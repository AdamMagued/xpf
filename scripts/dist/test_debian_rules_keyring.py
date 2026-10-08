#!/usr/bin/env python3
"""Behavior tests for debian/rules' archive-keyring package recipe."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "debian/rules"
PLACEHOLDER = b"PLACEHOLDER-xpf-archive-keyring\n"


def keyring_recipe():
    lines = RULES.read_text().splitlines()
    start = lines.index("\tinstall -d debian/xpf/usr/share/keyrings")
    end = next(i for i in range(start + 1, len(lines))
               if lines[i] == "\tfi")
    return "\n".join(lines[start:end + 1])


@unittest.skipUnless(shutil.which("make"), "make not installed")
class DebianRulesKeyringTests(unittest.TestCase):
    def run_recipe(self, extra_env=None, *, real_key=None):
        with tempfile.TemporaryDirectory(prefix="xpf-rules-keyring-") as tmp:
            root = Path(tmp)
            (root / "scripts/dist").mkdir(parents=True)
            (root / "scripts/dist/xpf-archive-keyring.asc.placeholder").write_bytes(
                PLACEHOLDER)
            if real_key is not None:
                (root / "scripts/dist/xpf-archive-keyring.asc").write_bytes(
                    real_key)
            makefile = root / "keyring.mk"
            makefile.write_text("all:\n" + keyring_recipe() + "\n")
            env = os.environ.copy()
            env.pop("XPF_RELEASE", None)
            env.pop("XPF_ALLOW_PLACEHOLDER_KEYRING", None)
            env.update(extra_env or {})
            result = subprocess.run(
                ["make", "--silent", "-f", str(makefile)], cwd=root, env=env,
                capture_output=True, text=True, check=False)
            installed = root / "debian/xpf/usr/share/keyrings/xpf-archive-keyring.asc"
            return result, installed.read_bytes() if installed.exists() else None

    def test_default_dev_build_warns_and_installs_placeholder(self):
        result, installed = self.run_recipe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WARNING:", result.stderr)
        self.assertIn("NOT publishable", result.stderr)
        self.assertEqual(installed, PLACEHOLDER)

    def test_explicit_dev_override_warns_and_installs_placeholder(self):
        result, installed = self.run_recipe(
            {"XPF_ALLOW_PLACEHOLDER_KEYRING": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("XPF_ALLOW_PLACEHOLDER_KEYRING=1", result.stderr)
        self.assertEqual(installed, PLACEHOLDER)

    def test_release_without_real_key_fails_even_with_dev_override(self):
        result, installed = self.run_recipe({
            "XPF_RELEASE": "1",
            "XPF_ALLOW_PLACEHOLDER_KEYRING": "1",
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("XPF_RELEASE=1", result.stderr)
        self.assertIsNone(installed)

    def test_release_with_real_key_installs_it(self):
        real = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nrelease fixture\n"
        result, installed = self.run_recipe({"XPF_RELEASE": "1"}, real_key=real)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(installed, real)
        self.assertNotIn("PLACEHOLDER", result.stderr)


if __name__ == "__main__":
    unittest.main()
