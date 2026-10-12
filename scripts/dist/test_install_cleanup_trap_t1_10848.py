#!/usr/bin/env python3
"""Shell-trap proof for psaab/xpf#10848 T1 (O5 code half).

Proves `scripts/dist/install.sh` installs `trap cleanup_on_fail EXIT` and
that the trap fires on failure: the source/pin written by this run are
removed when the installer does not finish.

`install.sh` is READ-ONLY here: tests source the real file with the
`XPF_INSTALL_SOURCE_ONLY=1` hook (same idiom as
`test_install_url_validate_9921.py`) and redirect `SRC`/`PIN`/`KEYRING`
into a temp dir, so no host path is touched.

Source refs at 4a17e0d29: `cleanup_on_fail` + `trap cleanup_on_fail EXIT`
(install.sh:85-150), `write_source` (:379-397), `write_channel_pin`
(:402-447), source-only hook (:533-540).

RED/GREEN: default run is GREEN (real trap verified). With
`T1_PROVE_RED=1` the harness strips the EXIT trap after sourcing —
simulating the trap-absent/broken pre-fix equivalent — and the firing
assertions FAIL (RED), proving the test can tell the difference.

Bounds: shell-trap behavior only. No anti-rollback floor, no Q1-Q4
enforcement, no APT resolver claims (those live in docs only).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_INSTALLSH = _DIST / "install.sh"

# Exact trap-install line the test pins against install.sh text.
_TRAP_LINE = "trap cleanup_on_fail EXIT"

# Set T1_PROVE_RED=1 to simulate the pre-fix equivalent (trap absent):
# the harness runs `trap - EXIT` after sourcing, and the trap-firing
# assertions below FAIL. Default (unset) verifies the real trap: GREEN.
_PROVE_RED = os.environ.get("T1_PROVE_RED") == "1"


def _run_sourced(body, tmpdir, extra_env=None):
    """Run `body` in a fresh sh sourcing the real install.sh (SOURCE_ONLY).

    Writes are live (XPF_DRY_RUN=0) but SRC/PIN/KEYRING are redirected
    into `tmpdir` by the caller body. Returns (rc, combined_output).
    """
    env = dict(os.environ)
    env.update({
        "XPF_INSTALL_SOURCE_ONLY": "1",
        "XPF_DRY_RUN": "0",
        "XPF_TEST_TMP": str(tmpdir),
        "XPF_TEST_URL": "https://example.invalid/apt",
        "XPF_TEST_CHANNEL": "stable",
    })
    env.pop("XPF_APT_BASE_URL", None)
    env.pop("XPF_CHANNEL", None)
    if extra_env:
        env.update(extra_env)
    script = f'. "$1"; {body}'
    p = subprocess.run(["sh", "-c", script, "sh", str(_INSTALLSH)],
                       capture_output=True, text=True, env=env, timeout=60)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _write_body(then, strip_trap):
    """Body: redirect targets to temp, run real writers, then `then`."""
    parts = [
        'SRC="$XPF_TEST_TMP/xpf.sources"',
        'PIN="$XPF_TEST_TMP/xpf-channel.pref"',
        'KEYRING="$XPF_TEST_TMP/xpf-archive-keyring.asc"',
        'XPF_APT_BASE_URL="$XPF_TEST_URL"',
        'CHANNEL="$XPF_TEST_CHANNEL"',
    ]
    if strip_trap:
        # Simulate the trap-absent/broken pre-fix equivalent.
        parts.append("trap - EXIT")
    parts += ["write_source", "write_channel_pin", then]
    return "; ".join(parts)


class TrapTextTests(unittest.TestCase):
    def test_trap_line_present_in_install_sh(self):
        text = _INSTALLSH.read_text()
        self.assertIn(_TRAP_LINE, text)
        self.assertIn("cleanup_on_fail() {", text)
        self.assertIn("SRC_WRITTEN=1", text)
        self.assertIn("PIN_WRITTEN=1", text)

    def test_trap_registered_after_source(self):
        with tempfile.TemporaryDirectory(
                prefix="t1-10848-trap-") as tmp:
            strip = "trap - EXIT; " if _PROVE_RED else ""
            rc, out = _run_sourced(f"{strip}trap", Path(tmp))
        self.assertEqual(rc, 0, out[-2000:])
        # The real sourced file must have the EXIT trap armed; with
        # T1_PROVE_RED=1 the trap was stripped, so this FAILS (RED).
        self.assertIn("cleanup_on_fail", out)


class TrapFiresTests(unittest.TestCase):
    def test_exit_trap_fires_cleanup_on_failure(self):
        with tempfile.TemporaryDirectory(
                prefix="t1-10848-fire-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            pin = tmpdir / "xpf-channel.pref"
            rc, out = _run_sourced(
                _write_body("false", strip_trap=_PROVE_RED), tmpdir)
            self.assertNotEqual(rc, 0, out[-2000:])
            # Writers ran (pre-cleanup proof): with the trap stripped
            # these still hold, isolating the RED to the firing asserts.
            self.assertIn("writing apt source", out)
            self.assertIn("wrote managed apt channel pin", out)
            # Trap-fired proof: with T1_PROVE_RED=1 the trap was
            # stripped, cleanup never ran, and these FAIL (RED).
            self.assertIn("install failed", out)
            self.assertIn("removing", out)
            self.assertFalse(src.exists(),
                             f"stale source left behind: {src}")
            self.assertFalse(pin.exists(),
                             f"stale pin left behind: {pin}")

    def test_without_trap_cleanup_does_not_fire_control(self):
        # Always-stripped control: proves the harness distinguishes
        # trap-armed (files removed) from trap-absent (files remain).
        # Passes in both modes; the RED signal comes from the test above.
        with tempfile.TemporaryDirectory(
                prefix="t1-10848-ctrl-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            pin = tmpdir / "xpf-channel.pref"
            rc, out = _run_sourced(
                _write_body("false", strip_trap=True), tmpdir)
            self.assertNotEqual(rc, 0, out[-2000:])
            self.assertIn("writing apt source", out)
            self.assertTrue(src.exists(), "control source missing")
            self.assertTrue(pin.exists(), "control pin missing")
            self.assertNotIn("install failed", out)

    def test_no_cleanup_on_success(self):
        with tempfile.TemporaryDirectory(
                prefix="t1-10848-ok-") as tmp:
            tmpdir = Path(tmp)
            src = tmpdir / "xpf.sources"
            pin = tmpdir / "xpf-channel.pref"
            rc, out = _run_sourced(
                _write_body("INSTALL_OK=1", strip_trap=_PROVE_RED),
                tmpdir)
            self.assertEqual(rc, 0, out[-2000:])
            self.assertTrue(src.exists(), "success run removed source")
            self.assertTrue(pin.exists(), "success run removed pin")
            self.assertNotIn("install failed", out)


if __name__ == "__main__":
    unittest.main()
