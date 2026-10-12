#!/usr/bin/env python3
"""Hermetic rolling-upgrade gate oracle tests (#12200)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts" / "rolling_upgrade_oracle.py"
HISTORICAL = ROOT / "docs" / "log" / "10023" / "raw" / "historical" / "iperf.log"
OLD = "a" * 64
NEW = "b" * 64


def healthy_json_stream(duration=12.0, step=0.1, streams=4, dead_stream_after=None,
                        zero_windows=None):
    zero_windows = zero_windows or {}
    sockets = list(range(5, 5 + streams))
    events = [{"event": "start", "data": {"connected": [{"socket": s, "local_port": 40000 + s} for s in sockets]}}]
    t = 0.0
    while t < duration - 1e-9:
        end = min(round(t + step, 9), duration)
        rows = []
        for socket in sockets:
            if socket == 5 and dead_stream_after is not None and t >= dead_stream_after:
                continue
            bps = 0.0 if any(start <= t < stop for start, stop in zero_windows.get(socket, ())) else 250_000_000.0
            rows.append({"socket": socket, "start": t, "end": end, "bits_per_second": bps,
                         "bytes": bps * (end - t) / 8, "retransmits": 0})
        events.append({"event": "interval", "data": {"streams": rows,
                        "sum": {"start": t, "end": end,
                                "bits_per_second": sum(row["bits_per_second"] for row in rows)}}})
        t = round(end, 9)
    events.append({"event": "end", "data": {}})
    return "\n".join(json.dumps(event) for event in events) + "\n"


def evidence_files(root, evidence, *, started_at=1000.0, old=OLD, candidate=NEW, samples=None):
    log = root / "iperf.jsonl"
    log.write_text(evidence, encoding="utf-8")
    cuts = root / "cuts.log"
    cuts.write_text(
        "1001.0 event=cut_start node=1\n"
        "1002.0 event=cut_end node=1\n"
        "1006.0 event=cut_start node=0\n"
        "1007.0 event=cut_end node=0\n",
        encoding="utf-8",
    )
    sample_path = root / "versions.log"
    if samples is None:
        samples = [
            (1000.0, old, old),
            (1003.0, old, candidate),
            (1003.2, old, candidate),
            (1008.0, candidate, candidate),
        ]
    sample_path.write_text("".join(f"{t} {sha0} {sha1}\n" for t, sha0, sha1 in samples), encoding="utf-8")
    return log, cuts, sample_path


class RollingUpgradeOracleTests(unittest.TestCase):
    def run_oracle(self, evidence, *, streams=4, started_at=1000.0, old=OLD,
                   candidate=NEW, samples=None, cut_text=None, max_interval_sec=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log, cuts, version_samples = evidence_files(
                root, evidence, started_at=started_at, old=old,
                candidate=candidate, samples=samples,
            )
            if cut_text is not None:
                cuts.write_text(cut_text, encoding="utf-8")
            command = [
                sys.executable, str(ORACLE), "--evidence", str(log), "--cuts", str(cuts),
                "--samples", str(version_samples), "--started-at", str(started_at),
                "--expected-version", candidate, "--streams", str(streams),
            ]
            if max_interval_sec is not None:
                command.extend(["--max-interval-sec", str(max_interval_sec)])
            return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_healthy_two_cut_run_passes_version_and_each_cut_once(self):
        proc = self.run_oracle(healthy_json_stream(), max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.count("CUT 1 PASS"), 1)
        self.assertEqual(proc.stdout.count("CUT 2 PASS"), 1)
        self.assertIn("RUN PASS", proc.stdout)
        self.assertIn("mixed-version interval observed", proc.stdout)

    def test_off_grid_cut_timestamps_are_accepted(self):
        cuts = (
            "1001.03 event=cut_start node=1\n"
            "1002.03 event=cut_end node=1\n"
            "1006.03 event=cut_start node=0\n"
            "1007.03 event=cut_end node=0\n"
        )
        samples = [
            (1000.0, OLD, OLD),
            (1003.0, OLD, NEW),
            (1003.2, OLD, NEW),
            (1008.0, NEW, NEW),
        ]
        proc = self.run_oracle(
            healthy_json_stream(duration=12.0),
            cut_text=cuts,
            samples=samples,
            max_interval_sec=0.25,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("CUT 1 PASS", proc.stdout)
        self.assertIn("CUT 2 PASS", proc.stdout)

    def test_resume_at_2_9_seconds_passes_and_at_3_1_seconds_fails(self):
        below_deadline = self.run_oracle(
            healthy_json_stream(zero_windows={5: [(2.0, 4.9)]}),
            max_interval_sec=0.25,
        )
        beyond_deadline = self.run_oracle(
            healthy_json_stream(zero_windows={5: [(2.0, 5.1)]}),
            max_interval_sec=0.25,
        )
        self.assertEqual(
            below_deadline.returncode, 0, below_deadline.stdout + below_deadline.stderr
        )
        self.assertIn("CUT 1 PASS", below_deadline.stdout)
        self.assertIn("RUN PASS", below_deadline.stdout)
        self.assertEqual(
            beyond_deadline.returncode, 1, beyond_deadline.stdout + beyond_deadline.stderr
        )
        self.assertIn("CUT 1 FAIL stream 5 had a 3.10s", beyond_deadline.stdout)

    def test_zero_window_failure_keeps_cut_attribution(self):
        proc = self.run_oracle(
            healthy_json_stream(zero_windows={5: [(1.0, 4.0)]}),
            max_interval_sec=0.25,
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn(
            "CUT 1 FAIL stream 5 had a 3.00s zero-throughput interval window across cut",
            proc.stdout,
        )

    def test_run_rejects_blackout_outside_both_cut_windows(self):
        cuts = (
            "1001.0 event=cut_start node=1\n"
            "1002.0 event=cut_end node=1\n"
            "1016.0 event=cut_start node=0\n"
            "1017.0 event=cut_end node=0\n"
        )
        samples = [
            (1000.0, OLD, OLD),
            (1003.0, OLD, NEW),
            (1003.2, OLD, NEW),
            (1018.0, NEW, NEW),
        ]
        blackout = {5: [(7.0, 10.5)]}
        proc = self.run_oracle(
            healthy_json_stream(duration=22.0, zero_windows=blackout),
            cut_text=cuts,
            samples=samples,
            max_interval_sec=0.25,
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("CUT 1 PASS", proc.stdout)
        self.assertIn("CUT 2 PASS", proc.stdout)
        self.assertIn("RUN FAIL stream 5 had a 3.50s zero-throughput window", proc.stdout)


    def test_whole_run_rejects_blackout_after_second_cut(self):
        blackout = {socket: [(8.2, 11.4)] for socket in range(5, 9)}
        proc = self.run_oracle(healthy_json_stream(zero_windows=blackout), max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("RUN FAIL stream 5 had a 3.20s zero-throughput window", proc.stdout)

    def test_whole_run_rejects_blackout_between_cuts(self):
        blackout = {socket: [(2.5, 5.7)] for socket in range(5, 9)}
        proc = self.run_oracle(healthy_json_stream(zero_windows=blackout), max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("RUN FAIL stream 5 had a 3.20s zero-throughput window", proc.stdout)
    def test_stream_that_dies_at_cut_must_not_pass_on_sum_traffic(self):
        proc = self.run_oracle(
            healthy_json_stream(dead_stream_after=2.0), max_interval_sec=0.25
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("CUT 1 FAIL stream 5 did not resume", proc.stdout)
        self.assertIn("CUT 2 FAIL stream 5 has no interval evidence", proc.stdout)

    def test_sampling_blackout_before_cut_is_rejected(self):
        events = [json.loads(line) for line in healthy_json_stream().splitlines()]
        for event in events:
            if event.get("event") == "interval":
                interval_start = event["data"]["sum"]["start"]
                if 0.4 <= interval_start < 1.0:
                    event["data"]["streams"] = []
        evidence = "\n".join(json.dumps(event) for event in events) + "\n"
        proc = self.run_oracle(evidence, max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("CUT 1 FAIL stream 5 interval evidence has a sampling gap", proc.stdout)
        self.assertIn("CUT 2 PASS", proc.stdout)

    def test_noop_drain_same_candidate_sha_fails_version_assertion(self):
        samples = [
            (1000.0, OLD, OLD),
            (1003.0, OLD, OLD),
            (1003.2, OLD, OLD),
            (1008.0, OLD, OLD),
        ]
        proc = self.run_oracle(healthy_json_stream(), old=OLD, candidate=OLD, samples=samples, max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("VERSION FAIL no-op drain", proc.stdout)
        self.assertEqual(proc.stdout.count("CUT 1 PASS"), 1)
        self.assertEqual(proc.stdout.count("CUT 2 PASS"), 1)

    def test_historical_10261_stranded_stream_shape_fails_both_cut_cells(self):
        self.assertTrue(HISTORICAL.is_file())
        historical = HISTORICAL.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log, cuts, samples_path = evidence_files(root, historical, started_at=1000.0)
            cuts.write_text(
                "1015.0 event=cut_start node=1\n1016.0 event=cut_end node=1\n"
                "1028.0 event=cut_start node=0\n1029.0 event=cut_end node=0\n",
                encoding="utf-8",
            )
            samples_path.write_text(
                f"1000.0 {OLD} {OLD}\n1017.0 {OLD} {NEW}\n1017.2 {OLD} {NEW}\n"
                f"1030.0 {NEW} {NEW}\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ORACLE), "--evidence", str(log), "--cuts", str(cuts),
                 "--samples", str(samples_path), "--started-at", "1000.0",
                 "--expected-version", NEW, "--streams", "4"],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.count("CUT 1 FAIL"), 1)
        self.assertEqual(proc.stdout.count("CUT 2 FAIL"), 1)
        self.assertIn("#10261 shape", proc.stdout)

    def test_missing_cut_marker_is_unusable_evidence(self):
        proc = self.run_oracle(healthy_json_stream(), cut_text="1001.0 event=cut_start node=1\n")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("cut trace must contain one start/end pair", proc.stdout)

    def test_version_requires_two_mixed_version_samples(self):
        samples = [(1000.0, OLD, OLD), (1003.0, OLD, OLD), (1003.2, OLD, OLD),
                   (1008.0, NEW, NEW)]
        proc = self.run_oracle(healthy_json_stream(), samples=samples)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("VERSION FAIL no sampled mixed-version interval", proc.stdout)

    def test_candidate_sha_must_be_live_on_both_nodes_after_cuts(self):
        samples = [(1000.0, OLD, OLD), (1003.0, NEW, OLD), (1003.2, NEW, OLD),
                   (1008.0, OLD, NEW)]
        proc = self.run_oracle(healthy_json_stream(), samples=samples)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("VERSION FAIL node0 running-exe SHA did not change", proc.stdout)

    def test_version_samples_must_bracket_both_cuts(self):
        samples = [(1001.0, OLD, OLD), (1003.0, NEW, OLD), (1003.2, NEW, OLD),
                   (1008.0, NEW, NEW)]
        proc = self.run_oracle(healthy_json_stream(), samples=samples)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("VERSION FAIL version samples do not bracket", proc.stdout)

    def test_iperf_error_event_after_both_cuts_fails_cut_cells(self):
        evidence = healthy_json_stream() + json.dumps({"event": "error", "data": {"error": "late failure"}}) + "\n"
        proc = self.run_oracle(evidence)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("CUT 1 FAIL iperf error event", proc.stdout)
        self.assertIn("CUT 2 FAIL iperf error event", proc.stdout)

    def test_interval_wider_than_100_ms_sampling_limit_fails(self):
        proc = self.run_oracle(healthy_json_stream(step=0.3), max_interval_sec=0.25)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("CUT 1 FAIL stream 5 interval width 0.300s", proc.stdout)

    def test_mixed_version_samples_reject_excessive_gap(self):
        samples = [(1000.0, OLD, OLD), (1003.0, OLD, NEW), (1005.5, OLD, NEW),
                   (1008.0, NEW, NEW)]
        proc = self.run_oracle(healthy_json_stream(), samples=samples)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("VERSION FAIL mixed-version sampling has an unexplained interval gap", proc.stdout)

    def test_mixed_version_samples_must_span_minimum_interval(self):
        samples = [(1000.0, OLD, OLD), (1003.0, OLD, NEW), (1003.05, OLD, NEW),
                   (1008.0, NEW, NEW)]
        proc = self.run_oracle(healthy_json_stream(), samples=samples)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("VERSION FAIL mixed-version samples do not span", proc.stdout)

    def test_cut_cannot_start_before_client_started_at(self):
        cuts = ("999.5 event=cut_start node=1\n1002.0 event=cut_end node=1\n"
                "1006.0 event=cut_start node=0\n1007.0 event=cut_end node=0\n")
        proc = self.run_oracle(healthy_json_stream(), cut_text=cuts)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("invalid timestamps for node1 cut", proc.stdout)

    def test_missing_one_of_eight_streams_fails(self):
        proc = self.run_oracle(healthy_json_stream(streams=7), streams=8)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("only 7/8 expected streams", proc.stdout)
        self.assertIn("RUN FAIL stream evidence incomplete for whole-run continuity", proc.stdout)

    def test_zero_window_three_seconds_fails_but_2_9_seconds_passes(self):
        at_limit = self.run_oracle(
            healthy_json_stream(zero_windows={5: [(3.0, 6.0)]}), max_interval_sec=0.25
        )
        below_limit = self.run_oracle(
            healthy_json_stream(zero_windows={5: [(3.0, 5.9)]}), max_interval_sec=0.25
        )
        self.assertEqual(at_limit.returncode, 1, at_limit.stdout + at_limit.stderr)
        self.assertIn("RUN FAIL stream 5 had a 3.00s zero-throughput window", at_limit.stdout)
        self.assertEqual(below_limit.returncode, 0, below_limit.stdout + below_limit.stderr)
        self.assertIn("RUN PASS", below_limit.stdout)

    def test_mixed_version_must_be_on_node_named_by_first_cut(self):
        samples = [(1000.0, OLD, OLD), (1003.0, NEW, OLD), (1003.2, NEW, OLD),
                   (1008.0, NEW, NEW)]
        proc = self.run_oracle(healthy_json_stream(), samples=samples)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("VERSION FAIL no sampled mixed-version interval", proc.stdout)


if __name__ == "__main__":
    unittest.main()
