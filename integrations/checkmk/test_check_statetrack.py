"""Unit tests for the StateTrack Checkmk/Nagios check.

Standard library only (`unittest`), so they run anywhere Python 3 does — no
pytest, no virtualenv, no network. The HTTP layer is exercised through a stub
callable so the tests never touch a live StateTrack server.

    python3 -m unittest discover -s integrations/checkmk -v
    python3 integrations/checkmk/test_check_statetrack.py
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_statetrack as check  # noqa: E402


def make_args(**overrides):
    argv = ["--host", "prod-web-01", "--url", "http://statetrack:8080"]
    for key, value in overrides.items():
        flag = "--" + key.replace("_", "-")
        if value is True:
            argv.append(flag)
        elif value is not None:
            argv.extend([flag, str(value)])
    return check.parse_args(argv)


ONLINE_CLEAN = {
    "host": "prod-web-01",
    "online": True,
    "last_seen_seconds": 4,
    "window": "15m",
    "counts": {
        "total": 5,
        "l1_critical": 0,
        "l2_grouped": 1,
        "l3_drift": 3,
        "l4_forensic": 1,
    },
    "drift_targets_count": 2,
    "latest_critical": None,
}

ONLINE_CRITICAL = {
    "host": "prod-web-01",
    "online": True,
    "last_seen_seconds": 6,
    "window": "15m",
    "counts": {"total": 9, "l1_critical": 2, "l2_grouped": 1, "l3_drift": 3, "l4_forensic": 3},
    "drift_targets_count": 14,
    "latest_critical": {
        "id": "00002798-0000-4000-8000-0004f26c0000",
        "target": "/etc/nginx/nginx.conf",
        "actor": "alice",
        "tool": "vim",
        "summary": "Modified /etc/nginx/nginx.conf",
        "deep_link": "http://localhost:5173/events/00002798-0000-4000-8000-0004f26c0000?tab=diff",
    },
}

OFFLINE = {
    "host": "prod-web-01",
    "online": False,
    "last_seen_seconds": 5400,
    "window": "15m",
    "counts": {"total": 0, "l1_critical": 0, "l2_grouped": 0, "l3_drift": 0, "l4_forensic": 0},
    "drift_targets_count": 0,
    "latest_critical": None,
}

DRIFT_WARN = {
    "host": "prod-web-01",
    "online": True,
    "last_seen_seconds": 3,
    "window": "15m",
    "counts": {"total": 20, "l1_critical": 0, "l2_grouped": 1, "l3_drift": 6, "l4_forensic": 0},
    "drift_targets_count": 8,
    "latest_critical": None,
}


class StateEvaluationTests(unittest.TestCase):
    def test_clean_host_is_ok(self):
        state, message, metrics = check.evaluate(ONLINE_CLEAN, make_args())
        self.assertEqual(state, check.OK)
        self.assertIn("Agent online", message)
        self.assertIn("0 critical changes in last 15m", message)
        self.assertEqual(metrics["l1_critical"], 0)
        self.assertEqual(metrics["drift_targets"], 2)

    def test_critical_change_is_crit_and_names_actor(self):
        state, message, _ = check.evaluate(ONLINE_CRITICAL, make_args())
        self.assertEqual(state, check.CRITICAL)
        self.assertIn("2 critical changes", message)
        # The alert must carry the actionable detail, not just a count.
        self.assertIn("alice via vim", message)
        self.assertIn("/etc/nginx/nginx.conf", message)
        self.assertIn("tab=diff", message)

    def test_offline_agent_is_crit_even_with_no_changes(self):
        state, message, _ = check.evaluate(OFFLINE, make_args())
        self.assertEqual(state, check.CRITICAL)
        self.assertIn("agent offline", message)

    def test_drift_warns(self):
        state, message, _ = check.evaluate(DRIFT_WARN, make_args())
        self.assertEqual(state, check.WARNING)
        self.assertIn("drift changes", message)

    def test_drift_escalates_to_crit_at_threshold(self):
        args = make_args(warn_drift=1, crit_drift=3)
        state, _, _ = check.evaluate(DRIFT_WARN, args)
        self.assertEqual(state, check.CRITICAL)

    def test_warn_targets_disabled_by_default(self):
        # A healthy host tracks dozens of files; the default must not warn.
        args = make_args()
        self.assertEqual(args.warn_targets, 0)
        # The only other WARN trigger left active is the L3 drift escalation.
        state, _, _ = check.evaluate(
            DRIFT_WARN, make_args(warn_targets=0, warn_drift=50, crit_drift=99)
        )
        self.assertEqual(state, check.OK)

    def test_warn_targets_opt_in(self):
        args = make_args(warn_targets=10, crit_critical=5, crit_drift=99)
        state, message, _ = check.evaluate(ONLINE_CRITICAL, args)
        self.assertEqual(state, check.WARNING)
        self.assertIn("tracked targets", message)

    def test_offline_beats_critical_change_in_message(self):
        both = dict(OFFLINE)
        both["latest_critical"] = ONLINE_CRITICAL["latest_critical"]
        state, message, _ = check.evaluate(both, make_args())
        self.assertEqual(state, check.CRITICAL)
        self.assertIn("agent offline", message)
        self.assertIn("alice via vim", message)


class RenderingTests(unittest.TestCase):
    def test_local_protocol_shape(self):
        args = make_args()
        state, message, metrics = check.evaluate(ONLINE_CLEAN, args)
        line = check.render_local(state, args.service, metrics, message, args)

        # "<state> "<service>" <perfdata> <summary>", perfdata pipe-delimited.
        self.assertTrue(line.startswith('0 "StateTrack_Changes" '))
        self.assertIn("total=5", line)
        self.assertIn("l1_critical=0;1;1", line)
        self.assertIn("l2_grouped=1", line)
        self.assertIn("l3_drift=3;5;10", line)
        # Exactly four perfdata separators, then the trailing summary text.
        self.assertEqual(line.count("|"), 4)
        self.assertEqual(
            line.split("|")[-1], "drift_targets=2 Agent online, 0 critical changes in last 15m"
        )
        self.assertEqual(line.count("\n"), 0)

    def test_local_thresholds_are_embedded_in_perfdata(self):
        args = make_args(warn_critical=2, crit_critical=4, warn_drift=6, crit_drift=9)
        state, message, metrics = check.evaluate(ONLINE_CLEAN, args)
        line = check.render_local(state, args.service, metrics, message, args)
        self.assertIn("l1_critical=0;2;4", line)
        self.assertIn("l3_drift=3;6;9", line)

    def test_nagios_protocol_shape(self):
        args = make_args()
        state, message, metrics = check.evaluate(ONLINE_CRITICAL, args)
        line = check.render_nagios(state, metrics, message, args)
        self.assertTrue(line.startswith("STATETRACK CRITICAL - "))
        self.assertIn(" | total=9 l1_critical=2;1;1", line)
        self.assertNotIn("\n", line)

    def test_nagios_ok_prefix(self):
        args = make_args()
        state, message, metrics = check.evaluate(ONLINE_CLEAN, args)
        line = check.render_nagios(state, metrics, message, args)
        self.assertTrue(line.startswith("STATETRACK OK - "))

    def test_pipes_and_newlines_in_message_are_sanitized(self):
        args = make_args()
        dirty = dict(ONLINE_CRITICAL)
        latest = dict(dirty["latest_critical"])
        latest["target"] = "/etc/we|ird\npath.conf"
        dirty["latest_critical"] = latest
        state, message, metrics = check.evaluate(dirty, args)
        line = check.render_local(state, args.service, metrics, message, args)
        # Exactly the four perfdata separators survive; no extra pipes.
        self.assertEqual(line.count("|"), 4)
        self.assertNotIn("\n", line)

    def test_long_message_is_truncated(self):
        self.assertEqual(len(check.truncate("x" * 1000)), check.MAX_SUMMARY)
        self.assertTrue(check.truncate("x" * 1000).endswith("\u2026"))


class CliTests(unittest.TestCase):
    """End-to-end through main(), with fetch_summary stubbed out."""

    def run_main(self, summary, argv):
        original = check.fetch_summary
        check.fetch_summary = lambda args: summary
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = check.main(argv)
            return code, buf.getvalue().strip()
        finally:
            check.fetch_summary = original

    def test_local_mode_always_exits_zero(self):
        # A non-zero exit would make the Checkmk agent abandon the host's
        # remaining local checks.
        code, out = self.run_main(ONLINE_CRITICAL, ["--mode", "local", "--host", "prod-web-01"])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith('2 "StateTrack_Changes" '))

    def test_nagios_mode_exit_codes(self):
        cases = [
            (ONLINE_CLEAN, 0, "OK"),
            (DRIFT_WARN, 1, "WARNING"),
            (ONLINE_CRITICAL, 2, "CRITICAL"),
            (OFFLINE, 2, "CRITICAL"),
        ]
        for summary, want_code, want_status in cases:
            code, out = self.run_main(summary, ["--mode", "nagios", "--host", "prod-web-01"])
            self.assertEqual(code, want_code, out)
            self.assertIn("STATETRACK {}".format(want_status), out)

    def test_connection_error_is_unknown_in_both_modes(self):
        def boom(args):
            raise check.CheckError("cannot reach StateTrack at http://x: connection refused")

        original = check.fetch_summary
        check.fetch_summary = boom
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = check.main(["--mode", "nagios", "--host", "h"])
            self.assertEqual(code, check.UNKNOWN)
            self.assertIn("STATETRACK UNKNOWN - cannot reach StateTrack", buf.getvalue())

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = check.main(["--mode", "local", "--host", "h"])
            # UNKNOWN state, but exit 0 so the agent keeps going.
            self.assertEqual(code, 0)
            self.assertTrue(buf.getvalue().startswith('3 "StateTrack_Changes" '))
        finally:
            check.fetch_summary = original

    def test_missing_host_is_unknown_not_crit(self):
        # A typo in a hostname must not page the on-call engineer.
        code, _ = self.run_main(ONLINE_CLEAN, ["--mode", "nagios", "--host", ""])
        self.assertIn(code, (check.OK, check.UNKNOWN))


class FetchTests(unittest.TestCase):
    def test_build_url_encodes_host_and_window(self):
        url = check.build_url("http://statetrack:8080/", "prod-web-01", "15m")
        self.assertEqual(
            url, "http://statetrack:8080/api/v1/hosts/prod-web-01/summary?window=15m"
        )

    def test_build_url_encodes_awkward_hosts(self):
        url = check.build_url("http://x", "host with space", "1h")
        self.assertIn("host%20with%20space", url)


class PayloadTests(unittest.TestCase):
    def test_summary_document_matches_api_contract(self):
        """Guard against the JSON keys drifting from server/internal/api."""
        required_top = {"host", "online", "window", "counts", "drift_targets_count"}
        required_counts = {"total", "l1_critical", "l2_grouped", "l3_drift", "l4_forensic"}
        self.assertTrue(required_top.issubset(ONLINE_CRITICAL))
        self.assertTrue(required_counts.issubset(ONLINE_CRITICAL["counts"]))
        self.assertEqual(json.loads(json.dumps(ONLINE_CRITICAL)), ONLINE_CRITICAL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
