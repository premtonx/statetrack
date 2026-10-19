#!/usr/bin/env python3
"""StateTrack check for Checkmk (and any Nagios-compatible supervisor).

Polls the StateTrack unified host summary endpoint and renders it as either a
Checkmk *local check* or a *Nagios/Icinga/MRPE* active check.

Why one script for two protocols: the state computation is identical, only the
rendering and the exit convention differ. Keeping them together means an
operator adding a threshold has one place to change and cannot accidentally
park the two integrations on different logic.

    GET {base}/api/v1/hosts/{host}/summary?window={window}

Requires nothing outside the Python 3 standard library, so it can be dropped
straight onto a monitored host or a Checkmk poller without a pip install and
without a virtualenv.

Examples
--------
Local check (drop in /usr/lib/check_mk_agent/local/, must be executable)::

    check_statetrack.py --url http://statetrack:8080 --host prod-web-01

Nagios active check::

    check_statetrack.py --mode nagios --url http://statetrack:8080 \\
        --host prod-web-01 --token "$STATETRACK_TOKEN"

Exit codes (Nagios mode only; local checks must always exit 0 so the agent
still runs the checks after this one)::

    0 OK   1 WARNING   2 CRITICAL   3 UNKNOWN
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

# --- Checkmk/Nagios state constants ---------------------------------------- #
OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3

STATE_NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}

# Checkmk local checks expect a single line per service. Anything longer is
# truncated by the agent anyway, so we clip it ourselves and keep the message
# readable in the GUI.
MAX_SUMMARY = 480

DEFAULT_SERVICE = "StateTrack_Changes"


class CheckError(Exception):
    """A condition that maps to the UNKNOWN state (config or connectivity)."""


# --------------------------------------------------------------------------- #
# Argument parsing                                                            #
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="StateTrack monitoring check (Checkmk local check / Nagios active check).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=("local", "nagios"),
        default="local",
        help="Output protocol. 'local' for Checkmk local checks, 'nagios' for "
        "active checks / MRPE / Icinga2 (uses standard exit codes).",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("STATETRACK_URL", "http://localhost:8080"),
        help="StateTrack server base URL (env: STATETRACK_URL).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("STATETRACK_HOST") or default_hostname(),
        help="Hostname (or host UUID) to check. Defaults to this machine's "
        "hostname, which matches how the agent enrols (env: STATETRACK_HOST).",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("STATETRACK_TOKEN", ""),
        help="Bearer token for the API (env: STATETRACK_TOKEN).",
    )
    parser.add_argument(
        "--window",
        default="15m",
        help="Change lookback window, e.g. 15m, 1h, 7d.",
    )
    parser.add_argument(
        "--service",
        default=DEFAULT_SERVICE,
        help="Checkmk service name to report.",
    )
    parser.add_argument(
        "--warn-critical",
        type=int,
        default=1,
        help="WARN when at least this many L1 critical changes are in the window. "
        "Defaults to 1, i.e. any critical change warns (and CRITs via --crit-critical).",
    )
    parser.add_argument(
        "--crit-critical",
        type=int,
        default=1,
        help="CRIT when at least this many L1 critical changes are in the window.",
    )
    parser.add_argument(
        "--warn-drift",
        type=int,
        default=5,
        help="WARN when L3 drift changes reach this count.",
    )
    parser.add_argument(
        "--crit-drift",
        type=int,
        default=10,
        help="CRIT when L3 drift changes reach this count.",
    )
    parser.add_argument(
        "--warn-targets",
        type=int,
        default=0,
        help="WARN when tracked drift targets reach this count (0 disables: a "
        "healthy host legitimately tracks dozens of files).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification (self-signed internal CA).",
    )
    return parser.parse_args(argv)


def default_hostname():
    return socket.gethostname()


# --------------------------------------------------------------------------- #
# Fetching                                                                    #
# --------------------------------------------------------------------------- #
def build_url(base, host, window):
    base = base.rstrip("/")
    return "{}/api/v1/hosts/{}/summary?{}".format(
        base, urllib.parse.quote(host, safe=""), urllib.parse.urlencode({"window": window})
    )


def fetch_summary(args):
    """Return the parsed summary document, or raise CheckError."""
    url = build_url(args.url, args.host, args.window)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    if args.token:
        request.add_header("Authorization", "Bearer {}".format(args.token))

    context = None
    if args.insecure:
        import ssl

        context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(request, timeout=args.timeout, context=context) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        # A 404 is a configuration problem (wrong hostname), not an outage, and
        # saying so saves the operator a debugging round-trip.
        if exc.code == 404:
            raise CheckError("host {!r} is unknown to StateTrack (HTTP 404)".format(args.host))
        if exc.code in (401, 403):
            raise CheckError("StateTrack rejected the token (HTTP {})".format(exc.code))
        raise CheckError("StateTrack returned HTTP {}".format(exc.code))
    except urllib.error.URLError as exc:
        raise CheckError("cannot reach StateTrack at {}: {}".format(args.url, exc.reason))
    except socket.timeout:
        raise CheckError("timed out after {:.0f}s talking to {}".format(args.timeout, args.url))

    try:
        payload = json.loads(body)
    except ValueError:
        raise CheckError("StateTrack returned a non-JSON response")
    if not isinstance(payload, dict):
        raise CheckError("unexpected summary payload")
    return payload


# --------------------------------------------------------------------------- #
# State evaluation                                                            #
# --------------------------------------------------------------------------- #
def evaluate(summary, args):
    """Map a summary document onto (state, message).

    Precedence is deliberate: an offline agent beats everything (its silence is
    why we are here), then critical changes, then drift.
    """
    online = bool(summary.get("online"))
    counts = summary.get("counts") or {}
    l1 = int(counts.get("l1_critical") or 0)
    l2 = int(counts.get("l2_grouped") or 0)
    l3 = int(counts.get("l3_drift") or 0)
    total = int(counts.get("total") or 0)
    targets = int(summary.get("drift_targets_count") or 0)
    window = summary.get("window") or args.window

    state = OK
    reasons = []

    if not online:
        state = CRITICAL
        last_seen = summary.get("last_seen_seconds")
        reasons.append("agent offline (last seen {}s ago)".format(last_seen))

    if l1 >= args.crit_critical:
        state = CRITICAL
        reasons.append(
            "{} critical change{} in last {}".format(l1, "" if l1 == 1 else "s", window)
        )
    elif l1 >= args.warn_critical:
        state = max(state, WARNING)
        reasons.append("{} critical change(s) in last {}".format(l1, window))

    if l3 >= args.crit_drift:
        state = CRITICAL
        reasons.append("{} drift changes (>= {})".format(l3, args.crit_drift))
    elif l3 >= args.warn_drift:
        state = max(state, WARNING)
        reasons.append("{} drift changes".format(l3))

    if args.warn_targets and targets >= args.warn_targets:
        state = max(state, WARNING)
        reasons.append("{} tracked targets".format(targets))

    if reasons:
        message = "; ".join(reasons)
    elif online:
        message = "Agent online, 0 critical changes in last {}".format(window)
    else:
        message = "Agent offline"

    # The newest critical change is what makes the alert actionable, so it is
    # appended in full: actor, tool, path and the console deep link.
    detail = critical_detail(summary)
    if detail and state > OK:
        message = "{} - {}".format(message, detail)
    elif detail:
        message = "{} - {}".format(message, detail)

    return state, message, {
        "total": total,
        "l1_critical": l1,
        "l2_grouped": l2,
        "l3_drift": l3,
        "drift_targets": targets,
    }


def critical_detail(summary):
    """Render the latest critical change as 'actor via tool: path (link)'."""
    latest = summary.get("latest_critical")
    if not isinstance(latest, dict):
        return ""
    parts = []
    actor = (latest.get("actor") or "").strip()
    tool = (latest.get("tool") or "").strip()
    if actor and tool:
        parts.append("{} via {}".format(actor, tool))
    elif actor:
        parts.append(actor)
    target = (latest.get("target") or "").strip()
    if target:
        parts.append(target)
    text = " ".join(parts) if parts else (latest.get("summary") or "").strip()

    summary_text = (latest.get("summary") or "").strip()
    alt = (latest.get("id") or "").strip()
    detail = "latest: {} {}".format(text, summary_text).strip() if text else summary_text
    if alt:
        # Compact identifier so an operator can grep the raw check output even
        # when the deep link is truncated downstream.
        detail = "{} [{}]".format(detail, alt) if detail else "[{}]".format(alt)

    link = (latest.get("deep_link") or "").strip()
    if link:
        detail = "{} {}".format(detail, link) if detail else link
    return detail.strip()


def sanitize(text):
    """Make a message safe for a single-line, pipe-delimited check output.

    Checkmk splits the line on the first '|' and Nagios parses the performance
    data section similarly, so a newline or a stray pipe in a filename would
    corrupt the whole check. One line, no pipes.
    """
    text = re.sub(r"\s+", " ", str(text)).strip()
    return text.replace("|", "/")


def truncate(text, limit=MAX_SUMMARY):
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "\u2026"


def fmt_number(value):
    """Render a counter without a spurious '.0' so perfdata stays tidy."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


# --------------------------------------------------------------------------- #
# Rendering                                                                   #
# --------------------------------------------------------------------------- #
def render_local(state, service, metrics, message, args):
    """Checkmk local check protocol:

        <state> "<service>" <perfdata> <summary>

    Thresholds ride along in perfdata (`value;warn;crit`) so Checkmk draws the
    levels on the graph rather than us baking them into the state text.
    """
    perf = [
        "total={}".format(fmt_number(metrics["total"])),
        "l1_critical={};{};{}".format(
            fmt_number(metrics["l1_critical"]), args.warn_critical, args.crit_critical
        ),
        "l2_grouped={}".format(fmt_number(metrics["l2_grouped"])),
        "l3_drift={};{};{}".format(
            fmt_number(metrics["l3_drift"]), args.warn_drift, args.crit_drift
        ),
        "drift_targets={}".format(fmt_number(metrics["drift_targets"])),
    ]
    return '{} "{}" {} {}'.format(
        state, service, "|".join(perf), truncate(sanitize(message))
    )


def render_nagios(state, metrics, message, args):
    """Nagios plugin protocol: '<CHECK> <STATUS> - <text> | <perfdata>'.

    Space-separated perfdata here (vs Checkmk's pipe-delimited form) because
    that is what Nagios/Icinga/MRPE parse.
    """
    perf = [
        "total={}".format(fmt_number(metrics["total"])),
        "l1_critical={};{};{}".format(
            fmt_number(metrics["l1_critical"]), args.warn_critical, args.crit_critical
        ),
        "l2_grouped={}".format(fmt_number(metrics["l2_grouped"])),
        "l3_drift={};{};{}".format(
            fmt_number(metrics["l3_drift"]), args.warn_drift, args.crit_drift
        ),
        "drift_targets={}".format(fmt_number(metrics["drift_targets"])),
    ]
    return "STATETRACK {} - {} | {}".format(
        STATE_NAMES[state], truncate(sanitize(message)), " ".join(perf)
    )


# --------------------------------------------------------------------------- #
# Entry point                                                                 #
# --------------------------------------------------------------------------- #
def main(argv=None):
    args = parse_args(argv)

    try:
        summary = fetch_summary(args)
        state, message, metrics = evaluate(summary, args)
    except CheckError as exc:
        # Connectivity and configuration problems are UNKNOWN, not CRITICAL: an
        # alerting storm caused by the monitoring server being down is not a
        # production incident and would page the wrong person.
        message = str(exc)
        if args.mode == "local":
            print('{} "{}" - {}'.format(UNKNOWN, args.service, truncate(sanitize(message))))
        else:
            print("STATETRACK {} - {}".format(STATE_NAMES[UNKNOWN], truncate(sanitize(message))))
        # A local check must exit 0 or the Checkmk agent aborts the remaining
        # local checks for that host.
        return 0 if args.mode == "local" else UNKNOWN

    if args.mode == "local":
        print(render_local(state, args.service, metrics, message, args))
        return 0

    print(render_nagios(state, metrics, message, args))
    return state


if __name__ == "__main__":
    sys.exit(main())
