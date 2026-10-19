"""Verify what the Checkmk GUI renders for the StateTrack services.

Reads the site's Livestatus socket directly. The Raw Edition's REST API lists
configured services but omits runtime columns (state, plugin output, perfdata),
so a REST-only check can say "the service exists" while never proving it turned
CRIT with five metrics — which is exactly what the demo needs to prove.

Usage (inside the Checkmk container):
    python3 verify_checkmk_livestatus.py [site] [--wait SECONDS]
"""

import json
import socket
import sys
import time

EXPECTED_METRICS = 5


def parse_args(argv):
    site = "cmk"
    wait = 0
    args = list(argv)
    if args and not args[0].startswith("--"):
        site = args.pop(0)
    if "--wait" in args:
        wait = int(args[args.index("--wait") + 1])
    return site, wait


def query(sock_path, q):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect(sock_path)
    s.sendall(q.encode() + b"\n")
    chunks = []
    while True:
        data = s.recv(65536)
        if not data:
            break
        chunks.append(data)
    s.close()
    return b"".join(chunks).decode("utf-8", "replace")


def fetch(sock_path):
    """Return the live StateTrack services as dicts.

    JSON output is used rather than the pipe/semicolon text format: plugin
    output legitimately contains both ';' (the reason list is semicolon-joined)
    and '|' (stripped, but perfdata thresholds use them), so any positional
    split mis-assigns columns exactly on the rows this check cares about.
    """
    q = (
        "GET services\n"
        "Columns: host_name description state plugin_output perf_data\n"
        "OutputFormat: json\n"
        "Filter: description ~~ StateTrack\n"
        "\n"
    )
    raw = query(sock_path, q).strip()
    if not raw or raw == "[]":
        return []
    rows = json.loads(raw)
    keys = ["host_name", "description", "state", "plugin_output", "perf_data"]
    return [dict(zip(keys, row)) for row in rows]


def evaluate(rows, hosts, failures):
    seen = set()
    for row in rows:
        host = row["host_name"]
        desc = row["description"]
        seen.add((host, desc))
        metrics = [m for m in (row["perf_data"] or "").split() if m]
        output = (row["plugin_output"] or "").replace("\n", " ")
        # Livestatus' JSON encoding returns state as an integer, while the text
        # format returns a string; normalise so both paths share one comparison.
        state = str(row["state"])
        print("{:<14} {:<26} state={} metrics={} {}".format(
            host, desc, state, len(metrics), output[:96]))

        # CRIT (2) with five metrics is the target state on a host that has L1
        # mutations. OK (0) is legitimate for a host with none, but a PENDING
        # (-1) means the core has not run the check yet.
        if state not in ("0", "2"):
            failures.append("{} / {}: state {} (expected OK or CRIT)".format(
                host, desc, state))
        if state in ("0", "2") and len(metrics) < EXPECTED_METRICS:
            failures.append("{} / {}: {} perfdata metrics (expected {})".format(
                host, desc, len(metrics), EXPECTED_METRICS))

    for host in hosts:
        for desc in ("StateTrack Changes", "StateTrack Active Check"):
            if (host, desc) not in seen:
                failures.append("{}: {} is not inventoried".format(host, desc))
    return failures


def main():
    site, wait = parse_args(sys.argv[1:])
    sock_path = "/omd/sites/{}/tmp/run/live".format(site)
    hosts = ["prod-web-01", "win-app-02", "prod-k8s-01", "prod-web-02"]

    deadline = time.time() + wait
    while True:
        try:
            rows = fetch(sock_path)
        except (OSError, ValueError) as exc:
            print("cannot read Livestatus at {}: {}".format(sock_path, exc))
            return 1

        failures = []
        evaluate(rows, hosts, failures)
        # The active checks are scheduled by the core, not by this script: on a
        # freshly activated site they sit at PENDING for up to a minute. Waiting
        # is what turns that into a green verification instead of a flaky one.
        if not failures or time.time() >= deadline:
            break
        print("\n{} service(s) not ready, retrying in 10s...\n".format(len(failures)))
        time.sleep(10)

    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  - {}".format(f))
        return 1

    print("\nAll {} hosts report both StateTrack services with live perfdata.".format(len(hosts)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
