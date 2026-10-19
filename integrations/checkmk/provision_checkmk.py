#!/usr/bin/env python3
"""Provision the StateTrack Checkmk demo: 4 hosts, 2 check modes, live data.

Runs *inside* the Checkmk container and drives Checkmk's own REST API, so it
works the same whether a human runs it by hand or `scripts/provision_checkmk.ps1`
runs it after `docker compose up`. It is idempotent: re-running updates the
objects it owns and leaves everything else alone.

What it creates, per host in HOSTS
----------------------------------
1. The host object (folder `/`, no real agent — the datasource program replaces
   agent access entirely).
2. A `datasource_programs` rule pointing at
   `/omd/sites/<site>/local/bin/statetrack_agent_wrapper.sh <host>`.
   That wrapper emits `<<<check_mk>>>` + `<<<local:sep(0)>>>` and runs the
   repository's `check_statetrack.py --mode local`, which is what renders the
   `StateTrack Changes` service.
3. A `custom_checks` rule running `check_statetrack.py --mode nagios`, which is
   the Nagios/MRPE deployment shape. Both appear on every host, so one
   screenshot shows both integration modes.

Then it activates the changes and forces one check cycle, so the GUI is
populated before the script returns rather than up to a minute later.

Credentials
-----------
The REST API needs the automation user `cmkadmin` and the site password
(`CMK_PASSWORD`, default `statetrack` for the demo).

Exit status is 0 only when every host ended up with a live `StateTrack Changes`
service, so the caller can gate a recording on it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The demo fleet. Kept in lockstep with server/internal/demo/heartbeat.go and
# server/cmd/statetrack-seed: these are the four hosts StateTrack enrols, so
# these are the four a Checkmk operator should see.
HOSTS = ["prod-web-01", "win-app-02", "prod-k8s-01", "prod-web-02"]

SERVICE = "StateTrack Changes"
ACTIVE_SERVICE = "StateTrack Active Check"

# Every host shares the same OS facts. The datasource program reports the facts
# itself; these attributes only stop Checkmk from trying to connect to an agent
# that is not listening on these (fictional) machines.
HOST_ATTRIBUTES = {
    "tag_agent": "cmk-agent",
    # A datasource program is executed locally, so the address is never dialled.
    # Loopback keeps a misconfigured host from reaching a real machine.
    "ipaddress": "127.0.0.1",
}


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__("HTTP {}: {}".format(status, body))
        self.status = status
        self.body = body


def site_path(base):
    """The site ID embedded in an origin URL, or CMK_SITE_ID.

    Accepts either `http://localhost:5000` or `http://localhost:5000/cmk`, so
    the script behaves the same whether an operator copies the GUI URL or the
    origin from the docs.
    """
    parsed = urllib.parse.urlparse(base)
    segments = [s for s in parsed.path.split("/") if s]
    if segments:
        return segments[0]
    return os.environ.get("CMK_SITE_ID", "cmk")


class Rest:
    """Minimal Checkmk REST client (stdlib only, no pip on the site)."""

    def __init__(self, base, user, password):
        # `base` is the origin (http://localhost:5000); the API lives below the
        # site's own path, so the site ID is part of the URL, not a header.
        self.base = base.rstrip("/") + "/" + site_path(base) + "/check_mk/api/1.0"
        self.user = user
        self.password = password

    def call(self, method, path, body=None, expect=(200, 201, 204, 302), headers=None):
        url = self.base + path
        data = None
        hdrs = {
            "Accept": "application/json",
            "Authorization": "Bearer {} {}".format(self.user, self.password),
        }
        if headers:
            hdrs.update(headers)
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", "replace")
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            status = exc.code
        except urllib.error.URLError as exc:
            raise ApiError(0, "cannot reach Checkmk at {}: {}".format(url, exc.reason))

        if status not in expect:
            raise ApiError(status, raw)
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw

    def value(self, path):
        """Return the single value of a /value endpoint."""
        doc = self.call("GET", path)
        return (doc or {}).get("value")


# --------------------------------------------------------------------------- #
# Steps                                                                       #
# --------------------------------------------------------------------------- #
def wait_for_site(rest, deadline=180, grace=75):
    """Block until the REST API answers (the site starts after the hook runs).

    A 404 is *not* immediately fatal. On a first boot (or after `-Recreate`)
    Apache answers before the site's REST route exists, so `/version` returns a
    plain "Not Found" page for a minute or two — retrying is exactly right. It
    only means the URL is wrong if it is still 404 after `grace` seconds, at
    which point retrying provably cannot help and the message says so.
    """
    start = time.time()
    last = None
    while time.time() - start < deadline:
        try:
            rest.call("GET", "/version")
            return True
        except ApiError as exc:
            last = exc
            if exc.status == 404 and time.time() - start > grace:
                site = urllib.parse.urlsplit(rest.base).path.strip("/").split("/")[0]
                raise SystemExit(
                    "Checkmk REST API still 404 at {} after {}s — check the site "
                    "ID (is the site actually at /{}/?)".format(rest.base, grace, site)
                )
            time.sleep(3)
    raise SystemExit("Checkmk REST API did not become ready: {}".format(last))


def upsert_host(rest, host):
    """Create the host, or confirm its attributes already match.

    The update path matters because a partially-provisioned site is the normal
    case after a failed run. It compares only the attributes this script owns:
    `meta_data` is server-managed and echoing it back is rejected by the API, so
    a blind "send the whole document" update cannot work.
    """
    body = {"host_name": host, "folder": "/", "attributes": HOST_ATTRIBUTES}
    try:
        rest.call("POST", "/domain-types/host_config/collections/all", body)
        print("  host {}: created".format(host))
        return
    except ApiError as exc:
        # 400/409 is "already exists" (the status varies by version); anything
        # else is a real problem and must not be swallowed.
        if exc.status not in (400, 409):
            raise

    existing = rest.call(
        "GET",
        "/objects/host_config/{}".format(urllib.parse.quote(host, safe="")),
    )
    current = ((existing or {}).get("extensions") or {}).get("attributes") or {}
    if all(current.get(k) == v for k, v in HOST_ATTRIBUTES.items()):
        print("  host {}: already configured".format(host))
        return

    merged = dict(current)
    merged.pop("meta_data", None)
    merged.update(HOST_ATTRIBUTES)
    rest.call(
        "PUT",
        "/objects/host_config/{}".format(urllib.parse.quote(host, safe="")),
        {"update_attributes": merged, "remove_attributes": []},
    )
    print("  host {}: updated".format(host))


def datasource_rule(host, site):
    """Rule body for the local-check datasource program."""
    wrapper = "/omd/sites/{}/local/bin/statetrack_agent_wrapper.sh".format(site)
    return {
        "ruleset": "datasource_programs",
        "folder": "/",
        "conditions": {"host_name": {"match_on": [host], "operator": "one_of"}},
        "properties": {
            "description": "StateTrack datasource program ({})".format(host),
            "disabled": False,
        },
        # The value is the command line; Checkmk appends nothing, so the host
        # name is passed here explicitly rather than relying on a macro that
        # differs between a GUI-triggered and core-triggered run.
        #
        # The REST API stores the value in `value_raw`, not `value`: `value` is
        # a read-only normalised form it derives on the way out, and sending it
        # is rejected as an unknown field. value_raw is *parsed as a Python
        # literal*, so a bare command is read as code — hence json.dumps, which
        # produces a double-quoted, correctly escaped Python string literal.
        "value_raw": json.dumps("{} {}".format(wrapper, host)),
    }


def active_check_rule(host, site):
    """Rule body for the Nagios-mode active check (MRPE-shaped)."""
    script = "/omd/sites/{}/local/bin/check_statetrack.py".format(site)
    command = (
        "{} --mode nagios --url {} --host {} --window {} --service '{}'".format(
            script,
            os.environ.get("STATETRACK_URL", "http://host.docker.internal:8080"),
            host,
            os.environ.get("STATETRACK_WINDOW", "7d"),
            ACTIVE_SERVICE,
        )
    )
    return {
        "ruleset": "custom_checks",
        "folder": "/",
        "conditions": {"host_name": {"match_on": [host], "operator": "one_of"}},
        "properties": {
            "description": "StateTrack active check ({})".format(host),
            "disabled": False,
        },
        # Dictionary-valued rulesets take the JSON encoding of the value as a
        # string in value_raw; the API does not accept a nested object.
        "value_raw": json.dumps(
            {"service_description": ACTIVE_SERVICE, "command_line": command}
        ),
    }


def upsert_rule(rest, body):
    """Find a rule this script owns (by ruleset + description) and replace it."""
    ruleset = body["ruleset"]
    description = body["properties"]["description"]
    listing = rest.call(
        "GET", "/domain-types/rule/collections/all?ruleset_name={}".format(ruleset)
    )
    for rule in (listing or {}).get("value") or []:
        ext = rule.get("extensions") or {}
        if (ext.get("properties") or {}).get("description") == description:
            rule_id = rule.get("id")
            # An update may not move a rule between rulesets or folders: those
            # identify the object, so the API rejects them as unknown fields
            # here (they are create-only). Only the mutable half is sent.
            update = {
                "conditions": body["conditions"],
                "properties": body["properties"],
                "value_raw": body["value_raw"],
            }
            rest.call(
                "PUT",
                "/objects/rule/{}".format(urllib.parse.quote(rule_id, safe="")),
                update,
                headers={"If-Match": "*"},
            )
            print("  rule: {} (updated)".format(description))
            return
    rest.call("POST", "/domain-types/rule/collections/all", body)
    print("  rule: {} (created)".format(description))


def activate(rest):
    """Activate pending changes so the core picks up the new rules.

    The activation endpoint is a state-changing action on the site, so Checkmk
    requires an If-Match header; `*` is the documented "regardless of current
    state" value for an automation that is not racing a human in the GUI.
    """
    try:
        rest.call(
            "POST",
            "/domain-types/activation_run/actions/activate-changes/invoke",
            {"redirect": False, "sites": [os.environ.get("CMK_SITE_ID", "cmk")]},
            headers={"If-Match": "*"},
        )
        print("  activation: ok")
    except ApiError as exc:
        # 422 means "nothing to activate", which is the success case for a
        # re-run with no edits.
        if exc.status == 422:
            print("  activation: nothing pending")
            return
        raise


def discover(rest, site, hosts):
    """Rescan each host's agent output so its services are inventoried.

    A datasource program only becomes a service after discovery: creating the
    host and the rule tells Checkmk *how* to get data, not yet *what* services
    that data contains. `-II` is used rather than `-I` so a re-run replaces the
    inventory instead of accumulating stale services when a check is renamed.
    """
    import subprocess

    for host in hosts:
        proc = subprocess.run(
            ["su", "-", site, "-c",
             "cd /omd/sites/{0} && ./bin/cmk -II {1}".format(site, host)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print("  discovery {}: exit {} ({})".format(
                host, proc.returncode, (proc.stderr or proc.stdout).strip()[:200]))
        else:
            print("  discovery {}: ok".format(host))

    # Discovery writes new service definitions, which are itself a pending
    # change; without a second activation the core has no idea they exist.
    activate(rest)


def force_check(site, hosts):
    """Run one check cycle per host so the GUI is populated immediately."""
    import subprocess

    ok = True
    for host in hosts:
        # `cmk` must run with the site as its working directory: it resolves
        # its own paths relative to the site root, and the flags it accepts
        # differ from the wrapper's --check help text (e.g. -v is only valid
        # before the host argument).
        proc = subprocess.run(
            ["su", "-", site, "-c",
             "cd /omd/sites/{0} && ./bin/cmk --check {1}".format(site, host)],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            print("  check {}: ran".format(host))
            continue
        # A non-zero exit is reported but not fatal: the check may still have
        # produced a result, and verify() is the real gate.
        print("  check {}: exit {} ({})".format(
            host, proc.returncode, (proc.stderr or proc.stdout).strip()[:300]))
        ok = False
    return ok


def service_state(rest, host, description):
    """Return the live service document, or None when it is not inventoried.

    Used only to answer "does the service exist". The REST API's service
    endpoints omit runtime columns (plugin output, perfdata) in the Raw Edition,
    so whether the check *reported* something is decided by `livestatus()`.
    """
    path = "/objects/host/{}/actions/show_service/invoke?service_description={}".format(
        urllib.parse.quote(host, safe=""),
        urllib.parse.quote(description, safe=""),
    )
    try:
        return (rest.call("GET", path) or {}).get("extensions") or {}
    except ApiError as exc:
        if exc.status == 404:
            return None
        raise


def livestatus(site):
    """Return {(host, description): (state, output, perfdata)} from Livestatus.

    Livestatus is the same source the GUI renders, so this is the only way to
    prove what an operator will actually see. JSON output is used rather than
    the text protocol: plugin output contains ';' (the reason list) and the
    perfdata contains '|' inside thresholds, so a positional split mis-assigns
    columns precisely on the rows that matter.
    """
    import socket

    sock_path = "/omd/sites/{}/tmp/run/live".format(site)
    query = (
        "GET services\n"
        "Columns: host_name description state plugin_output perf_data\n"
        "OutputFormat: json\n"
        "Filter: description ~~ StateTrack\n"
        "\n"
    )
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(15)
    try:
        sock.connect(sock_path)
        sock.sendall(query.encode() + b"\n")
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()

    raw = b"".join(chunks).decode("utf-8", "replace").strip()
    if not raw or raw == "[]":
        return {}
    out = {}
    for row in json.loads(raw):
        host, description, state, output, perf = row
        out[(host, description)] = (state, output or "", perf or "")
    return out


def verify(rest, site, hosts):
    """Confirm every host reports both StateTrack services with live perfdata."""
    live = livestatus(site)
    failures = []
    for host in hosts:
        for name in (SERVICE, ACTIVE_SERVICE):
            if service_state(rest, host, name) is None:
                failures.append("{}: {} is not inventoried".format(host, name))
                continue
            row = live.get((host, name))
            if row is None:
                failures.append("{}: {} has no live check result".format(host, name))
                continue
            state, output, perf = row
            metrics = [m for m in perf.split() if m]
            print("  {} / {}: state={} metrics={} {}".format(
                host, name, state, len(metrics), output.replace("\n", " ")[:96]))
            # A CRIT (2) with five metrics is the target on a host with L1
            # mutations; OK (0) is legitimate for a host with none. PENDING (-1)
            # means the core has not run the check yet.
            if state not in (0, 2):
                failures.append("{}: {} has state {} (expected OK or CRIT)".format(
                    host, name, state))
            elif len(metrics) < 5:
                failures.append("{}: {} reports {} perfdata metrics (expected 5)".format(
                    host, name, len(metrics)))
    return failures


# --------------------------------------------------------------------------- #
# Entry point                                                                 #
# --------------------------------------------------------------------------- #
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", default=os.environ.get("CMK_SITE_ID", "cmk"))
    parser.add_argument("--url", default="http://localhost:5000")
    parser.add_argument("--user", default=os.environ.get("CMK_USER", "cmkadmin"))
    parser.add_argument(
        "--password", default=os.environ.get("CMK_PASSWORD", "statetrack")
    )
    parser.add_argument("--hosts", nargs="*", default=HOSTS)
    parser.add_argument(
        "--skip-check", action="store_true", help="do not force an immediate check cycle"
    )
    args = parser.parse_args(argv)

    rest = Rest(args.url, args.user, args.password)

    print("1. waiting for the Checkmk site")
    wait_for_site(rest)

    print("2. hosts")
    for host in args.hosts:
        upsert_host(rest, host)

    print("3. rules")
    for host in args.hosts:
        upsert_rule(rest, datasource_rule(host, args.site))
        upsert_rule(rest, active_check_rule(host, args.site))

    print("4. activating")
    activate(rest)

    if not args.skip_check:
        print("5. discovering services")
        discover(rest, args.site, args.hosts)

        print("6. forcing a check cycle")
        force_check(args.site, args.hosts)

    print("7. verifying")
    failures = verify(rest, args.site, args.hosts)
    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  - {}".format(f))
        return 1

    print("\nAll {} hosts report {}.".format(len(args.hosts), SERVICE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
