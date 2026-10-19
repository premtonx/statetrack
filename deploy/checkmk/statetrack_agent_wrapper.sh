#!/usr/bin/env bash
# StateTrack datasource program for Checkmk.
#
# Checkmk runs this script instead of a real agent when a host is configured
# with "Program" as its data source. It emits one agent-format document:
#
#   <<<check_mk>>>            agent header (version + OS facts Checkmk expects)
#   <<<local:sep(0)>>>        the local-check section, one line per service
#
# Everything below the second header is produced by the repository's own
# check_statetrack.py in --mode local, so the Checkmk GUI and a production
# local-check deployment render the exact same line from the same code path.
#
# Usage (Checkmk appends the host name as $1):
#   statetrack_agent_wrapper.sh <hostname>
#
# Environment overrides (set them on the site, not per host):
#   STATETRACK_URL     base URL of the StateTrack server (default
#                      http://host.docker.internal:8080 when running in the
#                      Docker demo, http://localhost:8080 otherwise)
#   STATETRACK_WINDOW  change lookback window (default 7d)
#   STATETRACK_TOKEN   bearer token, if the API requires one
#   STATETRACK_SERVICE service name (default "StateTrack Changes")
#
# The script is deliberately tolerant: if StateTrack is unreachable it still
# prints a complete document with an UNKNOWN local check. A datasource program
# that emits nothing makes Checkmk drop every service on the host, which looks
# like a deleted host rather than an outage.

set -u

HOST="${1:-}"
PYTHON_BIN="${STATETRACK_PYTHON:-python3}"
# Installed next to this script by the compose post-start hook, so the demo
# works regardless of the site ID (cmk, demo, ...).
CHECK="${STATETRACK_CHECK:-$(dirname "$0")/check_statetrack.py}"
URL="${STATETRACK_URL:-http://host.docker.internal:8080}"
WINDOW="${STATETRACK_WINDOW:-7d}"
SERVICE="${STATETRACK_SERVICE:-StateTrack Changes}"

# The agent header. Checkmk only requires the marker, but it uses the OS facts
# to decide which check plugins a host is eligible for; claiming a Linux agent
# keeps the "Check_MK" service itself green and avoids odd "no data" states.
cat <<'HEADER'
<<<check_mk>>>
Version: 2.3.0
AgentOS: linux
Hostname: state-track-datasource
HEADER

# A missing host argument is a configuration error, not a monitoring outage:
# report it as UNKNOWN rather than crashing with a traceback Checkmk swallows.
if [ -z "$HOST" ]; then
    echo '<<<local:sep(0)>>>'
    echo '3 "StateTrack Changes" - datasource program was called without a host name'
    exit 0
fi

# The agent's own hostname differs from the Checkmk host name in the demo
# (Checkmk inventory names vs. StateTrack enrolment names), so the name is
# always passed explicitly.
ARGS=(--mode local --url "$URL" --host "$HOST" --window "$WINDOW" --service "$SERVICE")
if [ -n "${STATETRACK_TOKEN:-}" ]; then
    ARGS+=(--token "$STATETRACK_TOKEN")
fi
if [ "${STATETRACK_INSECURE:-0}" = "1" ]; then
    ARGS+=(--insecure)
fi

echo '<<<local:sep(0)>>>'
"$PYTHON_BIN" "$CHECK" "${ARGS[@]}" 2>/dev/null ||
    echo '3 "StateTrack Changes" - check_statetrack.py crashed; see the site log'
exit 0
