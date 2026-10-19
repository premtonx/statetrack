#!/bin/sh
#
# Container entrypoint for StateTrack.
#
# The image is a single static binary, so there is almost nothing to configure
# here. This script adds the one thing a container runtime cannot do
# declaratively: a clear, early failure when DATABASE_URL is unset. Without it
# the server would fall back to localhost and log connection errors that say
# nothing about the actual mistake.
#
# Waiting for Postgres is *not* done here. The server retries its first connect
# for up to STATETRACK_DB_CONNECT_TIMEOUT (60s), which works the same in compose,
# Kubernetes and a bare `docker run`, and needs no netcat in the runtime image.
set -eu

if [ "${1:-}" = "" ]; then
  set -- statetrack-server
fi

# Flags belong to the server binary: `docker run --rm statetrack --version`
# must work with no database configured.
case "${1}" in
  -*)
    exec statetrack-server "$@"
    ;;
esac

if [ -z "${DATABASE_URL:-}" ] && [ -n "${STATETRACK_DATABASE_URL:-}" ]; then
  DATABASE_URL="${STATETRACK_DATABASE_URL}"
  export DATABASE_URL
fi

# The server subcommand is the only long-running one. `--help` on the entrypoint
# itself is served by the binary's own flag handling above.
if [ "${1}" = "statetrack-server" ] && [ -z "${DATABASE_URL:-}" ]; then
  echo "statetrack: DATABASE_URL is not set." >&2
  echo "  docker run -e DATABASE_URL=postgres://user:pass@host:5432/statetrack?sslmode=disable ..." >&2
  echo "  ...or use deploy/docker-compose.quickstart.yml, which provides Postgres for you." >&2
  exit 1
fi

exec "$@"
