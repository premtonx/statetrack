#!/usr/bin/env bash
# Checkmk container post-start hook: wire the StateTrack check into the site.
#
# Runs on every container start, after `omd start`, via
# /docker-entrypoint.d/post-start (mounted from deploy/checkmk/hooks/post-start).
# Idempotent by design: it copies the staged files into the site, then only
# creates what is missing.
#
# Why copy instead of bind-mounting the site path: `omd create` aborts if
# /omd/sites/<site> already exists, so mounting onto local/bin would break the
# very first boot. Copying also survives the site living on a named volume that
# outlives the image.

set -eu

SITE="${CMK_SITE_ID:-cmk}"
SITE_DIR="/omd/sites/$SITE"
STAGE="/opt/statetrack"

# Give the site a moment to finish bringing its services up: on first boot
# `omd create` runs immediately before this hook and is not instant.
for _ in $(seq 1 60); do
    [ -d "$SITE_DIR/etc" ] && break
    sleep 2
done

if [ ! -d "$SITE_DIR/etc" ]; then
    echo "### statetrack: site $SITE not ready, skipping"
    exit 0
fi

# ---- 1. Install the check + datasource wrapper into the site --------------
install -d -o "$SITE" -g "$SITE" "$SITE_DIR/local/bin"
install -m 0755 -o "$SITE" -g "$SITE" \
    "$STAGE/check_statetrack.py" "$SITE_DIR/local/bin/check_statetrack.py"
install -m 0755 -o "$SITE" -g "$SITE" \
    "$STAGE/statetrack_agent_wrapper.sh" "$SITE_DIR/local/bin/statetrack_agent_wrapper.sh"

# Pin the interpreter the site actually has rather than relying on PATH at
# check time.
if command -v python3 >/dev/null 2>&1; then
    WRAPPER_PY="$(command -v python3)"
else
    WRAPPER_PY="$SITE_DIR/bin/python3"
fi

# ---- 2. Expose the same script as a local check for agent-sourced hosts ---
# The demo hosts use the datasource program above, but installing the script
# under local/ documents (and enables) the production deployment shape for any
# host that runs a real Checkmk agent.
install -d -o "$SITE" -g "$SITE" "$SITE_DIR/local/lib/check_mk_agent/local"
cat >"$SITE_DIR/local/lib/check_mk_agent/local/check_statetrack.sh" <<EOF
#!/bin/sh
# StateTrack local check (see integrations/checkmk/README.md).
# interval: 300
exec "$WRAPPER_PY" "$SITE_DIR/local/bin/check_statetrack.py" \\
    --mode local \\
    --url "\${STATETRACK_URL:-http://host.docker.internal:8080}" \\
    --host "\${STATETRACK_HOST:-\$(hostname -s)}" \\
    --window "\${STATETRACK_WINDOW:-7d}" \\
    --service "StateTrack Changes" \\
    --token "\${STATETRACK_TOKEN:-}"
EOF
chmod 0755 "$SITE_DIR/local/lib/check_mk_agent/local/check_statetrack.sh"
chown -R "$SITE:$SITE" "$SITE_DIR/local"

# ---- 3. Make the wrapper's default base URL reachable from the container --
# host.docker.internal resolves thanks to extra_hosts; nothing to configure.

echo "### statetrack: installed check_statetrack.py and datasource wrapper"
