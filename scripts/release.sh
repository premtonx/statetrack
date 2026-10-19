#!/usr/bin/env bash
#
# Build the downloadable release archives into dist/<version>/.
#
#   ./scripts/release.sh v0.1.0
#
# Everything this script produces is attached to the GitHub release by
# `gh release create`. It is a plain shell script on purpose: it runs the same
# in a developer checkout on Linux/macOS, in Git Bash on Windows, and in the
# release workflow, with no Go or Node needed to *run* it (the builds inside it
# need both, but the workflow installs those first).
#
# Artifacts
#   statetrack-agent-linux-amd64.tar.gz     binary + install.sh + unit + agent.yaml.example
#   statetrack-agent-linux-arm64.tar.gz     ditto
#   statetrack-agent-windows-amd64.zip      .exe + install.ps1 + agent.yaml.example
#   statetrack-server-linux-amd64.tar.gz    server (console + migrations embedded)
#   statetrack-server-windows-amd64.zip
#   statetrack-mcp-linux-amd64.tar.gz       stdio MCP adapter for Claude/Cursor
#   statetrack-mcp-windows-amd64.zip
#   statetrack-integrations-bundle.zip      Grafana/Prometheus/Checkmk/Zabbix + quickstart
#   SHA256SUMS.txt                          checksums for every archive above
#
# The server binary embeds the console and the SQL migrations, so packaging it
# requires `web/dist` (built here unless SKIP_WEB=1 and it already exists).
set -euo pipefail

VERSION="${1:-${STATETRACK_VERSION:-v0.1.0}}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist/$VERSION"
COMMIT="${STATETRACK_COMMIT:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${STATETRACK_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE"
AGENT_LDFLAGS="-s -w -X main.version=$VERSION"
MCP_LDFLAGS="-s -w -X main.version=$VERSION"

log()  { printf '\033[34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m  ok\033[0m %s\n' "$*"; }
die()  { printf '\033[31merr\033[0m %s\n' "$*" >&2; exit 1; }

cd "$ROOT"
command -v go >/dev/null || die "go is required"
[ -n "$VERSION" ] || die "usage: scripts/release.sh <version>"

# ------------------------------------------------------------- 1. console ---
if [ "${SKIP_WEB:-0}" != "1" ]; then
  log "building the web console"
  if [ ! -d web/node_modules ]; then
    (cd web && npm ci --no-audit --no-fund)
  fi
  (cd web && npm run build)
fi
[ -f web/dist/index.html ] || die "web/dist/index.html is missing; run (cd web && npm run build)"

# The embed directive reads internal/webui/dist, so stage the built console
# there before compiling. This mirrors what the Dockerfile does.
#
# The committed `README.txt` in that directory is kept: it is what makes
# `//go:embed all:dist` resolve in a fresh checkout, and deleting it here would
# leave the working tree dirty after every release build.
log "staging the console into the server embed"
mkdir -p server/internal/webui/dist
find server/internal/webui/dist -mindepth 1 -maxdepth 1 ! -name README.txt -exec rm -rf {} +
cp -a web/dist/. server/internal/webui/dist/

# ------------------------------------------------------------ 2. binaries ---
log "cross-compiling binaries"
STAGE="$ROOT/dist/.stage-$VERSION"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$DIST"

build() { # os arch package output ldflags
  local os="$1"
  local arch="$2"
  local pkg="$3"
  local out="$4"
  local ldflags="$5"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOFLAGS=-buildvcs=false \
    go build -trimpath -ldflags "$ldflags" -o "$out" "$pkg"
}

for arch in amd64 arm64; do
  build linux "$arch" ./agent/cmd/statetrack-agent "$STAGE/bin/statetrack-agent-linux-$arch" "$AGENT_LDFLAGS"
  ok "agent linux/$arch"
done
build windows amd64 ./agent/cmd/statetrack-agent "$STAGE/bin/statetrack-agent-windows-amd64.exe" "$AGENT_LDFLAGS"
ok "agent windows/amd64"

build linux amd64 ./server/cmd/statetrack-server "$STAGE/bin/statetrack-server-linux-amd64" "$LDFLAGS"
build windows amd64 ./server/cmd/statetrack-server "$STAGE/bin/statetrack-server-windows-amd64.exe" "$LDFLAGS"
ok "server linux/amd64 + windows/amd64"

build linux amd64 ./server/cmd/statetrack-mcp "$STAGE/bin/statetrack-mcp-linux-amd64" "$MCP_LDFLAGS"
build windows amd64 ./server/cmd/statetrack-mcp "$STAGE/bin/statetrack-mcp-windows-amd64.exe" "$MCP_LDFLAGS"
ok "mcp linux/amd64 + windows/amd64"

# A build that lost its embeds would still start and then serve a placeholder,
# which is worse than failing here. `grep -a` reads the binary as text, so this
# check works on a Windows host cross-compiling for Linux, where the produced
# executable cannot be run.
grep -aq "$VERSION" "$STAGE/bin/statetrack-server-linux-amd64" \
  || die "server binary does not carry the $VERSION stamp"
grep -aq 'assets/index-' "$STAGE/bin/statetrack-server-linux-amd64" \
  || die "server binary does not embed the built console"
grep -aq 'schema_migrations' "$STAGE/bin/statetrack-server-linux-amd64" \
  || die "server binary does not embed the SQL migrations"
if [ "$(uname -s)" = "Linux" ]; then
  "$STAGE/bin/statetrack-server-linux-amd64" --version | grep -q "$VERSION" \
    || die "server binary does not report $VERSION"
fi
ok "server embeds the console, the migrations and the $VERSION stamp"

# ------------------------------------------------------------- 3. staging ---
stage_agent_linux() { # arch
  local arch="$1"
  local dir="$STAGE/agent-linux-$arch"
  mkdir -p "$dir"
  cp "$STAGE/bin/statetrack-agent-linux-$arch" "$dir/statetrack-agent"
  cp deploy/install.sh "$dir/install.sh"
  cp deploy/linux/statetrack-agent.service "$dir/statetrack-agent.service"
  cp deploy/linux/agent.yaml.example "$dir/agent.yaml.example"
  chmod 0755 "$dir/statetrack-agent" "$dir/install.sh"
}

stage_agent_windows() {
  local dir="$STAGE/agent-windows-amd64"
  mkdir -p "$dir"
  cp "$STAGE/bin/statetrack-agent-windows-amd64.exe" "$dir/statetrack-agent.exe"
  cp deploy/install.ps1 "$dir/install.ps1"
  cp deploy/windows/agent.yaml.example "$dir/agent.yaml.example"
}

stage_server() { # os arch ext
  local os="$1"
  local arch="$2"
  local ext="$3"
  local dir="$STAGE/server-$os-$arch"
  mkdir -p "$dir"
  cp "$STAGE/bin/statetrack-server-$os-$arch$ext" "$dir/statetrack-server$ext"
  chmod 0755 "$dir/statetrack-server$ext" 2>/dev/null || true
  cat > "$dir/README.txt" <<'EOF'
statetrack-server — StateTrack central server
=============================================

The console, the REST/WebSocket API, agent gRPC ingestion and the Prometheus
exporter are one static binary. The React console and the SQL migrations are
compiled into it, so there is nothing else to ship and no asset directory to
keep beside it.

Requirements
  PostgreSQL 14+ (16/17 recommended). Nothing else.

Start it
  export DATABASE_URL='postgres://user:pass@localhost:5432/statetrack?sslmode=disable'
  ./statetrack-server

  Migrations run automatically on first boot. Then open http://localhost:8080.
  The first administrator's password is generated and printed once:

    ./statetrack-server 2>&1 | grep administrator

  ...or choose it yourself:

    STATETRACK_ADMIN_EMAIL=you@example.com \
    STATETRACK_ADMIN_PASSWORD='a-long-password' ./statetrack-server

Ports
  8080   console + REST/WS API + /metrics + /healthz
  50051  agent gRPC ingestion

Environment
  DATABASE_URL                 postgres://... (required)
  STATETRACK_DEMO_MODE         1 enables the demo heartbeat + auto-login (default 0)
  STATETRACK_SESSION_SECRET    signs console cookies; set it in production
  STATETRACK_AUTO_MIGRATE      1 applies pending migrations on boot (default 1)
  STATETRACK_SERVE_UI          1 serves the embedded console (default 1)
  STATETRACK_ADMIN_EMAIL       bootstrap administrator address
  STATETRACK_ADMIN_PASSWORD    bootstrap administrator password
  S3_ENDPOINT / S3_BUCKET ...  offload large diff blobs (default: inline in Postgres)

Docker is the recommended deployment:
  ghcr.io/premtonx/statetrack:latest
  or deploy/docker-compose.quickstart.yml from the integrations bundle.
EOF
}

stage_mcp() { # os arch ext
  local os="$1"
  local arch="$2"
  local ext="$3"
  local dir="$STAGE/mcp-$os-$arch"
  mkdir -p "$dir"
  cp "$STAGE/bin/statetrack-mcp-$os-$arch$ext" "$dir/statetrack-mcp$ext"
  cat > "$dir/README.txt" <<'EOF'
statetrack-mcp — Model Context Protocol adapter for StateTrack
==============================================================

This binary speaks MCP over stdio to a desktop client (Claude Desktop, Cursor)
and forwards tool calls to a running statetrack-server over HTTP. It holds no
database credentials and needs no configuration file.

Claude Desktop  (~/.config/claude/claude_desktop_config.json on Linux/macOS,
                 %APPDATA%\Claude\claude_desktop_config.json on Windows):

  {
    "mcpServers": {
      "statetrack": {
        "command": "/usr/local/bin/statetrack-mcp",
        "env": { "STATETRACK_URL": "http://localhost:8080" }
      }
    }
  }

Cursor  (Settings -> MCP -> Add server, or ~/.cursor/mcp.json):

  {
    "mcpServers": {
      "statetrack": {
        "command": "/usr/local/bin/statetrack-mcp",
        "env": { "STATETRACK_URL": "http://localhost:8080" }
      }
    }
  }

Environment:
  STATETRACK_URL    server base URL (default http://localhost:8080)
  STATETRACK_TOKEN  API key, when the server requires one

Example prompts:
  "What changed on prod-web-01 in the last 6 hours?"
  "Which hosts drifted from the baseline this week?"
  "Was there a change immediately before the 03:14 error spike?"
EOF
  chmod 0755 "$dir/statetrack-mcp$ext" 2>/dev/null || true
}

stage_integrations() {
  local dir="$STAGE/integrations"
  mkdir -p "$dir/grafana" "$dir/prometheus" "$dir/checkmk" "$dir/zabbix" "$dir/docker" "$dir/kubernetes"
  cp integrations/grafana/statetrack-overview-dashboard.json "$dir/grafana/"
  cp integrations/grafana/README.md "$dir/grafana/" 2>/dev/null || true
  cp integrations/prometheus/prometheus_alerts.yml "$dir/prometheus/"
  cp deploy/prometheus/prometheus.yml "$dir/prometheus/statetrack-scrape-example.yml"
  cp integrations/checkmk/check_statetrack.py "$dir/checkmk/"
  cp integrations/checkmk/README.md "$dir/checkmk/" 2>/dev/null || true
  cp integrations/zabbix/zabbix_template_statetrack.yaml "$dir/zabbix/"
  cp integrations/zabbix/README.md "$dir/zabbix/" 2>/dev/null || true
  cp deploy/docker-compose.quickstart.yml "$dir/docker/"
  cp deploy/k8s/*.yaml "$dir/kubernetes/"
  cat > "$dir/README.md" <<'EOF'
# StateTrack integrations bundle

Everything needed to wire StateTrack into an existing monitoring stack, with
no repository checkout.

| Path | What it is | Where it goes |
| --- | --- | --- |
| `grafana/statetrack-overview-dashboard.json` | Overview dashboard: KPI grid, telemetry hero with L1/L2 change flags, breakdown, recent changes | Grafana → Dashboards → Import |
| `prometheus/prometheus_alerts.yml` | Alert rules: agent offline, critical-change spike, change storm | `rule_files:` in `prometheus.yml` |
| `prometheus/statetrack-scrape-example.yml` | Scrape config for the server's `/metrics` | merge into `scrape_configs:` |
| `checkmk/check_statetrack.py` | Checkmk check plugin (`--mode local`, `--mode nagios`) | `/omd/sites/<site>/local/lib/python3/cmk/base/plugins/agent_based/` |
| `zabbix/zabbix_template_statetrack.yaml` | Zabbix 7.0 template (host, items, triggers) | Zabbix → Data collection → Templates → Import |
| `docker/docker-compose.quickstart.yml` | Self-contained server + Postgres stack | `docker compose up -d` |
| `kubernetes/` | DaemonSet, cluster Deployment and RBAC | `kubectl apply -f kubernetes/` |

Each directory's README repeats the exact setup commands for that integration.
EOF
}

stage_agent_linux amd64
stage_agent_linux arm64
stage_agent_windows
stage_server linux amd64 ""
stage_server windows amd64 ".exe"
stage_mcp linux amd64 ""
stage_mcp windows amd64 ".exe"
stage_integrations
ok "staged release trees"

# ------------------------------------------------------------ 4. archives ---
log "creating archives"

# Shared ownership/mode rules so a tarball extracted as root does not hand out
# a world-writable binary.
# Archives are flat: the files land directly in the extraction directory, which
# is what every install snippet in the docs and installers assumes.
tar_gz() { # source-dir archive-name
  tar --owner=0 --group=0 --numeric-owner -czf "$DIST/$2" -C "$STAGE/$1" .
  ok "$2"
}
zip_dir() { # source-dir archive-name
  if command -v zip >/dev/null 2>&1; then
    (cd "$STAGE" && zip -qr "$DIST/$2" "$1")
  else
    # Git Bash and minimal CI images have no zip(1); PowerShell can archive on
    # Windows. `cygpath -w` converts the MSYS paths this script uses into the
    # Windows paths Compress-Archive expects (an unconverted /c/Users/... is
    # rejected as an invalid filesystem path).
    local src="$STAGE/$1"
    local dst="$DIST/$2"
    if command -v cygpath >/dev/null 2>&1; then
      src="$(cygpath -w "$src")"
      dst="$(cygpath -w "$dst")"
    fi
    # A wrapper directory inside the archive would put the extracted binary one
    # level deeper than the README's paths assume, so the wildcard flattens it.
    powershell -NoProfile -Command \
      "Compress-Archive -Path '$src\\*' -DestinationPath '$dst' -Force" >/dev/null
  fi
  ok "$2"
}

tar_gz agent-linux-amd64       statetrack-agent-linux-amd64.tar.gz
tar_gz agent-linux-arm64       statetrack-agent-linux-arm64.tar.gz
zip_dir agent-windows-amd64    statetrack-agent-windows-amd64.zip
tar_gz server-linux-amd64      statetrack-server-linux-amd64.tar.gz
zip_dir server-windows-amd64   statetrack-server-windows-amd64.zip
tar_gz mcp-linux-amd64         statetrack-mcp-linux-amd64.tar.gz
zip_dir mcp-windows-amd64      statetrack-mcp-windows-amd64.zip
zip_dir integrations           statetrack-integrations-bundle.zip

# ------------------------------------------------------------ 5. checksums --
log "writing SHA256SUMS.txt"
: > "$DIST/SHA256SUMS.txt"
( cd "$DIST" && for f in *.tar.gz *.zip; do
    [ -f "$f" ] || continue
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$f" >> SHA256SUMS.txt
    else
      shasum -a 256 "$f" >> SHA256SUMS.txt
    fi
  done )
ok "SHA256SUMS.txt"

rm -rf "$STAGE"

log "release artifacts in dist/$VERSION"
ls -lh "$DIST" | sed '1d'
cat <<EOF

Next:
  gh release create $VERSION dist/$VERSION/* \\
    --title "StateTrack $VERSION" --notes-file RELEASE_NOTES_$VERSION.md
EOF
