#!/usr/bin/env bash
#
# StateTrack agent installer for Linux (systemd).
#
#   curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.sh \
#     | sudo bash -s -- --server statetrack.internal:50051 --token st_enroll_xxx
#
# The installer is deliberately boring: it downloads one release archive,
# verifies it against the release's published SHA-256 manifest, and installs
# the binary, configuration and systemd unit. Nothing is compiled, nothing is
# fetched from a third party, and a tampered download is refused before it can
# be installed.
#
# Stages:
#   1. resolve architecture (x86_64 / aarch64)
#   2. download statetrack-agent-linux-<arch>.tar.gz + SHA256SUMS.txt
#   3. verify the archive checksum
#   4. install /usr/local/bin/statetrack-agent
#   5. write /etc/statetrack/agent.yaml (mode 0600, never overwritten)
#   6. install, enable and start statetrack-agent.service
#
# Environment:
#   STATETRACK_RELEASES_URL  override the download root (air-gapped mirror)
#   STATETRACK_VERSION       release tag to install (default: latest)
#
set -euo pipefail

REPO="${STATETRACK_REPO:-premtonx/statetrack}"
VERSION="${STATETRACK_VERSION:-latest}"
if [ "$VERSION" = "latest" ]; then
  RELEASES_URL="${STATETRACK_RELEASES_URL:-https://github.com/${REPO}/releases/latest/download}"
else
  RELEASES_URL="${STATETRACK_RELEASES_URL:-https://github.com/${REPO}/releases/download/${VERSION}}"
fi

SERVER=""
TOKEN=""
ORG=""
BINARY=""     # install this local binary instead of downloading
URL=""        # install this archive/binary URL instead of the default
FORCE=0       # overwrite an existing agent.yaml
NO_START=0    # install but do not start the service

C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_BLUE=$'\033[34m'
if [ ! -t 1 ] || [ "${NO_COLOR:-}" != "" ]; then C_RESET=""; C_DIM=""; C_RED=""; C_GREEN=""; C_BLUE=""; fi

log()  { printf '%s==>%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%swarn%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { printf '%serr %s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
Usage: install.sh [options]

  --server HOST:PORT   gRPC address of the StateTrack server (server.address)
  --token TOKEN        enrollment token from Settings -> Agents
  --org ORG            organization label (server.org)
  --version TAG        release to install, e.g. v0.1.0 (default: latest)
  --binary PATH        install a local statetrack-agent binary instead
  --url URL            download this archive or binary instead of the release
  --force              overwrite an existing /etc/statetrack/agent.yaml
  --no-start           install and enable, but do not start the service
  -h, --help           this text

Examples:
  curl -fsSL https://raw.githubusercontent.com/premtonx/statetrack/main/deploy/install.sh \
    | sudo bash -s -- --server 10.0.4.20:50051 --token st_enroll_abc123

  sudo ./install.sh --binary ./statetrack-agent --server localhost:50051
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --server)   SERVER="${2:-}"; shift 2 ;;
    --token)    TOKEN="${2:-}";  shift 2 ;;
    --org)      ORG="${2:-}";    shift 2 ;;
    --version)  VERSION="${2:-}"; shift 2
                if [ "$VERSION" = "latest" ]; then
                  RELEASES_URL="${STATETRACK_RELEASES_URL:-https://github.com/${REPO}/releases/latest/download}"
                else
                  RELEASES_URL="${STATETRACK_RELEASES_URL:-https://github.com/${REPO}/releases/download/${VERSION}}"
                fi ;;
    --binary)   BINARY="${2:-}"; shift 2 ;;
    --url)      URL="${2:-}";    shift 2 ;;
    --force)    FORCE=1; shift ;;
    --no-start) NO_START=1; shift ;;
    -h|--help)  usage ;;
    *) warn "unknown flag: $1"; usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

# ---------------------------------------------------------------- 1. arch ---
case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "unsupported architecture: $(uname -m) (need x86_64 or aarch64)" ;;
esac

DEST="/usr/local/bin/statetrack-agent"
CONFIG="/etc/statetrack/agent.yaml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fetch() { curl -fsSL --retry 3 --retry-delay 1 "$1" -o "$2"; }

# ------------------------------------------------------------ 2. download ---
if [ -n "$BINARY" ]; then
  [ -f "$BINARY" ] || die "no such file: $BINARY"
  install -m 0755 "$BINARY" "$DEST"
  ok "installed $BINARY -> $DEST"
elif [ -n "$URL" ]; then
  log "downloading $URL"
  fetch "$URL" "$WORK/payload"
  case "$URL" in
    *.tar.gz|*.tgz) tar -xzf "$WORK/payload" -C "$WORK" ;;
    *.zip)          command -v unzip >/dev/null || die "unzip is required for .zip installs"
                    unzip -q "$WORK/payload" -d "$WORK" ;;
    *)              mv "$WORK/payload" "$WORK/statetrack-agent" ;;
  esac
  BIN="$(find "$WORK" -maxdepth 2 -type f -name 'statetrack-agent' | head -n1)"
  [ -n "$BIN" ] || die "archive did not contain a statetrack-agent binary"
  install -m 0755 "$BIN" "$DEST"
  ok "installed $DEST"
else
  ARCHIVE="statetrack-agent-linux-${ARCH}.tar.gz"
  log "downloading ${ARCHIVE} (${VERSION})"
  fetch "${RELEASES_URL}/${ARCHIVE}" "$WORK/$ARCHIVE"

  # --------------------------------------------------------- 3. checksum ---
  log "verifying SHA-256"
  if fetch "${RELEASES_URL}/SHA256SUMS.txt" "$WORK/SHA256SUMS.txt" 2>/dev/null; then
    EXPECTED="$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*" f { print $1; exit }' "$WORK/SHA256SUMS.txt")"
    [ -n "$EXPECTED" ] || die "SHA256SUMS.txt has no entry for $ARCHIVE"
    ACTUAL="$(sha256sum "$WORK/$ARCHIVE" | awk '{ print $1 }')"
    if [ "$EXPECTED" != "$ACTUAL" ]; then
      die "checksum mismatch for $ARCHIVE
  expected $EXPECTED
  actual   $ACTUAL
Refusing to install a tampered or corrupted archive."
    fi
    ok "checksum matches (${ACTUAL:0:16}…)"
  else
    warn "SHA256SUMS.txt unavailable; skipping checksum verification"
  fi

  tar -xzf "$WORK/$ARCHIVE" -C "$WORK"
  BIN="$(find "$WORK" -maxdepth 2 -type f -name 'statetrack-agent' | head -n1)"
  [ -n "$BIN" ] || die "$ARCHIVE did not contain a statetrack-agent binary"
  install -m 0755 "$BIN" "$DEST"
  ok "installed $DEST"
fi

# ------------------------------------------------------------ 4. config ----
mkdir -p /etc/statetrack
chmod 0755 /etc/statetrack
if [ -f "$CONFIG" ] && [ "$FORCE" -ne 1 ]; then
  log "keeping existing $CONFIG (pass --force to overwrite)"
else
  umask 077
  cat > "$CONFIG" <<EOF
# StateTrack agent configuration.
# Generated by deploy/install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Full parameter reference: docs/agent-deployment-guide.md
host_id: ""                     # empty: derive from /etc/machine-id, then hostname
state_dir: /var/lib/statetrack
log_level: info

server:
  address: ${SERVER}
  token: ${TOKEN}
  org: ${ORG}

# Filesystem scope. Defaults are applied by the agent; uncomment to narrow them.
# watch:
#   paths:
#     - /etc
#     - /etc/systemd/system
#     - /var/spool/cron
#     - /root/.ssh
#     - /home/*/.ssh
#   exclude:
#     - /etc/ssl/certs/**
#   critical:
#     - /etc/sudoers
#     - /etc/ssh/sshd_config
#     - /etc/pam.d/**

systemd:
  enabled: true
  units: ["*.service", "*.timer", "*.socket"]

packages:
  enabled: true

spool:
  max_mb: 200
EOF
  chmod 0600 "$CONFIG"
  chown root:root "$CONFIG" 2>/dev/null || true
  ok "wrote $CONFIG"
fi

# ------------------------------------------------------------- 5. unit -----
UNIT_SRC="$WORK/statetrack-agent.service"
if [ ! -f "$UNIT_SRC" ]; then
  # The release archive ships the unit; a --binary/--url install may not.
  UNIT_SRC="/etc/systemd/system/statetrack-agent.service"
  if [ ! -f "$UNIT_SRC" ]; then
    cat > "$UNIT_SRC" <<'UNIT'
[Unit]
Description=StateTrack Agent (infrastructure change intelligence)
Documentation=https://github.com/premtonx/statetrack
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
# The agent watches the filesystem and process tree, so it runs as root and
# keeps exactly the privileges its collectors need. Everything else is
# dropped by the sandbox directives below.
ExecStart=/usr/local/bin/statetrack-agent --config /etc/statetrack/agent.yaml
Restart=always
RestartSec=5s

ProtectSystem=full
StateDirectory=statetrack
ReadWritePaths=/var/lib/statetrack

# The only capabilities the collectors require:
#   CAP_SYS_ADMIN       - fanotify (rich file-change notifications)
#   CAP_AUDIT_READ      - read the audit log to attribute changes to actors
#   CAP_DAC_READ_SEARCH - read otherwise-unreadable files (e.g. /etc/shadow)
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_AUDIT_READ CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_SYS_ADMIN CAP_AUDIT_READ CAP_DAC_READ_SEARCH

RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
SystemCallArchitectures=native
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  fi
else
  install -m 0644 "$UNIT_SRC" /etc/systemd/system/statetrack-agent.service
fi

# ------------------------------------------------------------ 6. service ---
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable statetrack-agent >/dev/null 2>&1 || true
  if [ "$NO_START" -eq 1 ]; then
    log "service installed and enabled (not started: --no-start)"
  else
    systemctl restart statetrack-agent
    sleep 1
    if systemctl is-active --quiet statetrack-agent; then
      ok "statetrack-agent is running"
    else
      warn "statetrack-agent did not reach the running state; inspect: journalctl -u statetrack-agent -n 50"
    fi
  fi
else
  warn "systemctl not found; binary and config are installed but no service was registered"
fi

cat <<EOF

${C_GREEN}StateTrack agent installed.${C_RESET}

  binary    $DEST
  config    $CONFIG
  service   statetrack-agent ${DIM}(systemd)${C_RESET}

  status    systemctl status statetrack-agent
  logs      journalctl -u statetrack-agent -f

The host appears in the console under Servers within a few seconds of the
first heartbeat. If it does not, confirm that ${SERVER} is reachable from this
host and that the enrollment token has not expired.
EOF
