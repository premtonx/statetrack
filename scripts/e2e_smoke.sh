#!/usr/bin/env bash
#
# Full-stack automated smoke test for StateTrack.
#
# Verifies the whole distributed loop: docker stack health -> server ->
# Postgres + SeaweedFS + Grafana annotations -> REST, plus the real agent's
# secret scrubbing. Exits 0 on success.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== 1/4: docker stack"
docker compose up -d

echo "== 2/4: migrations"
make migrate

echo "== 3/4: build"
make build

echo "== 4/4: smoke test (waits for the stack to become healthy)"
go run ./server/cmd/statetrack-smoke
