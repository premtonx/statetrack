# syntax=docker/dockerfile:1.7
#
# StateTrack — production container image.
#
#   docker build -t statetrack:v0.1.0 .
#   docker run -d -p 8080:8080 -p 50051:50051 \
#     -e STATETRACK_DATABASE_URL=postgres://user:pass@host:5432/statetrack?sslmode=disable \
#     statetrack:v0.1.0
#
# The three stages exist so the runtime image contains one static binary and a
# CA bundle — no Node, no Go toolchain, no node_modules, no source. The console
# and the SQL migrations are compiled into that binary, so a container started
# against an empty Postgres migrates itself and serves the UI on the same port
# as the API.

# --------------------------------------------------------------------------- #
# Stage 1 — build the React console                                           #
# --------------------------------------------------------------------------- #
FROM node:20-alpine AS web

WORKDIR /src/web

# Dependency manifests first: the npm layer is cached until the lockfile changes,
# which is the difference between a 20-second rebuild and a 4-minute one.
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY web/ ./

# Integration assets (Grafana dashboard, Prometheus rules, Checkmk plugin,
# Zabbix template) are served for copy/download from the console. In the repo
# they live beside the docs that describe them; a production build has no repo
# root to read from, so they are copied into public/ and bundled normally.
COPY integrations/grafana/statetrack-overview-dashboard.json ../integrations/grafana/
COPY integrations/grafana/README.md ../integrations/grafana/
COPY integrations/prometheus/prometheus_alerts.yml ../integrations/prometheus/
COPY integrations/checkmk/check_statetrack.py ../integrations/checkmk/
COPY integrations/zabbix/zabbix_template_statetrack.yaml ../integrations/zabbix/
RUN mkdir -p public/integration-assets/{grafana,prometheus,checkmk,zabbix} \
 && cp ../integrations/grafana/statetrack-overview-dashboard.json public/integration-assets/grafana/ \
 && cp ../integrations/grafana/README.md public/integration-assets/grafana/ \
 && cp ../integrations/prometheus/prometheus_alerts.yml public/integration-assets/prometheus/ \
 && cp ../integrations/checkmk/check_statetrack.py public/integration-assets/checkmk/ \
 && cp ../integrations/zabbix/zabbix_template_statetrack.yaml public/integration-assets/zabbix/

# `npm run build` runs tsc --noEmit first, so a type error fails the image build
# rather than shipping a console that throws at runtime.
RUN npm run build


# --------------------------------------------------------------------------- #
# Stage 2 — compile the server with the console embedded                      #
# --------------------------------------------------------------------------- #
FROM golang:1.26-alpine AS server

# git + ca-certificates: `go mod download` shells out to git for VCS fetches and
# the final binary needs a CA bundle to verify Agent/API TLS peers.
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# The repo is a Go workspace of three modules (pkg, agent, server). Copying the
# manifests separately keeps the module download layer cached across source
# edits.
COPY go.work go.work.sum ./
COPY pkg/go.mod pkg/go.sum ./pkg/
COPY agent/go.mod agent/go.sum ./agent/
COPY server/go.mod server/go.sum ./server/
RUN go work sync && cd server && go mod download

COPY pkg/ ./pkg/
COPY server/ ./server/

# The console replaces the checkout placeholder under internal/webui/dist, which
# is what the //go:embed directive reads.
COPY --from=web /src/web/dist/ ./server/internal/webui/dist/

ARG VERSION=v0.1.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.buildDate=${BUILD_DATE}" \
      -o /out/statetrack-server ./server/cmd/statetrack-server

# Prove the embeds made it into the binary before it becomes the image. A build
# that silently lost the console or the migrations would still start and then
# serve a placeholder page / fail on an empty schema, which is far worse than
# failing here.
RUN test -s /out/statetrack-server \
 && /out/statetrack-server --version | grep -q "${VERSION}"


# --------------------------------------------------------------------------- #
# Stage 3 — minimal runtime                                                   #
# --------------------------------------------------------------------------- #
FROM alpine:3.20 AS runtime

# ca-certificates: outbound HTTPS to Grafana, Slack, Teams, PagerDuty, Jira,
# ServiceNow and AI providers. tzdata: event timestamps render in the configured
# zone. Nothing else is needed; the binary is static.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 statetrack \
 && adduser -S -u 10001 -G statetrack -H -h /var/lib/statetrack statetrack \
 && mkdir -p /var/lib/statetrack \
 && chown -R statetrack:statetrack /var/lib/statetrack

COPY --from=server /out/statetrack-server /usr/local/bin/statetrack-server
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# The server writes nothing to disk when blob storage is S3 and migrations are in
# Postgres; state dir exists only for a deployment that enables the local spool.
USER statetrack
WORKDIR /var/lib/statetrack

ENV HTTP_ADDR=:8080 \
    GRPC_ADDR=:50051 \
    STATETRACK_DEMO_MODE=0 \
    STATETRACK_AUTO_MIGRATE=1 \
    STATETRACK_SERVE_UI=1

# 8080: console + REST/WS API + /metrics.  50051: agent gRPC ingestion.
EXPOSE 8080 50051

# Health is the API's own readiness endpoint, not a TCP probe: a process whose
# Postgres connection died would still accept a socket.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD wget -qO- "http://127.0.0.1:8080/healthz" >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["statetrack-server"]
