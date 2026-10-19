SHELL := /usr/bin/env bash

MODULE_PB     := github.com/statetrack/statetrack/pkg/pb
PROTO_DIR     := proto
PROTO_FILES   := $(shell find $(PROTO_DIR) -name '*.proto')
BIN_DIR       := bin
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS       := -s -w -X main.version=$(VERSION)

POSTGRES_USER ?= statetrack
POSTGRES_DB   ?= statetrack
CHECKMK_PORT  ?= 5000
CHECKMK_SITE  ?= cmk
MIGRATIONS    := $(sort $(wildcard server/migrations/*.sql))

GO_MODULES    := ./pkg/... ./agent/... ./server/...

GO_IMAGE      := golang:1.26
GO_DOCKER     := docker run --rm -v $(CURDIR):/src -w /src \
                 -v statetrack-gomod:/go/pkg/mod -v statetrack-gocache:/root/.cache/go-build \
                 -e GOFLAGS=-buildvcs=false -e CGO_ENABLED=1
E2E_CAPS      := --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add AUDIT_CONTROL --cap-add AUDIT_READ --pid=host

.PHONY: all tools proto build build-agent build-server test test-integration test-race test-e2e vet tidy \
        up down logs migrate seed grafana-seed demo-traffic checkmk psql clean

all: proto build test

## tools: install protoc Go plugins (protoc itself must be installed separately)
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

## proto: regenerate Go code in pkg/pb from proto/
proto:
	protoc -I $(PROTO_DIR) \
		--go_out=pkg/pb --go_opt=module=$(MODULE_PB) \
		--go-grpc_out=pkg/pb --go-grpc_opt=module=$(MODULE_PB) \
		$(PROTO_FILES)

## build: build agent (linux amd64/arm64, windows amd64) and server
build: build-agent build-server

build-agent:
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/statetrack-agent-linux-amd64       ./agent/cmd/statetrack-agent
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/statetrack-agent-linux-arm64       ./agent/cmd/statetrack-agent
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/statetrack-agent-windows-amd64.exe ./agent/cmd/statetrack-agent

build-server:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/statetrack-server ./server/cmd/statetrack-server
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/statetrack-mcp ./server/cmd/statetrack-mcp
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/statetrack-grafana-seed ./server/cmd/statetrack-grafana-seed
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/statetrack-demo-traffic ./server/cmd/statetrack-demo-traffic

## test: unit tests for all modules
test:
	go test $(GO_MODULES)

## test-integration: tests that need the docker-compose stack (run `make up migrate` first)
test-integration:
	STATETRACK_TEST_DATABASE_URL=postgres://$(POSTGRES_USER):statetrack@localhost:5432/$(POSTGRES_DB)?sslmode=disable \
		go test -count=1 ./server/...

## test-race: race detector in a Linux container (cgo is enabled only there;
## release builds stay CGO_ENABLED=0)
test-race:
	$(GO_DOCKER) $(GO_IMAGE) go test -race -count=1 $(GO_MODULES)

## test-e2e: Linux collector end-to-end tests, unprivileged and privileged
test-e2e:
	$(GO_DOCKER) -e STATETRACK_E2E=1 $(GO_IMAGE) go test -race -count=1 -v -run E2E ./agent/internal/app/
	$(GO_DOCKER) -e STATETRACK_E2E=1 $(E2E_CAPS) $(GO_IMAGE) go test -race -count=1 -v -run E2E ./agent/internal/app/

vet:
	go vet $(GO_MODULES)

tidy:
	cd pkg && go mod tidy
	cd agent && go mod tidy
	cd server && go mod tidy

## up/down/logs: local dependency stack (Postgres 17, SeaweedFS S3, Grafana)
up:
	docker compose up -d --wait

down:
	docker compose down

logs:
	docker compose logs -f

PSQL := docker compose exec -T postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -v ON_ERROR_STOP=1 -tA -q

## migrate: apply pending SQL migrations in order, each in a single transaction
migrate:
	@echo 'CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());' | $(PSQL) -f -
	@for f in $(MIGRATIONS); do \
		v=$$(basename "$$f" .sql); \
		if [ "$$(echo "SELECT 1 FROM schema_migrations WHERE version = '$$v';" | $(PSQL) -f -)" = "1" ]; then \
			echo "skip   $$f (already applied)"; continue; \
		fi; \
		echo "apply  $$f"; \
		{ cat "$$f"; echo "INSERT INTO schema_migrations (version) VALUES ('$$v');"; } | \
			$(PSQL) --single-transaction -f - || exit 1; \
	done

## seed: load a realistic demo timeline for today (idempotent)
seed:
	go run ./server/cmd/statetrack-seed

## grafana-seed: import the dashboard + push L1 annotations to Docker Grafana (:3000)
grafana-seed:
	go run ./server/cmd/statetrack-grafana-seed

## demo-traffic: drive changes through the ingest API so the Grafana panels move
## Usage: make demo-traffic ARGS="-duration 5m -interval 1s"
demo-traffic:
	go run ./server/cmd/statetrack-demo-traffic $(ARGS)

## checkmk: provision the local Checkmk Raw demo (:5000) with the four demo hosts
checkmk:
	docker compose --profile monitoring up -d --wait checkmk
	docker compose --profile monitoring cp integrations/checkmk/provision_checkmk.py checkmk:/tmp/provision_checkmk.py
	docker compose --profile monitoring cp integrations/checkmk/verify_checkmk_livestatus.py checkmk:/tmp/verify_checkmk_livestatus.py
	docker compose --profile monitoring exec -T \
		-e STATETRACK_URL=http://host.docker.internal:8080 -e STATETRACK_WINDOW=7d \
		-e CMK_SITE_ID=$(CHECKMK_SITE) -e CMK_PASSWORD=statetrack \
		checkmk python3 /tmp/provision_checkmk.py --site $(CHECKMK_SITE) --url http://localhost:$(CHECKMK_PORT) --password statetrack
	docker compose --profile monitoring exec -T -u $(CHECKMK_SITE) checkmk \
		python3 /tmp/verify_checkmk_livestatus.py $(CHECKMK_SITE) --wait 120

psql:
	docker compose exec postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

clean:
	rm -rf $(BIN_DIR)
