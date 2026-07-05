# humandbs-drs build and development tasks

MODULE  := github.com/ddbj/humandbs-drs
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
           -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
           -X $(MODULE)/internal/buildinfo.Date=$(DATE)

BIN := bin

.PHONY: all build drs issuer test test-integration test-e2e e2e-up e2e-down vet lint fmt tidy run-drs run-issuer clean

all: build

build: drs issuer

drs:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/drs ./cmd/drs

issuer:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/issuer ./cmd/issuer

test:
	go test ./...

# Runs the SeaweedFS-backed integration tests. Bring up the backend first
# (docker compose up -d seaweedfs) and point the tests at it.
test-integration: HUMANDBS_TEST_S3_ENDPOINT ?= http://localhost:8333
test-integration:
	HUMANDBS_TEST_S3_ENDPOINT=$(HUMANDBS_TEST_S3_ENDPOINT) go test -tags integration ./...

# The end-to-end stack: the base compose topology plus the e2e fixtures and
# the second drs instance from the override file.
COMPOSE_E2E := docker compose -f compose.yaml -f test/e2e/compose.e2e.yaml

e2e-up:
	$(COMPOSE_E2E) up -d --build

e2e-down:
	$(COMPOSE_E2E) down -v

# Runs the end-to-end tests against an already running stack (make e2e-up).
test-e2e:
	HUMANDBS_E2E=1 go test -tags e2e -count=1 ./test/e2e/

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

tidy:
	go mod tidy

run-drs: drs
	./$(BIN)/drs \
		-public-host localhost:28000 \
		-manifest manifest.json \
		-index-db index.db \
		-service-id jp.ac.nig.ddbj.humandbs-drs \
		-service-name "HumanDBs DRS" \
		-org-name DDBJ \
		-org-url https://www.ddbj.nig.ac.jp/ \
		-trusted-issuer http://localhost:28001

run-issuer: issuer
	./$(BIN)/issuer -public-url http://localhost:28001

clean:
	rm -rf $(BIN)
