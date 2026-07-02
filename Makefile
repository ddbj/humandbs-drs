# humandbs-drs build and development tasks

MODULE  := github.com/ddbj/humandbs-drs
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
           -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
           -X $(MODULE)/internal/buildinfo.Date=$(DATE)

BIN := bin

.PHONY: all build drs issuer test vet lint fmt tidy run-drs run-issuer clean

all: build

build: drs issuer

drs:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/drs ./cmd/drs

issuer:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/issuer ./cmd/issuer

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

tidy:
	go mod tidy

run-drs: drs
	./$(BIN)/drs -public-host localhost:28000

run-issuer: issuer
	./$(BIN)/issuer -public-url http://localhost:28001

clean:
	rm -rf $(BIN)
