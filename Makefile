SHELL := /bin/bash

GO ?= go
PYTHON ?= python3
TARGET_OS ?= linux
TARGET_ARCH ?= $(shell $(GO) env GOARCH)
BIN_DIR ?= bin
DESTDIR ?= dist/stage
TEST_IMAGE ?= qntw-blackhole-tests:local
MODULES := probe-blackhole tls-alert-gate observability/udp-observer
ABS_BIN_DIR := $(abspath $(BIN_DIR))

.PHONY: help build cross-build test vet race syntax fixtures-check stage test-stage integration-build integration test-integration docker-integration

help:
	@printf '%s\n' 'make build              Build all Linux binaries (TARGET_OS/TARGET_ARCH override)' 'make cross-build        Build Linux amd64 and arm64 binaries' 'make test               Go and Python unit tests, syntax and fixture checks' 'make vet                Vet all Go modules' 'make race               Race-check all Go modules' 'make stage DESTDIR=DIR  Prepare an installation tree without installing it' 'make docker-integration Run isolated Linux integration tests in Docker' 'make integration        Run namespace tests on a disposable Linux root machine'

build:
	@mkdir -p "$(ABS_BIN_DIR)"
	cd probe-blackhole && CGO_ENABLED=0 GOOS="$(TARGET_OS)" GOARCH="$(TARGET_ARCH)" $(GO) build -trimpath -o "$(ABS_BIN_DIR)/vpnshop-probe-blackhole" .
	cd tls-alert-gate && CGO_ENABLED=0 GOOS="$(TARGET_OS)" GOARCH="$(TARGET_ARCH)" $(GO) build -trimpath -o "$(ABS_BIN_DIR)/vpnshop-tls-alert-gate" .
	cd observability/udp-observer && CGO_ENABLED=0 GOOS="$(TARGET_OS)" GOARCH="$(TARGET_ARCH)" $(GO) build -trimpath -o "$(ABS_BIN_DIR)/vpnshop-udp-observer" .

cross-build:
	$(MAKE) build TARGET_OS=linux TARGET_ARCH=amd64 BIN_DIR="$(BIN_DIR)/linux-amd64"
	$(MAKE) build TARGET_OS=linux TARGET_ARCH=arm64 BIN_DIR="$(BIN_DIR)/linux-arm64"

test: syntax fixtures-check
	@set -e; for module in $(MODULES); do (cd "$$module" && $(GO) test ./...); done
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s observability -p 'test_*.py' -v

vet:
	@set -e; for module in $(MODULES); do (cd "$$module" && $(GO) vet ./...); done

race:
	@set -e; for module in $(MODULES); do (cd "$$module" && $(GO) test -race ./...); done

syntax:
	@set -e; while IFS= read -r -d '' script; do bash -n "$$script"; done < <(find probe-blackhole tls-alert-gate observability tools -type f -name '*.sh' -print0)
	ruby -c probe-blackhole/build-profiles.rb
	$(PYTHON) -c 'from pathlib import Path; [compile(p.read_bytes(), str(p), "exec") for p in Path("observability").glob("*.py")]'

fixtures-check:
	@set -e; fixtures=$$(mktemp -d); trap 'rm -rf -- "$$fixtures"' EXIT; ruby probe-blackhole/build-profiles.rb probe-blackhole/profiles.json "$$fixtures"; cmp probe-blackhole/profiles.nft "$$fixtures/profiles.nft"; cmp probe-blackhole/counters.nft "$$fixtures/counters.nft"; test "$$(find "$$fixtures" -name '*.hello' | wc -l | tr -d ' ')" = 6

stage: build
	QNTW_STAGE_BIN_DIR="$(ABS_BIN_DIR)" bash tools/stage.sh "$(DESTDIR)"

test-stage:
	bash tools/test-stage.sh

integration-build: build
	cd probe-blackhole && CGO_ENABLED=0 GOOS="$(TARGET_OS)" GOARCH="$(TARGET_ARCH)" $(GO) test -c -o "$(ABS_BIN_DIR)/blackhole.test" .
	cd observability/udp-observer && CGO_ENABLED=0 GOOS="$(TARGET_OS)" GOARCH="$(TARGET_ARCH)" $(GO) build -trimpath -o "$(ABS_BIN_DIR)/udp-test-client" ./test-client
	cd observability/udp-observer && CGO_ENABLED=0 GOOS="$(TARGET_OS)" GOARCH="$(TARGET_ARCH)" $(GO) build -trimpath -o "$(ABS_BIN_DIR)/udp-test-peer" ./test-peer

integration: integration-build
	QNTW_TEST_BIN_DIR="$(ABS_BIN_DIR)" bash tools/test-integration.sh

test-integration: integration

docker-integration: integration-build
	docker build -f tools/Dockerfile.tests -t "$(TEST_IMAGE)" tools
	docker run --rm --privileged --network none --entrypoint /bin/bash --mount "type=bind,src=$(CURDIR),dst=/src,readonly" --mount "type=bind,src=$(ABS_BIN_DIR),dst=/test-bin,readonly" -e QNTW_TEST_BIN_DIR=/test-bin "$(TEST_IMAGE)" /src/tools/test-integration.sh
