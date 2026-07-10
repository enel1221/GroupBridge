SHELL := /usr/bin/env bash

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
HOST_IP ?=

.DEFAULT_GOAL := help

.PHONY: help test test-cover fmt fmt-check vet build verify container helm-lint \
	keycloak-extension demo-up demo-down demo-status demo-test demo-reset

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "GroupBridge targets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run the Go test suite with the race detector.
	go test -race ./...

test-cover: ## Write Go coverage to coverage.out.
	go test -race -coverprofile=coverage.out ./...

fmt: ## Format Go code.
	gofmt -w cmd internal

fmt-check: ## Fail when Go code is not formatted.
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }

vet: ## Run Go static analysis.
	go vet ./...

build: ## Build the GroupBridge binary.
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)" -o bin/groupbridge ./cmd/groupbridge

container: ## Build the GroupBridge OCI image.
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t groupbridge:dev .

keycloak-extension: ## Build and test the minimal Keycloak provider image.
	docker build -t groupbridge-keycloak-extension:dev extensions/keycloak-event-listener

helm-lint: ## Lint and render the Helm chart.
	helm lint charts/groupbridge
	helm template groupbridge charts/groupbridge >/dev/null

verify: fmt-check vet test helm-lint ## Run the local release-quality checks.
	@if command -v shellcheck >/dev/null && compgen -G 'hack/*.sh' >/dev/null; then shellcheck hack/*.sh; fi

demo-up: ## Build and start the complete k3d demo; set HOST_IP for remote access.
	GROUPBRIDGE_DEMO_HOST=$(HOST_IP) ./hack/demo-up.sh

demo-down: ## Stop and delete the local k3d demo.
	./hack/demo-down.sh

demo-status: ## Print demo health, URLs, credentials, and kubeconfig commands.
	./hack/demo-status.sh

demo-test: ## Exercise membership removal and restoration against the running demo.
	./hack/demo-test.sh

demo-reset: demo-down demo-up ## Recreate the local demo from scratch.
