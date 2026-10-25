# main package lives at the module root, not cmd/$(BINARY).
CMD_PATH := .

common.mk:
	@curl -fsSL https://raw.githubusercontent.com/alex27riva/go-mk/main/common.mk -o $@

include common.mk

PREFIX ?= $(HOME)/.local

.PHONY: mock vet fmt install e2e

mock: ## Build the mock Jade device
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/jade-mock ./cmd/jade-mock

vet: ## go vet
	$(GO) vet ./...

fmt: ## gofmt
	gofmt -s -w .

# age finds plugins on $PATH by name.
install: build ## Install to $(PREFIX)/bin
	install -Dm755 $(BUILD_DIR)/$(BINARY) $(PREFIX)/bin/$(BINARY)

# Needs age on PATH.
e2e: build mock ## End-to-end run against the mock device with the real age CLI
	./scripts/e2e.sh
