.PHONY: build install fmt vet lint golangci-lint-version test check docker-build docker-check release-linux release-darwin release-windows

include native-deps.env

VERSION ?= v0.2.0
BUILD_DIR ?= .build
GOLANGCI_LINT_VERSION ?= v2.12.2
PREFIX ?= /usr/local/bin
HOST_PLATFORM := $(shell go env GOOS)-$(shell go env GOARCH)
HOST_BINARY := graphit-broker$(if $(filter windows-%,$(HOST_PLATFORM)),.exe,)

build:
	./scripts/build-embedded.sh "$(HOST_PLATFORM)" "$(HOST_BINARY)" "$(VERSION)"

install: build
	mkdir -p "$(PREFIX)"
	@if [ -w "$(PREFIX)" ]; then \
		cp "$(HOST_BINARY)" "$(PREFIX)/$(HOST_BINARY)"; \
	else \
		sudo cp "$(HOST_BINARY)" "$(PREFIX)/$(HOST_BINARY)"; \
	fi
	@echo "  ✓ Installed to $(PREFIX)/$(HOST_BINARY)"
	@case ":$$PATH:" in \
		*":$(PREFIX):"*) ;; \
		*) echo "  ⚠ $(PREFIX) is not in your PATH. Add it: export PATH=\"\$$PATH:$(PREFIX)\"" ;; \
	esac

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "  ! golangci-lint not found. Install it with:"; \
		echo "      go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"; \
		exit 1; \
	}
	golangci-lint run ./...

# Single source of truth for the pinned linter; CI installs what this prints.
golangci-lint-version:
	@echo "$(GOLANGCI_LINT_VERSION)"

test:
	go test ./...

check:
	go vet ./...
	go test ./...

docker-build: build
	docker build -t graphit-broker:dev .

docker-check: docker-build
	./scripts/container-smoke.sh graphit-broker:dev

release-linux:
	rm -rf "$(BUILD_DIR)/graphit-broker-linux-amd64" "$(BUILD_DIR)/graphit-broker-linux-amd64.tar.gz" "$(BUILD_DIR)/graphit-broker-linux-amd64.sha256"
	mkdir -p "$(BUILD_DIR)/graphit-broker-linux-amd64"
	./scripts/build-embedded.sh linux-amd64 "$(BUILD_DIR)/graphit-broker-linux-amd64/graphit-broker" "$(VERSION)"
	cp config.example.yaml "$(BUILD_DIR)/graphit-broker-linux-amd64/config.example.yaml"
	tar -C "$(BUILD_DIR)" -czf "$(BUILD_DIR)/graphit-broker-linux-amd64.tar.gz" graphit-broker-linux-amd64
	cd "$(BUILD_DIR)" && sha256sum graphit-broker-linux-amd64.tar.gz > graphit-broker-linux-amd64.sha256

release-darwin:
	rm -rf "$(BUILD_DIR)/graphit-broker-darwin-arm64" "$(BUILD_DIR)/graphit-broker-darwin-arm64.tar.gz" "$(BUILD_DIR)/graphit-broker-darwin-arm64.sha256"
	mkdir -p "$(BUILD_DIR)/graphit-broker-darwin-arm64"
	./scripts/build-embedded.sh darwin-arm64 "$(BUILD_DIR)/graphit-broker-darwin-arm64/graphit-broker" "$(VERSION)"
	cp config.example.yaml "$(BUILD_DIR)/graphit-broker-darwin-arm64/config.example.yaml"
	tar -C "$(BUILD_DIR)" -czf "$(BUILD_DIR)/graphit-broker-darwin-arm64.tar.gz" graphit-broker-darwin-arm64
	cd "$(BUILD_DIR)" && shasum -a 256 graphit-broker-darwin-arm64.tar.gz > graphit-broker-darwin-arm64.sha256

release-windows:
	rm -rf "$(BUILD_DIR)/graphit-broker-windows-amd64" "$(BUILD_DIR)/graphit-broker-windows-amd64.tar.gz" "$(BUILD_DIR)/graphit-broker-windows-amd64.sha256"
	mkdir -p "$(BUILD_DIR)/graphit-broker-windows-amd64"
	./scripts/build-embedded.sh windows-amd64 "$(BUILD_DIR)/graphit-broker-windows-amd64/graphit-broker.exe" "$(VERSION)"
	cp config.example.yaml "$(BUILD_DIR)/graphit-broker-windows-amd64/config.example.yaml"
	tar -C "$(BUILD_DIR)" -czf "$(BUILD_DIR)/graphit-broker-windows-amd64.tar.gz" graphit-broker-windows-amd64
	cd "$(BUILD_DIR)" && sha256sum graphit-broker-windows-amd64.tar.gz > graphit-broker-windows-amd64.sha256
