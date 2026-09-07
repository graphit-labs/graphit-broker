.PHONY: build fmt vet test check docker-build release-linux

include native-deps.env

VERSION ?= dev
BUILD_DIR ?= .build
ORT_RELEASE_DIR := $(BUILD_DIR)/onnxruntime-linux-amd64
LINUX_RELEASE_DIR := $(BUILD_DIR)/graphit-broker-linux-amd64

build:
	go build -ldflags "-s -w -X main.version=$(VERSION)" ./cmd/graphit-auth-broker

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...

test:
	go test ./...

check:
	go vet ./...
	go test ./...

docker-build:
	docker build -t graphit-broker:dev .

release-linux:
	rm -rf "$(ORT_RELEASE_DIR)" "$(LINUX_RELEASE_DIR)" \
		"$(BUILD_DIR)/graphit-broker-linux-amd64.tar.gz" \
		"$(BUILD_DIR)/graphit-broker-linux-amd64.sha256"
	mkdir -p "$(LINUX_RELEASE_DIR)/lib"
	./scripts/fetch-onnxruntime.sh linux-amd64 "$(ORT_RELEASE_DIR)"
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-ldflags "-s -w -X main.version=$(VERSION)" \
		-o "$(LINUX_RELEASE_DIR)/graphit-broker" ./cmd/graphit-auth-broker
	cp config.example.yaml "$(LINUX_RELEASE_DIR)/config.example.yaml"
	cp -L "$(ORT_RELEASE_DIR)/lib/libonnxruntime.so.$(ONNXRUNTIME_VERSION)" "$(LINUX_RELEASE_DIR)/lib/"
	ln -s "libonnxruntime.so.$(ONNXRUNTIME_VERSION)" "$(LINUX_RELEASE_DIR)/lib/libonnxruntime.so"
	cp -L "$(ORT_RELEASE_DIR)/lib/libonnxruntime_providers_shared.so" "$(LINUX_RELEASE_DIR)/lib/"
	cp -L "$(ORT_RELEASE_DIR)/lib/libonnxruntime_providers_cuda.so" "$(LINUX_RELEASE_DIR)/lib/"
	tar -C "$(BUILD_DIR)" -czf "$(BUILD_DIR)/graphit-broker-linux-amd64.tar.gz" graphit-broker-linux-amd64
	cd "$(BUILD_DIR)" && sha256sum graphit-broker-linux-amd64.tar.gz > graphit-broker-linux-amd64.sha256
