.PHONY: build install fmt vet lint test check qualify docker-build docker-check

ifeq ($(OS),Windows_NT)
SHELL := sh
PREFIX ?= $(LOCALAPPDATA)/Programs/graphit-broker
else
PREFIX ?= /usr/local/bin
endif
HOST_BINARY := graphit-broker$(if $(filter Windows_NT,$(OS)),.exe,)

build:
	cargo run --locked --quiet -p xtask -- build --output "$(HOST_BINARY)"

install: build
	@set -eu; \
	context=$$(mktemp -d); \
	trap 'rm -rf "$$context"' EXIT HUP INT TERM; \
	cargo run --release --locked --offline --quiet -p xtask -- package \
	  --binary "./$(HOST_BINARY)" --output "$$context/installer-package"; \
	set -- "$$context"/installer-package/*.tar.gz; \
	[ "$$#" -eq 1 ] && [ -f "$$1" ]; \
	archive=$$1; \
	mkdir -p "$(PREFIX)"; \
	if [ "$(OS)" = Windows_NT ]; then \
	  powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1 -Archive "$$archive" -Dir "$(PREFIX)"; \
	elif [ -w "$(PREFIX)" ]; then \
	  sh install.sh --archive "$$archive" --dir "$(PREFIX)"; \
	else \
	  sudo sh install.sh --archive "$$archive" --dir "$(PREFIX)"; \
	fi

fmt:
	cargo fmt --all

vet:
	cargo clippy --locked --offline --workspace --all-targets -- -D warnings

lint: vet

test:
	cargo test --locked --offline --workspace --all-targets --no-fail-fast

check:
	cargo run --locked --offline --quiet --target host-tuple -p xtask -- hook pre-push

qualify:
	cargo run --locked --quiet --target host-tuple -p xtask -- qualify

docker-build: build
	@set -eu; \
	context=$$(mktemp -d); \
	trap 'rm -rf "$$context"' EXIT HUP INT TERM; \
	cp Dockerfile .dockerignore docker-entrypoint.sh "$$context/"; \
	cargo run --release --locked --offline --quiet -p xtask -- package \
	  --binary "./$(HOST_BINARY)" --output "$$context/installer-package"; \
	docker build -t graphit-broker:dev "$$context"

docker-check:
	cargo test --locked --offline -j4 -p broker-server --test container -- --ignored --exact broker_native_container_contract --test-threads=1
