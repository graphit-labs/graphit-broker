.PHONY: build fmt vet test check docker-build

build:
	go build ./cmd/graphit-broker

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
