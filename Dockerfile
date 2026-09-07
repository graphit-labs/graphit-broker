ARG GO_VERSION=1.26.6

FROM golang:${GO_VERSION}-bookworm AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/.cache/graphit-broker/native \
    ./scripts/build-embedded.sh linux-amd64 /out/graphit-broker "$VERSION" gpu

FROM nvidia/cuda:12.8.1-cudnn-runtime-ubuntu24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgomp1 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/graphit-broker /graphit-broker
COPY --chown=65532:65532 --chmod=0600 config.example.yaml /etc/graphit-broker/config.yaml
RUN install -d -o 65532 -g 65532 -m 0700 /var/lib/graphit-broker /var/cache/graphit-broker/models && \
    chown -R 65532:65532 /etc/graphit-broker
ENV GRAPHIT_GLOBAL_DIR=/var/lib/graphit-broker/.graphit
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/graphit-broker", "--healthcheck", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/graphit-broker"]
CMD ["--config", "/etc/graphit-broker/config.yaml"]
