ARG GO_VERSION=1.26.6

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/graphit-broker ./cmd/graphit-auth-broker

FROM debian:bookworm-slim AS onnxruntime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar && rm -rf /var/lib/apt/lists/*
COPY native-deps.env /tmp/native-deps.env
RUN . /tmp/native-deps.env && \
    curl -fL --retry 5 --connect-timeout 30 \
      "https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/${ONNXRUNTIME_LINUX_AMD64_ARCHIVE}" \
      -o /tmp/onnxruntime.tgz && \
    echo "${ONNXRUNTIME_LINUX_AMD64_GPU_SHA256}  /tmp/onnxruntime.tgz" | sha256sum -c - && \
    mkdir -p /opt/onnxruntime && \
    tar -xzf /tmp/onnxruntime.tgz --strip-components=1 -C /opt/onnxruntime && \
    rm /tmp/onnxruntime.tgz

FROM nvidia/cuda:12.8.1-cudnn-runtime-ubuntu24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgomp1 && rm -rf /var/lib/apt/lists/*
COPY --from=onnxruntime /opt/onnxruntime /opt/onnxruntime
COPY --from=build /out/graphit-broker /graphit-broker
COPY --chown=65532:65532 --chmod=0600 config.example.yaml /etc/graphit-broker/config.yaml
RUN install -d -o 65532 -g 65532 -m 0700 /var/lib/graphit-broker /var/cache/graphit-broker/models && \
    chown -R 65532:65532 /etc/graphit-broker
ENV ONNXRUNTIME_SHARED_LIBRARY_PATH=/opt/onnxruntime/lib/libonnxruntime.so
ENV LD_LIBRARY_PATH=/opt/onnxruntime/lib:${LD_LIBRARY_PATH}
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/graphit-broker", "--healthcheck", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/graphit-broker"]
CMD ["--config", "/etc/graphit-broker/config.yaml"]
