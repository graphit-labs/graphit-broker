FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/graphit-broker ./cmd/graphit-broker && \
    install -d -m 0700 /out/state

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/graphit-broker /graphit-broker
COPY --from=build --chown=65532:65532 --chmod=0700 /out/state /var/lib/graphit-broker
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/graphit-broker", "--healthcheck", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/graphit-broker"]
CMD ["--config", "/etc/graphit-broker/config.yaml"]
