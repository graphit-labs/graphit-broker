#!/bin/sh
set -eu

image=${1:?usage: scripts/container-smoke.sh IMAGE}
workspace=$(mktemp -d)
container="graphit-broker-smoke-$$"

cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker run --rm --user 0:0 --entrypoint /bin/chmod \
        -v "$workspace:/workspace" "$image" -R a+rwx /workspace >/dev/null 2>&1 || true
    rm -rf "$workspace" || true
}
trap cleanup EXIT INT TERM

docker image inspect "$image" >/dev/null
test "$(docker image inspect --format '{{.Config.User}}' "$image")" = "graphit:graphit"
docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" | grep -Fx 'GRAPHIT_GLOBAL_DIR=/home/graphit/.graphit'
docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" | grep -Fx 'GRAPHIT_BROKER_CONFIG=/home/graphit/.graphit/broker/config.yaml'
docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" | grep -Fx 'GRAPHIT_BROKER_HEALTHCHECK_URL=http://127.0.0.1:8080/readyz'
if docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" | grep -Eq '^(BROKER_DATABASE_DSN|BROKER_MODELS_DIRECTORY)='; then
    echo "container image must not prescribe database or model environment variables" >&2
    exit 1
fi
test "$(docker image inspect --format '{{.Config.WorkingDir}}' "$image")" = '/home/graphit/.graphit/broker'
test "$(docker image inspect --format '{{len .Config.Volumes}}' "$image")" = 2
docker image inspect --format '{{json .Config.Volumes}}' "$image" | grep -F '"/home/graphit/.graphit/broker"'
docker image inspect --format '{{json .Config.Volumes}}' "$image" | grep -F '"/var/lib/graphit/hub"'
docker image inspect --format '{{json .Config.Healthcheck.Test}}' "$image" | grep -F 'GRAPHIT_BROKER_HEALTHCHECK_URL'

if missing_output=$(docker run --rm "$image" --version 2>&1); then
    echo "container unexpectedly started without GRAPHIT_BROKER_CONFIG" >&2
    exit 1
fi
printf '%s\n' "$missing_output" | grep -F 'GRAPHIT_BROKER_CONFIG'

docker run --rm --entrypoint /bin/sh "$image" -c '
    test "$(id -un)" = graphit
    test "$(id -gn)" = graphit
    test "$(id -u)" = 10001
    test "$(id -g)" = 10001
'

mkdir "$workspace/writable"
chmod 0777 "$workspace/writable"
mkdir "$workspace/writable/broker"
chmod 0777 "$workspace/writable/broker"
cp examples/health-only.yaml "$workspace/writable/broker/config.yaml"
chmod 0644 "$workspace/writable/broker/config.yaml"
docker run --rm \
    -e GRAPHIT_GLOBAL_DIR=/mnt/graphit \
    -e GRAPHIT_BROKER_CONFIG=/mnt/graphit/broker/config.yaml \
    -v "$workspace/writable:/mnt/graphit" \
    "$image" --version >/dev/null
docker run --rm --user 0:0 --entrypoint /bin/sh \
    -v "$workspace/writable:/mnt/graphit" \
    "$image" -c 'test -d /mnt/graphit/broker/runtime/onnxruntime'

mkdir -p "$workspace/hooks/init.d" "$workspace/hooks/pre-start.d" "$workspace/hooks-global"
chmod 0777 "$workspace/hooks-global"
cat > "$workspace/hooks/init.d/10-create-config.sh" <<'EOF'
#!/bin/sh
set -eu
test "$(id -u)" = 10001
test ! -d "$GRAPHIT_GLOBAL_DIR/broker"
mkdir -p "$GRAPHIT_GLOBAL_DIR/broker"
cp /tmp/health-only.yaml "$GRAPHIT_BROKER_CONFIG"
printf 'init-10\n' >> "$GRAPHIT_GLOBAL_DIR/hooks.trace"
EOF
cat > "$workspace/hooks/init.d/20-order.sh" <<'EOF'
#!/bin/sh
set -eu
test "$(cat "$GRAPHIT_GLOBAL_DIR/hooks.trace")" = init-10
printf 'init-20\n' >> "$GRAPHIT_GLOBAL_DIR/hooks.trace"
EOF
cat > "$workspace/hooks/init.d/30-executable" <<'EOF'
#!/bin/sh
set -eu
printf 'init-30\n' >> "$GRAPHIT_GLOBAL_DIR/hooks.trace"
EOF
chmod 0755 "$workspace/hooks/init.d/30-executable"
cat > "$workspace/hooks/pre-start.d/10-config.sh" <<'EOF'
#!/bin/sh
set -eu
test -r "$GRAPHIT_BROKER_CONFIG"
test "$(cat "$GRAPHIT_GLOBAL_DIR/hooks.trace")" = "$(printf 'init-10\ninit-20\ninit-30')"
printf 'pre-start-10\n' >> "$GRAPHIT_GLOBAL_DIR/hooks.trace"
EOF
cat > "$workspace/hooks/pre-start.d/20-order.sh" <<'EOF'
#!/bin/sh
set -eu
printf 'pre-start-20\n' >> "$GRAPHIT_GLOBAL_DIR/hooks.trace"
EOF
docker run --rm \
    -e GRAPHIT_GLOBAL_DIR=/mnt/graphit \
    -e GRAPHIT_BROKER_CONFIG=/mnt/graphit/broker/config.yaml \
    -v "$workspace/hooks-global:/mnt/graphit" \
    -v "$workspace/hooks:/docker-entrypoint.d:ro" \
    -v "$PWD/examples/health-only.yaml:/tmp/health-only.yaml:ro" \
    "$image" --version >/dev/null
test "$(cat "$workspace/hooks-global/hooks.trace")" = "$(printf 'init-10\ninit-20\ninit-30\npre-start-10\npre-start-20')"
test -f "$workspace/hooks-global/broker/config.yaml"
test ! -e "$workspace/hooks-global/init.d"
test ! -e "$workspace/hooks-global/pre-start.d"

mkdir -p "$workspace/fail-init/init.d" "$workspace/fail-pre-start/pre-start.d"
printf '#!/bin/sh\nexit 42\n' > "$workspace/fail-init/init.d/10-fail.sh"
printf '#!/bin/sh\nexit 43\n' > "$workspace/fail-pre-start/pre-start.d/10-fail.sh"
if fail_output=$(docker run --rm \
    -v "$workspace/writable:/mnt/graphit" \
    -e GRAPHIT_GLOBAL_DIR=/mnt/graphit \
    -e GRAPHIT_BROKER_CONFIG=/mnt/graphit/broker/config.yaml \
    -v "$workspace/fail-init:/docker-entrypoint.d:ro" \
    "$image" --version 2>&1); then
    echo "container unexpectedly continued after init.d hook failure" >&2
    exit 1
else
    test "$?" -eq 42
fi
printf '%s\n' "$fail_output" | grep -F '10-fail.sh' | grep -F 'failed with exit code 42'
if fail_output=$(docker run --rm \
    -v "$workspace/writable:/mnt/graphit" \
    -e GRAPHIT_GLOBAL_DIR=/mnt/graphit \
    -e GRAPHIT_BROKER_CONFIG=/mnt/graphit/broker/config.yaml \
    -v "$workspace/fail-pre-start:/docker-entrypoint.d:ro" \
    "$image" --version 2>&1); then
    echo "container unexpectedly continued after pre-start.d hook failure" >&2
    exit 1
else
    test "$?" -eq 43
fi
printf '%s\n' "$fail_output" | grep -F '10-fail.sh' | grep -F 'failed with exit code 43'

mkdir "$workspace/blocked"
chmod 000 "$workspace/blocked"
if blocked_output=$(docker run --rm \
    -e GRAPHIT_GLOBAL_DIR=/mnt/graphit \
    -v "$workspace/blocked:/mnt/graphit" \
    "$image" --version 2>&1); then
    echo "container unexpectedly accepted a GRAPHIT_GLOBAL_DIR without rwx" >&2
    exit 1
fi
printf '%s\n' "$blocked_output" | grep -E 'cannot create GRAPHIT_GLOBAL_DIR|must be a directory readable, writable, and executable'

mkdir "$workspace/service"
chmod 0777 "$workspace/service"
cp examples/health-only.yaml "$workspace/service/config.yaml"
chmod 0644 "$workspace/service/config.yaml"
docker run --detach --name "$container" \
    -e GRAPHIT_BROKER_HEALTHCHECK_URL='http://127.0.0.1:8080/readyz?container-smoke=1' \
    --mount "type=bind,src=$workspace/service,dst=/home/graphit/.graphit/broker" \
    "$image" >/dev/null

attempt=0
while [ "$attempt" -lt 90 ]; do
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$container")
    if [ "$health" = healthy ]; then
        break
    fi
    if [ "$health" = unhealthy ] || [ "$(docker inspect --format '{{.State.Running}}' "$container")" != true ]; then
        docker logs "$container" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 1
done
test "${health:-missing}" = healthy
docker exec "$container" /bin/sh -c 'test -f /home/graphit/.graphit/broker/broker.db'
docker exec "$container" /usr/local/bin/graphit-broker --healthcheck http://127.0.0.1:8080/healthz
docker exec "$container" /usr/local/bin/graphit-broker --healthcheck http://127.0.0.1:8080/readyz
