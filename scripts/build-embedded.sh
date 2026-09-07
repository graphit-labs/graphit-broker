#!/usr/bin/env bash
set -euo pipefail

build_platform=${1:?platform is required}
build_output=${2:?output path is required}
build_version=${3:-dev}
build_flavor=${4:-default}
build_project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_payload="$build_project_dir/internal/broker/onnxruntime_payload.tar.gz"
build_metadata="$build_project_dir/.build/onnxruntime-${build_platform}.env"

case "$build_platform" in
  linux-amd64) build_goos=linux; build_goarch=amd64 ;;
  darwin-arm64) build_goos=darwin; build_goarch=arm64 ;;
  windows-amd64) build_goos=windows; build_goarch=amd64 ;;
  *) echo "unsupported embedded broker platform: $build_platform" >&2; exit 1 ;;
esac

build_host="$(go env GOHOSTOS)-$(go env GOHOSTARCH)"
if [ "$build_host" != "$build_platform" ]; then
  case "$build_platform" in
    windows-amd64)
      command -v x86_64-w64-mingw32-gcc >/dev/null
      export CC=x86_64-w64-mingw32-gcc
      ;;
    darwin-arm64)
      echo "darwin-arm64 release builds require a native macOS arm64 host and Apple SDK (the GitHub release workflow provides one)" >&2
      exit 1
      ;;
    *)
      echo "no supported cross C compiler from $build_host to $build_platform" >&2
      exit 1
      ;;
  esac
fi

cleanup_build_payload() {
  rm -f "$build_payload"
}
trap cleanup_build_payload EXIT

mkdir -p "$(dirname "$build_output")" "$(dirname "$build_metadata")"
"$build_project_dir/scripts/prepare-embedded-onnxruntime.sh" \
  "$build_platform" "$build_payload" "$build_metadata" "$build_flavor"
# shellcheck source=/dev/null
source "$build_metadata"

bundle_package=github.com/graphit-labs/graphit-broker/internal/broker
cd "$build_project_dir"
CGO_ENABLED=1 GOOS="$build_goos" GOARCH="$build_goarch" go build \
  -tags onnxruntime_embedded \
  -trimpath \
  -ldflags "-s -w -X main.version=${build_version} -X ${bundle_package}.embeddedONNXRuntimeVersion=${ONNXRUNTIME_EMBED_VERSION} -X ${bundle_package}.embeddedONNXRuntimePlatform=${ONNXRUNTIME_EMBED_PLATFORM} -X ${bundle_package}.embeddedONNXRuntimeLibrary=${ONNXRUNTIME_EMBED_LIBRARY} -X ${bundle_package}.embeddedONNXRuntimeRequiredFiles=${ONNXRUNTIME_EMBED_REQUIRED_FILES} -X ${bundle_package}.embeddedONNXRuntimeBundleSHA256=${ONNXRUNTIME_EMBED_BUNDLE_SHA256}" \
  -o "$build_output" ./cmd/graphit-auth-broker

trap - EXIT
rm -f "$build_payload"
