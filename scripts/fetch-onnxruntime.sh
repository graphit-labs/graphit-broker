#!/usr/bin/env bash
set -euo pipefail

release_platform=${1:?release platform is required}
release_destination=${2:?destination directory is required}
release_project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

source "$release_project_dir/native-deps.env"

case "$release_platform" in
  linux-amd64)
    release_archive_name=$ONNXRUNTIME_LINUX_AMD64_ARCHIVE
    release_archive_sha256=$ONNXRUNTIME_LINUX_AMD64_GPU_SHA256
    ;;
  *)
    echo "unsupported ONNX Runtime release platform: $release_platform" >&2
    exit 1
    ;;
esac

if [ -e "$release_destination" ]; then
  echo "destination already exists: $release_destination" >&2
  exit 1
fi

release_cache_root=${GRAPHIT_BROKER_NATIVE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/graphit-broker/native}
release_archive_path="$release_cache_root/$release_archive_name"
release_archive_tmp="$release_archive_path.tmp.$$"
release_extract_tmp="$release_destination.tmp.$$"

cleanup_release_fetch() {
  rm -f "$release_archive_tmp"
  if [ -d "$release_extract_tmp" ]; then
    rm -rf "$release_extract_tmp"
  fi
}
trap cleanup_release_fetch EXIT

mkdir -p "$release_cache_root" "$(dirname "$release_destination")" "$release_extract_tmp"
if [ ! -f "$release_archive_path" ] || \
   [ "$(sha256sum "$release_archive_path" | awk '{print $1}')" != "$release_archive_sha256" ]; then
  curl -fL --retry 5 --retry-delay 5 --retry-all-errors --connect-timeout 30 \
    "https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/${release_archive_name}" \
    -o "$release_archive_tmp"
  echo "$release_archive_sha256  $release_archive_tmp" | sha256sum -c -
  mv "$release_archive_tmp" "$release_archive_path"
fi

echo "$release_archive_sha256  $release_archive_path" | sha256sum -c -
tar -xzf "$release_archive_path" --strip-components=1 -C "$release_extract_tmp"
test -s "$release_extract_tmp/lib/libonnxruntime.so.${ONNXRUNTIME_VERSION}"
test -s "$release_extract_tmp/lib/libonnxruntime_providers_shared.so"
test -s "$release_extract_tmp/lib/libonnxruntime_providers_cuda.so"
mv "$release_extract_tmp" "$release_destination"
trap - EXIT

echo "ONNX Runtime ${ONNXRUNTIME_VERSION} ready for ${release_platform}"
