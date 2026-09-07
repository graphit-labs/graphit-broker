#!/usr/bin/env bash
set -euo pipefail

embed_platform=${1:?platform is required}
embed_payload=${2:?payload destination is required}
embed_metadata=${3:?metadata destination is required}
embed_flavor=${4:-default}
embed_project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# shellcheck source=/dev/null
source "$embed_project_dir/native-deps.env"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

case "$embed_platform" in
  linux-amd64)
    embed_library="libonnxruntime.so.${ONNXRUNTIME_VERSION}"
    if [ "$embed_flavor" = default ] || [ "$embed_flavor" = gpu ]; then
      embed_archive=$ONNXRUNTIME_LINUX_AMD64_ARCHIVE
      embed_archive_sha=$ONNXRUNTIME_LINUX_AMD64_GPU_SHA256
      embed_required="${embed_library},libonnxruntime_providers_shared.so,libonnxruntime_providers_cuda.so"
      embed_resolved_flavor=gpu
    elif [ "$embed_flavor" = cpu ]; then
      embed_archive=$ONNXRUNTIME_LINUX_AMD64_CPU_ARCHIVE
      embed_archive_sha=$ONNXRUNTIME_LINUX_AMD64_CPU_SHA256
      embed_required="${embed_library}"
      embed_resolved_flavor=cpu
    else
      echo "unsupported embedded ONNX Runtime flavor for $embed_platform: $embed_flavor" >&2
      exit 1
    fi
    ;;
  darwin-arm64)
    if [ "$embed_flavor" != default ] && [ "$embed_flavor" != cpu ]; then
      echo "unsupported embedded ONNX Runtime flavor for $embed_platform: $embed_flavor" >&2
      exit 1
    fi
    embed_archive=$ONNXRUNTIME_DARWIN_ARM64_ARCHIVE
    embed_archive_sha=$ONNXRUNTIME_DARWIN_ARM64_SHA256
    embed_library="libonnxruntime.${ONNXRUNTIME_VERSION}.dylib"
    embed_required="${embed_library}"
    embed_resolved_flavor=coreml
    ;;
  windows-amd64)
    embed_library="onnxruntime.dll"
    if [ "$embed_flavor" = default ] || [ "$embed_flavor" = gpu ]; then
      embed_archive=$ONNXRUNTIME_WINDOWS_AMD64_ARCHIVE
      embed_archive_sha=$ONNXRUNTIME_WINDOWS_AMD64_GPU_SHA256
      embed_required="${embed_library},onnxruntime_providers_shared.dll,onnxruntime_providers_cuda.dll"
      embed_resolved_flavor=gpu
    elif [ "$embed_flavor" = cpu ]; then
      embed_archive=$ONNXRUNTIME_WINDOWS_AMD64_CPU_ARCHIVE
      embed_archive_sha=$ONNXRUNTIME_WINDOWS_AMD64_CPU_SHA256
      embed_required="${embed_library}"
      embed_resolved_flavor=cpu
    else
      echo "unsupported embedded ONNX Runtime flavor for $embed_platform: $embed_flavor" >&2
      exit 1
    fi
    ;;
  *)
    echo "unsupported embedded ONNX Runtime platform: $embed_platform" >&2
    exit 1
    ;;
esac

embed_cache_root=${GRAPHIT_BROKER_NATIVE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/graphit-broker/native}
embed_archive_path="$embed_cache_root/$embed_archive"
embed_archive_tmp="$embed_archive_path.tmp.$$"
embed_work=$(mktemp -d "${TMPDIR:-/tmp}/graphit-broker-onnxruntime.XXXXXX")
embed_payload_tmp="$embed_payload.tmp.$$"
embed_metadata_tmp="$embed_metadata.tmp.$$"

cleanup_embed() {
  rm -f "$embed_archive_tmp" "$embed_payload_tmp" "$embed_metadata_tmp"
  rm -rf "$embed_work"
}
trap cleanup_embed EXIT

mkdir -p "$embed_cache_root" "$(dirname "$embed_payload")" "$(dirname "$embed_metadata")"
if [ ! -f "$embed_archive_path" ] || [ "$(hash_file "$embed_archive_path")" != "$embed_archive_sha" ]; then
  curl -fL --retry 5 --retry-delay 5 --retry-all-errors --connect-timeout 30 \
    "https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/${embed_archive}" \
    -o "$embed_archive_tmp"
  if [ "$(hash_file "$embed_archive_tmp")" != "$embed_archive_sha" ]; then
    echo "ONNX Runtime archive checksum mismatch for $embed_platform" >&2
    exit 1
  fi
  mv "$embed_archive_tmp" "$embed_archive_path"
fi
if [ "$(hash_file "$embed_archive_path")" != "$embed_archive_sha" ]; then
  echo "cached ONNX Runtime archive checksum mismatch for $embed_platform" >&2
  exit 1
fi

mkdir -p "$embed_work/extracted" "$embed_work/payload"
case "$embed_archive" in
  *.zip) unzip -q "$embed_archive_path" -d "$embed_work/extracted" ;;
  *.tgz|*.tar.gz) tar -xzf "$embed_archive_path" -C "$embed_work/extracted" ;;
  *) echo "unsupported ONNX Runtime archive: $embed_archive" >&2; exit 1 ;;
esac

IFS=',' read -r -a embed_files <<< "$embed_required"
for embed_name in "${embed_files[@]}"; do
  embed_source=$(find "$embed_work/extracted" -type f -name "$embed_name" -print -quit)
  if [ -z "$embed_source" ]; then
    echo "ONNX Runtime archive does not contain $embed_name" >&2
    exit 1
  fi
  cp -L "$embed_source" "$embed_work/payload/$embed_name"
  chmod 0500 "$embed_work/payload/$embed_name"
  touch -t 197001010000.00 "$embed_work/payload/$embed_name"
done

if [ "$embed_platform" = darwin-arm64 ]; then
  if command -v llvm-nm >/dev/null 2>&1; then
    embed_coreml_symbols=$(llvm-nm -g "$embed_work/payload/$embed_library" 2>/dev/null || true)
  else
    embed_coreml_symbols=$(nm -g "$embed_work/payload/$embed_library" 2>/dev/null || true)
  fi
  if ! grep -q 'OrtSessionOptionsAppendExecutionProvider_CoreML' <<< "$embed_coreml_symbols"; then
    echo "macOS ONNX Runtime archive does not export the CoreML execution provider" >&2
    exit 1
  fi
fi

if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  LC_ALL=C tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -cf - -C "$embed_work/payload" . | gzip -n -9 > "$embed_payload_tmp"
else
  LC_ALL=C tar --format ustar --uid 0 --gid 0 --uname root --gname root \
    -cf - -C "$embed_work/payload" "${embed_files[@]}" | gzip -n -9 > "$embed_payload_tmp"
fi
embed_bundle_sha=$(hash_file "$embed_payload_tmp")
mv "$embed_payload_tmp" "$embed_payload"

{
  printf "ONNXRUNTIME_EMBED_VERSION='%s'\n" "$ONNXRUNTIME_VERSION"
  printf "ONNXRUNTIME_EMBED_PLATFORM='%s'\n" "$embed_platform"
  printf "ONNXRUNTIME_EMBED_LIBRARY='%s'\n" "$embed_library"
  printf "ONNXRUNTIME_EMBED_REQUIRED_FILES='%s'\n" "$embed_required"
  printf "ONNXRUNTIME_EMBED_BUNDLE_SHA256='%s'\n" "$embed_bundle_sha"
} > "$embed_metadata_tmp"
mv "$embed_metadata_tmp" "$embed_metadata"

trap - EXIT
rm -rf "$embed_work"
echo "Embedded ONNX Runtime ${ONNXRUNTIME_VERSION} ${embed_resolved_flavor} payload ready for ${embed_platform} (${embed_bundle_sha})"
