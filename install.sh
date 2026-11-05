#!/usr/bin/env sh
set -eu

repo=graphit-labs/graphit-broker
install_dir=${HOME}/.local/bin
version=${VERSION:-}
archive_path=

fail() { printf 'graphit-broker install: %s\n' "$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dir|--version|--archive)
      [ "$#" -ge 2 ] && [ -n "$2" ] || fail "$1 requires a value"
      case "$1" in
        --dir) install_dir=$2 ;;
        --version) version=$2 ;;
        --archive) archive_path=$2 ;;
      esac
      shift 2 ;;
    --dir=*) install_dir=${1#*=}; shift ;;
    --version=*) version=${1#*=}; shift ;;
    --archive=*) archive_path=${1#*=}; [ -n "$archive_path" ] || fail '--archive requires a value'; shift ;;
    --help|-h) printf 'Usage: sh install.sh [--dir PATH] [--version vX.Y.Z | --archive PATH]\n'; exit 0 ;;
    *) fail "unknown option $1" ;;
  esac
done
[ -n "$install_dir" ] || fail 'installation directory is empty'
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-amd64 ;;
  Darwin-arm64) platform=darwin-arm64 ;;
  *) fail 'unsupported platform (releases support Linux amd64 and macOS arm64; use install.ps1 on Windows amd64)' ;;
esac
for tool in tar mktemp; do command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"; done
if command -v sha256sum >/dev/null 2>&1; then hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then hash_tool=shasum
else fail 'SHA-256 verification requires sha256sum or shasum'; fi

archive="graphit-broker-$platform.tar.gz"
checksum="graphit-broker-$platform.sha256"
if [ -n "$archive_path" ]; then
  [ -z "$version" ] || fail '--archive and --version cannot be combined'
  case "$archive_path" in *.tar.gz) ;; *) fail '--archive requires a .tar.gz release archive' ;; esac
  [ -s "$archive_path" ] && [ -s "${archive_path%.tar.gz}.sha256" ] || fail 'local archive or adjacent .sha256 is missing'
  version='local archive'
else
  command -v curl >/dev/null 2>&1 || fail 'missing required tool: curl'
  if [ -z "$version" ]; then
    version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1) || fail 'could not fetch latest release'
  fi
  printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail "invalid release tag: $version"
fi
tmp=$(mktemp -d) || fail 'could not create temporary directory'
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
if [ -n "$archive_path" ]; then
  cp "$archive_path" "$tmp/$archive" || fail 'could not stage local archive'
  cp "${archive_path%.tar.gz}.sha256" "$tmp/$checksum" || fail 'could not stage local checksum'
else
  base="https://github.com/$repo/releases/download/$version"
  curl -fL --retry 3 "$base/$archive" -o "$tmp/$archive" || fail "download failed: $archive"
  curl -fsSL --retry 3 "$base/$checksum" -o "$tmp/$checksum" || fail "download failed: $checksum"
fi
expected=$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1; exit }' "$tmp/$checksum")
printf '%s\n' "$expected" | grep -Eq '^[a-fA-F0-9]{64}$' || fail 'release checksum missing or invalid'
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
if [ "$hash_tool" = sha256sum ]; then actual=$(sha256sum "$tmp/$archive" | awk '{print $1}')
else actual=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}'); fi
[ "$actual" = "$expected" ] || fail 'archive SHA-256 mismatch'

entry="graphit-broker-$platform/graphit-broker"
root="graphit-broker-$platform"
tar -tzf "$tmp/$archive" > "$tmp/entries" || fail 'could not list archive'
grep -Fxq "$entry" "$tmp/entries" || fail 'executable missing from archive'
while IFS= read -r member; do
  case "$member" in
    "$entry"|"$root/graphit-runtime/licenses/broker/LICENSE"|"$root/graphit-runtime/licenses/broker/ggml/LICENSE"|"$root/graphit-runtime/licenses/broker/ggml/LICENSE-MIT"|"$root/graphit-runtime/licenses/broker/ggml/LICENSE-APACHE"|"$root/graphit-runtime/licenses/broker/nvidia/LICENSE"|"$root/graphit-runtime/licenses/broker/ggml/licenses/LICENSE-jsonhpp") ;;
    "$root/graphit-runtime/broker/linux-libraries.json") [ "$platform" = linux-amd64 ] || fail 'Linux runtime on unsupported platform' ;;
    "$root/graphit-runtime/broker/macos-libraries.json") [ "$platform" = darwin-arm64 ] || fail 'macOS runtime on unsupported platform' ;;
    "$root/graphit-runtime/broker/licenses/darwin-arm64/OpenSSL-LICENSE.txt") [ "$platform" = darwin-arm64 ] || fail 'macOS runtime on unsupported platform' ;;
    "$root/graphit-runtime/broker/lib/"*)
      name=${member##*/}
      [ "$member" = "$root/graphit-runtime/broker/lib/$name" ] || fail 'invalid runtime library path'
      case "$name" in ''|*[!A-Za-z0-9._+-]*) fail 'invalid runtime library name' ;; esac
      case "$platform:$name" in linux-amd64:lib*.so|linux-amd64:lib*.so.*|darwin-arm64:lib*.dylib) ;; *) fail 'invalid runtime library name' ;; esac ;;
    "$root/graphit-runtime/licenses/broker/linux/"*)
      [ "$platform" = linux-amd64 ] || fail 'Linux runtime on unsupported platform'
      name=${member##*/}
      [ "$member" = "$root/graphit-runtime/licenses/broker/linux/$name" ] || fail 'invalid Linux notice path'
      case "$name" in ''|*[!A-Za-z0-9._+-]*) fail 'invalid Linux notice name' ;; esac
      case "$name" in GPL-3|lib*.copyright) ;; *) fail 'invalid Linux notice name' ;; esac ;;
    *) fail 'unexpected archive member' ;;
  esac
done < "$tmp/entries"
[ "$(sort "$tmp/entries" | uniq -d | wc -l)" -eq 0 ] || fail 'duplicate archive member'
tar -tvzf "$tmp/$archive" > "$tmp/types" || fail 'could not inspect archive'
while IFS= read -r member; do
  case "$member" in -*) ;; *) fail 'archive members must be regular files' ;; esac
done < "$tmp/types"
mkdir "$tmp/extracted"
tar -xzf "$tmp/$archive" -C "$tmp/extracted" || fail 'could not extract archive'
payload="$tmp/extracted/$root"
for notice in licenses/broker/LICENSE licenses/broker/ggml/LICENSE licenses/broker/ggml/LICENSE-MIT licenses/broker/ggml/LICENSE-APACHE licenses/broker/nvidia/LICENSE licenses/broker/ggml/licenses/LICENSE-jsonhpp; do
  [ -s "$payload/graphit-runtime/$notice" ] || fail 'required native license missing'
done
if [ "$platform" = linux-amd64 ]; then
  [ -s "$payload/graphit-runtime/broker/linux-libraries.json" ] || fail 'Linux runtime manifest missing'
  for library in "$payload/graphit-runtime/broker/lib/"*; do
    [ -e "$library" ] || continue
    name=${library##*/}
    # Cargo engine and NVIDIA licenses were validated above; only OS libraries
    # use distribution copyright files and the GCC runtime notice.
    case "$name" in
      libllama.so|libggml.so|libggml-base.so|libggml-cpu.so|libggml-cuda.so|libcudart.so.12|libcublas.so.12|libcublasLt.so.12|libcudart.so.13|libcublas.so.13|libcublasLt.so.13) continue ;;
    esac
    [ -s "$payload/graphit-runtime/licenses/broker/linux/$name.copyright" ] &&
      [ -s "$payload/graphit-runtime/licenses/broker/linux/GPL-3" ] || fail 'Linux runtime license missing'
  done
fi
if [ "$platform" = darwin-arm64 ]; then
  [ -s "$payload/graphit-runtime/broker/macos-libraries.json" ] || fail 'macOS runtime manifest missing'
  for library in "$payload/graphit-runtime/broker/lib/"*.dylib; do
    [ -e "$library" ] || continue
    [ -s "$payload/graphit-runtime/broker/licenses/darwin-arm64/OpenSSL-LICENSE.txt" ] || fail 'macOS runtime license missing'
  done
fi
mkdir -p "$install_dir" || fail "cannot create $install_dir (choose a writable --dir)"
stage=$(mktemp "$install_dir/.graphit-broker-install.XXXXXX") || fail "cannot stage in $install_dir"
trap 'rm -f "$stage"; rm -rf "$tmp"' EXIT HUP INT TERM
cat "$payload/graphit-broker" > "$stage" || fail 'could not stage executable'
[ -s "$stage" ] || fail 'release executable is empty'
chmod 755 "$stage"
# Install each sidecar through its own rename, preserving mappings held by active
# processes. Shared native notices are not deleted by another product's package.
while IFS= read -r member; do
  [ "$member" != "$entry" ] || continue
  relative=${member#"$root/"}
  target="$install_dir/$relative"
  mkdir -p "${target%/*}" || fail 'cannot create runtime directory'
  asset_stage=$(mktemp "${target%/*}/.broker-asset.XXXXXX") || fail 'cannot stage runtime asset'
  if ! cat "$payload/$relative" > "$asset_stage" || ! chmod 644 "$asset_stage" || ! mv -f "$asset_stage" "$target"; then
    rm -f "$asset_stage"
    fail 'could not publish runtime asset'
  fi
done < "$tmp/entries"
mv -f "$stage" "$install_dir/graphit-broker" || fail 'could not install executable'
printf 'Installed graphit-broker %s at %s/graphit-broker\n' "$version" "$install_dir"
case ":$PATH:" in *":$install_dir:"*) ;; *) printf 'Add %s to PATH to run graphit-broker.\n' "$install_dir" ;; esac
printf 'Create your config separately; see docs/binary.md.\n'
