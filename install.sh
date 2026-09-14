#!/usr/bin/env sh
set -eu

repo=graphit-labs/graphit-broker
install_dir=${HOME}/.local/bin
version=${VERSION:-}

fail() { printf 'graphit-broker install: %s\n' "$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dir|--version)
      [ "$#" -ge 2 ] && [ -n "$2" ] || fail "$1 requires a value"
      if [ "$1" = --dir ]; then install_dir=$2; else version=$2; fi
      shift 2 ;;
    --dir=*) install_dir=${1#*=}; shift ;;
    --version=*) version=${1#*=}; shift ;;
    --help|-h) printf 'Usage: sh install.sh [--dir PATH] [--version vX.Y.Z]\n'; exit 0 ;;
    *) fail "unknown option $1" ;;
  esac
done
[ -n "$install_dir" ] || fail 'installation directory is empty'
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-amd64 ;;
  Darwin-arm64) platform=darwin-arm64 ;;
  *) fail 'unsupported platform (releases support Linux amd64 and macOS arm64; use install.ps1 on Windows amd64)' ;;
esac
for tool in curl tar mktemp; do command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"; done
if command -v sha256sum >/dev/null 2>&1; then hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then hash_tool=shasum
else fail 'SHA-256 verification requires sha256sum or shasum'; fi

if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1) || fail 'could not fetch latest release'
fi
printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail "invalid release tag: $version"
archive="graphit-broker-$platform.tar.gz"
checksum="graphit-broker-$platform.sha256"
base="https://github.com/$repo/releases/download/$version"
tmp=$(mktemp -d) || fail 'could not create temporary directory'
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl -fL --retry 3 "$base/$archive" -o "$tmp/$archive" || fail "download failed: $archive"
curl -fsSL --retry 3 "$base/$checksum" -o "$tmp/$checksum" || fail "download failed: $checksum"
expected=$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1; exit }' "$tmp/$checksum")
printf '%s\n' "$expected" | grep -Eq '^[a-fA-F0-9]{64}$' || fail 'release checksum missing or invalid'
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
if [ "$hash_tool" = sha256sum ]; then actual=$(sha256sum "$tmp/$archive" | awk '{print $1}')
else actual=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}'); fi
[ "$actual" = "$expected" ] || fail 'archive SHA-256 mismatch'

entry="graphit-broker-$platform/graphit-broker"
tar -tzf "$tmp/$archive" | grep -Fxq "$entry" || fail 'executable missing from archive'
mkdir -p "$install_dir" || fail "cannot create $install_dir (choose a writable --dir)"
stage=$(mktemp "$install_dir/.graphit-broker-install.XXXXXX") || fail "cannot stage in $install_dir"
trap 'rm -f "$stage"; rm -rf "$tmp"' EXIT HUP INT TERM
tar -xOzf "$tmp/$archive" "$entry" > "$stage" || fail 'could not extract executable'
[ -s "$stage" ] || fail 'release executable is empty'
chmod 755 "$stage"
mv -f "$stage" "$install_dir/graphit-broker" || fail 'could not install executable'
printf 'Installed graphit-broker %s at %s/graphit-broker\n' "$version" "$install_dir"
case ":$PATH:" in *":$install_dir:"*) ;; *) printf 'Add %s to PATH to run graphit-broker.\n' "$install_dir" ;; esac
printf 'Create your config separately; see docs/binary.md.\n'
