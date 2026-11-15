#!/bin/sh
# The schema exists twice: spec/proto is normative and protocol/api is the
# generator input. Compiled to descriptors (without source info, so comments
# and formatting do not count) the two must be identical apart from
# go_package.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

# Same pinned compiler as protocol/scripts/generate-native-proto.sh.
protoc_version=35.1
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    protoc_platform=linux-x86_64
    protoc_sha256=6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7
    ;;
  Linux:aarch64|Linux:arm64)
    protoc_platform=linux-aarch_64
    protoc_sha256=01bf9d08808c7f96678b63f4bd8efa559bb4f83d5a7a270d5edaf507f9d5d9cf
    ;;
  Darwin:x86_64)
    protoc_platform=osx-x86_64
    protoc_sha256=537d73604a344ded6fc94e98e07e529d4fe3e4a0b09e59905353950fafc2a1f7
    ;;
  Darwin:arm64)
    protoc_platform=osx-aarch_64
    protoc_sha256=193289af0470c6a1aada357d4fba0bbf8d78bfaac8b5e42ca30af2ef75583de2
    ;;
  *)
    echo "unsupported protoc host: $(uname -s) $(uname -m)" >&2
    exit 1
    ;;
esac

protoc_zip="$work/protoc.zip"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  "https://github.com/protocolbuffers/protobuf/releases/download/v$protoc_version/protoc-$protoc_version-$protoc_platform.zip" \
  --output "$protoc_zip"
if command -v sha256sum >/dev/null 2>&1; then
  printf '%s  %s\n' "$protoc_sha256" "$protoc_zip" | sha256sum --check --status
else
  actual_sha256=$(shasum -a 256 "$protoc_zip" | awk '{print $1}')
  [ "$actual_sha256" = "$protoc_sha256" ]
fi
mkdir "$work/protoc"
unzip -q "$protoc_zip" -d "$work/protoc"
protoc="$work/protoc/bin/protoc"

describe() {
  "$protoc" -I "$1" -o "$work/$2.pb" "$1/tos/service/v1/native.proto"
  "$protoc" -I "$work/protoc/include" --decode=google.protobuf.FileDescriptorSet \
    google/protobuf/descriptor.proto < "$work/$2.pb" > "$work/$2.txt"
  count=$(grep -c '^ *go_package: ' "$work/$2.txt" || true)
  if [ "$count" != 1 ]; then
    echo "$1: expected exactly one go_package option, found $count" >&2
    exit 1
  fi
  grep -v '^ *go_package: ' "$work/$2.txt" > "$work/$2.cmp"
}

describe "$repo/spec/proto" spec
describe "$repo/protocol/api" protocol
if ! diff -u "$work/spec.cmp" "$work/protocol.cmp"; then
  echo "spec/proto and protocol/api describe different schemas" >&2
  exit 1
fi
echo "spec/proto and protocol/api: identical descriptors apart from go_package ($(wc -l < "$work/spec.cmp") lines)"
