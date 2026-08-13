#!/usr/bin/env bash
# ASSCOR Cross-Compilation Build Script
# Builds all three binaries for Linux amd64
# Usage: ./scripts/build.sh [version]

set -euo pipefail

VERSION="${1:-dev}"
BUILD_DIR="build"
# 内核可选模块 build-tag（微内核零膨胀：去掉 tag 编译最小内核）
MODULE_TAGS="heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper"
BINARIES=(
    "cmd/kernel:ASSCOR-kernel-linux-amd64"
    "cmd/agent:ASSCOR-agent-linux-amd64"
    "cmd/asscor:ASSCOR-linux-amd64"
)

export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

echo "=== ASSCOR Build ==="
echo "Version:  $VERSION"
echo "Platform: ${GOOS}/${GOARCH}"
echo "Output:   ${BUILD_DIR}/"
echo ""

mkdir -p "${BUILD_DIR}"

for entry in "${BINARIES[@]}"; do
    IFS=":" read -r src name <<< "$entry"
    echo "Building ${name}..."
    TAGS=""
    case "${src}" in
        cmd/kernel) TAGS="${MODULE_TAGS}" ;;
        cmd/asscor) TAGS="spc,attck_ext" ;;
    esac
    go build \
        -tags "${TAGS}" \
        -ldflags="-s -w -X github.com/asscor/asscor/internal/version.ASSCORVersion=${VERSION}" \
        -o "${BUILD_DIR}/${name}" \
        "./${src}"
    echo "  $(du -h "${BUILD_DIR}/${name}" | cut -f1)  ${name}"
done

cp config.ini agent.ini "${BUILD_DIR}/"
cp -r config/ "${BUILD_DIR}/"

echo ""
echo "Build complete: ${BUILD_DIR}/"
ls -lh "${BUILD_DIR}"/*-linux-amd64
