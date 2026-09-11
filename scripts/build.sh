#!/usr/bin/env bash
# ASSCOR Cross-Compilation Build Script
# Builds all three binaries for Linux amd64
# Usage: ./scripts/build.sh [version]

set -euo pipefail

VERSION="${1:-dev}"
BUILD_DIR="build"
# 内核可选模块 build-tag（微内核零膨胀：去掉 tag 编译最小内核）
MODULE_TAGS="heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine,oscal,expr,edgeexp"
BINARIES=(
    "cmd/kernel:ASSCOR-kernel-linux-amd64"
    "cmd/agent:ASSCOR-agent-linux-amd64"
    "cmd/asscor:ASSCOR-linux-amd64"
    # 实验场景采集器（cmd/edgescen）：实验矩阵要在目标机上跑它，故与三个主二进制一起交叉编译。
    # 它自己的最小 tag 集是 expr,engine,checks（见 cmd/edgescen/main.go 的文件头），
    # 这里沿用 MODULE_TAGS（超集）与 cmd/kernel 同款，避免脚本里再维护第二份 tag 清单。
    "cmd/edgescen:edgescen-linux-amd64"
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
        cmd/agent) TAGS="checks" ;;
        cmd/asscor) TAGS="engine,checks,adapter,spc,attck_ext" ;;
        cmd/edgescen) TAGS="${MODULE_TAGS}" ;;
    esac
    go build \
        -tags "${TAGS}" \
        -ldflags="-s -w -X github.com/chins-xing/asscor/internal/version.ASSCORVersion=${VERSION}" \
        -o "${BUILD_DIR}/${name}" \
        "./${src}"
    echo "  $(du -h "${BUILD_DIR}/${name}" | cut -f1)  ${name}"
done

cp config.ini agent.ini "${BUILD_DIR}/"
# Industry config templates (configs/ directory)
if [ -d "configs" ]; then
    cp -r configs/ "${BUILD_DIR}/"
fi

echo ""
echo "Build complete: ${BUILD_DIR}/"
ls -lh "${BUILD_DIR}"/*-linux-amd64
