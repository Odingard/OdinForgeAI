#!/bin/bash
set -e

AGENT_DIR="odinforge-agent"
OUTPUT_DIR="public/agents"
PLATFORMS=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64" "windows/amd64")

# Version: use env var, git tag, or default
VERSION="${AGENT_VERSION:-$(git describe --tags --always 2>/dev/null || echo "1.0.4")}"
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mkdir -p "$OUTPUT_DIR"

echo "Building OdinForge Agent v${VERSION} for all platforms..."

cd "$AGENT_DIR"

go mod download

for platform in "${PLATFORMS[@]}"; do
    GOOS="${platform%/*}"
    GOARCH="${platform#*/}"

    OUTPUT_NAME="odinforge-agent-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="${OUTPUT_NAME}.exe"
    fi

    echo "Building for ${GOOS}/${GOARCH}..."

    CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o "../${OUTPUT_DIR}/${OUTPUT_NAME}" \
        ./cmd/agent/

    echo "  -> ${OUTPUT_NAME} built successfully"
done

cd ..

echo ""
echo "All agent binaries built successfully (v${VERSION})!"
ls -lh "$OUTPUT_DIR"
