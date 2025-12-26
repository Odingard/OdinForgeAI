#!/bin/bash
set -e

AGENT_DIR="odinforge-agent"
OUTPUT_DIR="public/agents"
PLATFORMS=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64" "windows/amd64")

mkdir -p "$OUTPUT_DIR"

echo "Building OdinForge Agent for all platforms..."

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
        -ldflags="-s -w" \
        -o "../${OUTPUT_DIR}/${OUTPUT_NAME}" \
        ./cmd/agent/
    
    echo "  -> ${OUTPUT_NAME} built successfully"
done

cd ..

echo ""
echo "All agent binaries built successfully!"
ls -lh "$OUTPUT_DIR"
