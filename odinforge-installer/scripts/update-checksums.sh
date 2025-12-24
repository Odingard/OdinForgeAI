#!/bin/bash
#
# Update SHA256 checksums in shared/agent-releases.ts
# Run this after building new agent binaries
#
# Usage: ./update-checksums.sh /path/to/binaries

set -e

BINARIES_DIR="${1:-.}"
MANIFEST_FILE="../shared/agent-releases.ts"

if [[ ! -d "$BINARIES_DIR" ]]; then
    echo "Error: Directory $BINARIES_DIR not found"
    echo "Usage: $0 /path/to/binaries"
    exit 1
fi

echo "Computing SHA256 checksums for binaries in $BINARIES_DIR..."
echo ""

for platform in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64; do
    filename="odinforge-agent-${platform}"
    if [[ "$platform" == "windows-amd64" ]]; then
        filename="${filename}.exe"
    fi
    
    filepath="$BINARIES_DIR/$filename"
    
    if [[ -f "$filepath" ]]; then
        if command -v sha256sum &> /dev/null; then
            hash=$(sha256sum "$filepath" | awk '{print $1}')
        elif command -v shasum &> /dev/null; then
            hash=$(shasum -a 256 "$filepath" | awk '{print $1}')
        else
            echo "Error: Neither sha256sum nor shasum found"
            exit 1
        fi
        
        echo "$platform: $hash"
        
        # Update the manifest file
        if [[ -f "$MANIFEST_FILE" ]]; then
            # This is a simple sed replacement - for production, use a proper JSON/TS parser
            echo "  -> Update $MANIFEST_FILE manually with this hash"
        fi
    else
        echo "$platform: MISSING ($filepath not found)"
    fi
done

echo ""
echo "Update shared/agent-releases.ts with these checksums before deploying."
