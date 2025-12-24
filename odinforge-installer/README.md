# OdinForge Agent Installer

A cross-platform CLI tool that automatically downloads and installs the correct OdinForge Agent binary for your system.

## Features

- **Auto-detection**: Automatically detects your OS (Linux, macOS, Windows) and architecture (x64, ARM64)
- **Secure**: Verifies SHA256 checksums before installation
- **Simple**: Single command to download and install the agent
- **Cross-platform**: Works on Linux, macOS (Intel & Apple Silicon), and Windows

## Usage

### Basic Installation

```bash
# Download the installer for your platform and run:
./odinforge-installer --server-url https://your-server.com --registration-token YOUR_TOKEN
```

### Options

| Option | Description |
|--------|-------------|
| `--server-url <url>` | **Required.** OdinForge server URL |
| `--registration-token <token>` | **Required.** Registration token for auto-registration |
| `--platform <platform>` | Override platform detection |
| `--output <path>` | Download destination (default: current directory) |
| `--skip-checksum` | Skip SHA256 verification (not recommended) |
| `--dry-run` | Show what would be done without downloading |
| `--help, -h` | Show help message |
| `--version, -v` | Show version |

### Platform Override

If auto-detection fails, specify your platform manually:

```bash
# For Apple Silicon Mac
./odinforge-installer --server-url https://server.com --registration-token TOKEN --platform darwin-arm64

# For Linux ARM64 (e.g., Raspberry Pi, AWS Graviton)
./odinforge-installer --server-url https://server.com --registration-token TOKEN --platform linux-arm64
```

Available platforms:
- `linux-x64` - Linux x86_64
- `linux-arm64` - Linux ARM64 (aarch64)
- `darwin-x64` - macOS Intel
- `darwin-arm64` - macOS Apple Silicon
- `win32-x64` - Windows x64

## Building from Source

### Prerequisites

- Node.js 18+
- npm

### Build Commands

```bash
cd odinforge-installer
npm install

# Build all platforms
npm run build:all

# Build specific platforms
npm run build:linux
npm run build:macos
npm run build:windows
```

Built executables will be in the `dist/` directory.

## Security

- All downloads are verified against SHA256 checksums fetched from your OdinForge server
- The installer never stores or transmits your registration token except to the specified server
- Always download the installer from official sources

### Updating Checksums (For Administrators)

When publishing new agent binaries, update the SHA256 checksums in `shared/agent-releases.ts`:

```bash
# Generate checksums for all binaries
sha256sum odinforge-agent-*

# On macOS
shasum -a 256 odinforge-agent-*
```

Update the `sha256` field for each platform in the release manifest. The CLI installer fetches these values from your server at install time.

## Troubleshooting

### "Permission denied" on Linux/macOS

The agent installer requires root privileges. Run with sudo:

```bash
sudo ./odinforge-installer --server-url https://server.com --registration-token TOKEN
```

### "Checksum mismatch" error

This indicates the downloaded file may be corrupted or tampered with. Try:
1. Re-download the installer
2. Check your network connection
3. If the problem persists, contact support

### Platform not detected correctly

Use the `--platform` flag to manually specify your platform:

```bash
./odinforge-installer --server-url https://server.com --registration-token TOKEN --platform darwin-arm64
```
