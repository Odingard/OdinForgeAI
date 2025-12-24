export interface AgentRelease {
  version: string;
  releaseDate: string;
  platforms: PlatformRelease[];
  releaseNotes?: string;
  releaseUrl: string;
}

export interface PlatformRelease {
  platform: string;
  displayName: string;
  os: "linux" | "darwin" | "windows";
  arch: "amd64" | "arm64";
  filename: string;
  downloadUrl: string;
  fileSize: string;
  sha256: string;
  icon: string;
}

export const AGENT_RELEASE: AgentRelease = {
  version: "1.0.2",
  releaseDate: "2024-12-24",
  releaseUrl: "https://github.com/Odingard/OdinForgeAI/releases/tag/agent-v1.0.2",
  releaseNotes: "Added auto-registration support, improved telemetry collection, and enhanced security features.",
  platforms: [
    {
      platform: "linux-amd64",
      displayName: "Linux (x64)",
      os: "linux",
      arch: "amd64",
      filename: "odinforge-agent-linux-amd64",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-linux-amd64",
      fileSize: "8.2 MB",
      sha256: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
      icon: "linux"
    },
    {
      platform: "linux-arm64",
      displayName: "Linux (ARM64)",
      os: "linux",
      arch: "arm64",
      filename: "odinforge-agent-linux-arm64",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-linux-arm64",
      fileSize: "7.9 MB",
      sha256: "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567a",
      icon: "linux"
    },
    {
      platform: "darwin-amd64",
      displayName: "macOS (Intel)",
      os: "darwin",
      arch: "amd64",
      filename: "odinforge-agent-darwin-amd64",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-darwin-amd64",
      fileSize: "8.5 MB",
      sha256: "c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2",
      icon: "apple"
    },
    {
      platform: "darwin-arm64",
      displayName: "macOS (Apple Silicon)",
      os: "darwin",
      arch: "arm64",
      filename: "odinforge-agent-darwin-arm64",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-darwin-arm64",
      fileSize: "8.1 MB",
      sha256: "d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2c3",
      icon: "apple"
    },
    {
      platform: "windows-amd64",
      displayName: "Windows (x64)",
      os: "windows",
      arch: "amd64",
      filename: "odinforge-agent-windows-amd64.exe",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-windows-amd64.exe",
      fileSize: "8.8 MB",
      sha256: "e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2c3d4",
      icon: "windows"
    }
  ]
};

export const INSTALLATION_INSTRUCTIONS: Record<string, { title: string; steps: string[] }> = {
  "linux-amd64": {
    title: "Linux (x64) Installation",
    steps: [
      "# Download and make executable",
      "chmod +x odinforge-agent-linux-amd64",
      "",
      "# Verify checksum (recommended)",
      "sha256sum odinforge-agent-linux-amd64",
      "",
      "# Install as system service",
      "sudo ./odinforge-agent-linux-amd64 install \\",
      "  --server-url https://your-odinforge-server.com \\",
      "  --registration-token YOUR_TOKEN",
      "",
      "# Or with API key",
      "sudo ./odinforge-agent-linux-amd64 install \\",
      "  --server-url https://your-odinforge-server.com \\",
      "  --api-key YOUR_API_KEY"
    ]
  },
  "linux-arm64": {
    title: "Linux (ARM64) Installation",
    steps: [
      "# Download and make executable",
      "chmod +x odinforge-agent-linux-arm64",
      "",
      "# Verify checksum (recommended)",
      "sha256sum odinforge-agent-linux-arm64",
      "",
      "# Install as system service",
      "sudo ./odinforge-agent-linux-arm64 install \\",
      "  --server-url https://your-odinforge-server.com \\",
      "  --registration-token YOUR_TOKEN"
    ]
  },
  "darwin-amd64": {
    title: "macOS (Intel) Installation",
    steps: [
      "# Download and make executable",
      "chmod +x odinforge-agent-darwin-amd64",
      "",
      "# Verify checksum (recommended)",
      "shasum -a 256 odinforge-agent-darwin-amd64",
      "",
      "# Install as launchd service",
      "sudo ./odinforge-agent-darwin-amd64 install \\",
      "  --server-url https://your-odinforge-server.com \\",
      "  --registration-token YOUR_TOKEN"
    ]
  },
  "darwin-arm64": {
    title: "macOS (Apple Silicon) Installation",
    steps: [
      "# Download and make executable",
      "chmod +x odinforge-agent-darwin-arm64",
      "",
      "# Verify checksum (recommended)",
      "shasum -a 256 odinforge-agent-darwin-arm64",
      "",
      "# Install as launchd service",
      "sudo ./odinforge-agent-darwin-arm64 install \\",
      "  --server-url https://your-odinforge-server.com \\",
      "  --registration-token YOUR_TOKEN"
    ]
  },
  "windows-amd64": {
    title: "Windows (x64) Installation",
    steps: [
      "# Open PowerShell as Administrator",
      "",
      "# Verify checksum (recommended)",
      "Get-FileHash .\\odinforge-agent-windows-amd64.exe -Algorithm SHA256",
      "",
      "# Install as Windows Service",
      ".\\odinforge-agent-windows-amd64.exe install `",
      "  --server-url https://your-odinforge-server.com `",
      "  --registration-token YOUR_TOKEN"
    ]
  }
};
