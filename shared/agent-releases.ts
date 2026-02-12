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
  version: "1.0.4",
  releaseDate: "2026-02-11",
  releaseUrl: "https://github.com/Odingard/OdinForgeAI/releases/tag/agent-v1.0.4",
  releaseNotes: "Enterprise-grade upgrade: structured JSON logging, auto-update mechanism, watchdog health monitoring, K8s health/ready endpoints, proxy support (HTTP/HTTPS/SOCKS5), graceful shutdown timeout, and build-time version injection.",
  platforms: [
    {
      platform: "linux-amd64",
      displayName: "Linux (x64)",
      os: "linux",
      arch: "amd64",
      filename: "odinforge-agent-linux-amd64",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.4/odinforge-agent-linux-amd64",
      fileSize: "9.0 MB",
      sha256: "bbdc0c1c5c86835792091c275fee628c5361e12c390f5fd30265580b67bbab9a",
      icon: "linux"
    },
    {
      platform: "linux-arm64",
      displayName: "Linux (ARM64)",
      os: "linux",
      arch: "arm64",
      filename: "odinforge-agent-linux-arm64",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.4/odinforge-agent-linux-arm64",
      fileSize: "8.4 MB",
      sha256: "c7e552ccf86d6aaa681ef28aa0ed2145774489c408b7822304673643b134cfe9",
      icon: "linux"
    },
    {
      platform: "darwin-amd64",
      displayName: "macOS (Intel)",
      os: "darwin",
      arch: "amd64",
      filename: "odinforge-agent-darwin-amd64",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.4/odinforge-agent-darwin-amd64",
      fileSize: "9.1 MB",
      sha256: "c3a3b77f185e5f5d6ba86d944f13319d5f327c3eda48168be1c74d739f5713d6",
      icon: "apple"
    },
    {
      platform: "darwin-arm64",
      displayName: "macOS (Apple Silicon)",
      os: "darwin",
      arch: "arm64",
      filename: "odinforge-agent-darwin-arm64",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.4/odinforge-agent-darwin-arm64",
      fileSize: "8.5 MB",
      sha256: "0d042d02382bf56ebdea50fe3b83baa58a29f2650ffd0085e61f46f77a0687ad",
      icon: "apple"
    },
    {
      platform: "windows-amd64",
      displayName: "Windows (x64)",
      os: "windows",
      arch: "amd64",
      filename: "odinforge-agent-windows-amd64.exe",
      downloadUrl: "https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.4/odinforge-agent-windows-amd64.exe",
      fileSize: "9.3 MB",
      sha256: "8e3f47fa54bedceb94ac72f0e6139526479006cb21413c41085e1e7478677e12",
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
