#!/usr/bin/env node

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn, execSync } = require('child_process');

const VERSION = '1.0.2';
const GITHUB_RELEASE_URL = 'https://github.com/Odingard/OdinForgeAI/releases/tag/agent-v1.0.2';

// Platform mapping for API response parsing
const PLATFORM_MAP = {
  'linux-x64': 'linux-amd64',
  'linux-arm64': 'linux-arm64',
  'darwin-x64': 'darwin-amd64',
  'darwin-arm64': 'darwin-arm64',
  'win32-x64': 'windows-amd64'
};

// Fallback releases (used when server is unavailable)
const FALLBACK_RELEASES = {
  'linux-x64': {
    filename: 'odinforge-agent-linux-amd64',
    downloadUrl: 'https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-linux-amd64',
    sha256: null,
    displayName: 'Linux x64'
  },
  'linux-arm64': {
    filename: 'odinforge-agent-linux-arm64',
    downloadUrl: 'https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-linux-arm64',
    sha256: null,
    displayName: 'Linux ARM64'
  },
  'darwin-x64': {
    filename: 'odinforge-agent-darwin-amd64',
    downloadUrl: 'https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-darwin-amd64',
    sha256: null,
    displayName: 'macOS Intel'
  },
  'darwin-arm64': {
    filename: 'odinforge-agent-darwin-arm64',
    downloadUrl: 'https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-darwin-arm64',
    sha256: null,
    displayName: 'macOS Apple Silicon'
  },
  'win32-x64': {
    filename: 'odinforge-agent-windows-amd64.exe',
    downloadUrl: 'https://github.com/Odingard/OdinForgeAI/releases/download/agent-v1.0.2/odinforge-agent-windows-amd64.exe',
    sha256: null,
    displayName: 'Windows x64'
  }
};

async function fetchReleaseManifest(serverUrl) {
  return new Promise((resolve, reject) => {
    const url = `${serverUrl}/api/agent-releases/latest`;
    const protocol = url.startsWith('https') ? https : http;
    
    protocol.get(url, { timeout: 10000 }, (response) => {
      if (response.statusCode !== 200) {
        reject(new Error(`Failed to fetch manifest: HTTP ${response.statusCode}`));
        return;
      }
      
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', () => {
        try {
          const manifest = JSON.parse(data);
          const releases = {};
          
          for (const platform of manifest.release.platforms) {
            const key = Object.entries(PLATFORM_MAP).find(([k, v]) => v === platform.platform)?.[0];
            if (key) {
              releases[key] = {
                filename: platform.filename,
                downloadUrl: platform.downloadUrl,
                sha256: platform.sha256,
                displayName: platform.displayName
              };
            }
          }
          
          resolve({ releases, version: manifest.release.version });
        } catch (e) {
          reject(new Error('Failed to parse manifest'));
        }
      });
    }).on('error', reject).on('timeout', () => reject(new Error('Manifest fetch timeout')));
  });
}

const COLORS = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function color(text, colorCode) {
  if (process.stdout.isTTY) {
    return `${colorCode}${text}${COLORS.reset}`;
  }
  return text;
}

function log(message, type = 'info') {
  const prefix = {
    info: color('[INFO]', COLORS.blue),
    success: color('[OK]', COLORS.green),
    warn: color('[WARN]', COLORS.yellow),
    error: color('[ERROR]', COLORS.red),
    step: color('[>>]', COLORS.cyan)
  };
  console.log(`${prefix[type] || prefix.info} ${message}`);
}

function banner() {
  console.log('');
  console.log(color('╔═══════════════════════════════════════════════════════════╗', COLORS.cyan));
  console.log(color('║', COLORS.cyan) + color('        OdinForge Agent Installer v' + VERSION, COLORS.bright) + color('                    ║', COLORS.cyan));
  console.log(color('║', COLORS.cyan) + '     Adversarial Exposure Validation Platform            ' + color('║', COLORS.cyan));
  console.log(color('╚═══════════════════════════════════════════════════════════╝', COLORS.cyan));
  console.log('');
}

function usage() {
  console.log(`
${color('Usage:', COLORS.bright)}
  odinforge-installer [options]

${color('Required Options:', COLORS.bright)}
  --server-url <url>          OdinForge server URL (e.g., https://your-server.com)
  --registration-token <token> Registration token for agent auto-registration

${color('Optional:', COLORS.bright)}
  --platform <platform>       Override platform detection (linux-x64, linux-arm64, 
                              darwin-x64, darwin-arm64, win32-x64)
  --output <path>             Download destination (default: current directory)
  --skip-checksum             Skip SHA256 verification (not recommended)
  --dry-run                   Show what would be done without downloading
  --help, -h                  Show this help message
  --version, -v               Show version

${color('Examples:', COLORS.bright)}
  # Auto-detect platform and install
  odinforge-installer --server-url https://odinforge.example.com --registration-token abc123

  # Specify platform explicitly
  odinforge-installer --server-url https://odinforge.example.com --registration-token abc123 --platform linux-arm64

  # Download only (don't run install)
  odinforge-installer --server-url https://odinforge.example.com --registration-token abc123 --output ./agent
`);
}

function parseArgs(args) {
  const options = {
    serverUrl: null,
    registrationToken: null,
    platform: null,
    output: process.cwd(),
    skipChecksum: false,
    dryRun: false,
    help: false,
    version: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    switch (arg) {
      case '--server-url':
        options.serverUrl = next;
        i++;
        break;
      case '--registration-token':
        options.registrationToken = next;
        i++;
        break;
      case '--platform':
        options.platform = next;
        i++;
        break;
      case '--output':
        options.output = next;
        i++;
        break;
      case '--skip-checksum':
        options.skipChecksum = true;
        break;
      case '--dry-run':
        options.dryRun = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      case '--version':
      case '-v':
        options.version = true;
        break;
    }
  }

  return options;
}

function detectPlatform(releases) {
  const platform = os.platform();
  const arch = os.arch();

  let key;
  if (platform === 'linux') {
    key = arch === 'arm64' ? 'linux-arm64' : 'linux-x64';
  } else if (platform === 'darwin') {
    key = arch === 'arm64' ? 'darwin-arm64' : 'darwin-x64';
  } else if (platform === 'win32') {
    key = 'win32-x64';
  } else {
    return null;
  }

  return { key, ...releases[key] };
}

function download(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);
    const protocol = url.startsWith('https') ? https : http;

    const request = (currentUrl, redirectCount = 0) => {
      if (redirectCount > 5) {
        reject(new Error('Too many redirects'));
        return;
      }

      protocol.get(currentUrl, (response) => {
        if (response.statusCode === 301 || response.statusCode === 302) {
          file.close();
          fs.unlinkSync(destPath);
          const newFile = fs.createWriteStream(destPath);
          const redirectUrl = response.headers.location;
          const redirectProtocol = redirectUrl.startsWith('https') ? https : http;
          
          redirectProtocol.get(redirectUrl, (redirectResponse) => {
            if (redirectResponse.statusCode === 301 || redirectResponse.statusCode === 302) {
              newFile.close();
              fs.unlinkSync(destPath);
              request(redirectResponse.headers.location, redirectCount + 1);
              return;
            }

            const totalSize = parseInt(redirectResponse.headers['content-length'], 10);
            let downloadedSize = 0;

            redirectResponse.on('data', (chunk) => {
              downloadedSize += chunk.length;
              if (totalSize) {
                const percent = Math.round((downloadedSize / totalSize) * 100);
                process.stdout.write(`\r  Downloading: ${percent}% (${(downloadedSize / 1024 / 1024).toFixed(1)} MB)`);
              }
            });

            redirectResponse.pipe(newFile);

            newFile.on('finish', () => {
              newFile.close();
              console.log('');
              resolve(destPath);
            });
          }).on('error', (err) => {
            newFile.close();
            fs.unlinkSync(destPath);
            reject(err);
          });
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`Download failed with status ${response.statusCode}`));
          return;
        }

        const totalSize = parseInt(response.headers['content-length'], 10);
        let downloadedSize = 0;

        response.on('data', (chunk) => {
          downloadedSize += chunk.length;
          if (totalSize) {
            const percent = Math.round((downloadedSize / totalSize) * 100);
            process.stdout.write(`\r  Downloading: ${percent}% (${(downloadedSize / 1024 / 1024).toFixed(1)} MB)`);
          }
        });

        response.pipe(file);

        file.on('finish', () => {
          file.close();
          console.log('');
          resolve(destPath);
        });
      }).on('error', (err) => {
        file.close();
        fs.unlinkSync(destPath);
        reject(err);
      });
    };

    request(url);
  });
}

function verifyChecksum(filePath, expectedHash) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);

    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => {
      const actualHash = hash.digest('hex');
      if (actualHash.toLowerCase() === expectedHash.toLowerCase()) {
        resolve(true);
      } else {
        reject(new Error(`Checksum mismatch!\n  Expected: ${expectedHash}\n  Actual:   ${actualHash}`));
      }
    });
    stream.on('error', reject);
  });
}

function makeExecutable(filePath) {
  if (os.platform() !== 'win32') {
    fs.chmodSync(filePath, 0o755);
  }
}

function runInstall(agentPath, serverUrl, registrationToken) {
  return new Promise((resolve, reject) => {
    const isWindows = os.platform() === 'win32';
    const args = [
      'install',
      '--server-url', serverUrl,
      '--registration-token', registrationToken
    ];

    log(`Running: ${agentPath} ${args.join(' ')}`, 'step');

    const child = spawn(agentPath, args, {
      stdio: 'inherit',
      shell: isWindows
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Agent install exited with code ${code}`));
      }
    });

    child.on('error', reject);
  });
}

async function main() {
  const args = process.argv.slice(2);
  const options = parseArgs(args);

  if (options.version) {
    console.log(`OdinForge Installer v${VERSION}`);
    process.exit(0);
  }

  banner();

  if (options.help) {
    usage();
    process.exit(0);
  }

  if (!options.serverUrl || !options.registrationToken) {
    log('Missing required options: --server-url and --registration-token', 'error');
    usage();
    process.exit(1);
  }

  // Fetch release manifest from server for authoritative checksums
  let RELEASES = FALLBACK_RELEASES;
  let manifestVersion = VERSION;
  let manifestFetched = false;
  
  log('Fetching release manifest from server...', 'step');
  try {
    const manifest = await fetchReleaseManifest(options.serverUrl);
    RELEASES = manifest.releases;
    manifestVersion = manifest.version;
    manifestFetched = true;
    log(`Got manifest v${manifestVersion} from server`, 'success');
  } catch (err) {
    log(`Could not fetch manifest: ${err.message}`, 'warn');
    if (!options.skipChecksum) {
      log('', 'info');
      log('Cannot verify download integrity without manifest.', 'error');
      log('Options:', 'info');
      log('  1. Ensure server is reachable and try again', 'info');
      log('  2. Use --skip-checksum to proceed without verification (not recommended)', 'info');
      process.exit(1);
    }
    log('Using fallback release info (checksum verification disabled by --skip-checksum)', 'warn');
  }

  let release;
  if (options.platform) {
    release = RELEASES[options.platform];
    if (!release) {
      log(`Unknown platform: ${options.platform}`, 'error');
      log(`Available platforms: ${Object.keys(RELEASES).join(', ')}`, 'info');
      process.exit(1);
    }
    release = { key: options.platform, ...release };
    log(`Using specified platform: ${release.displayName}`, 'info');
  } else {
    release = detectPlatform(RELEASES);
    if (!release) {
      log(`Unsupported platform: ${os.platform()} ${os.arch()}`, 'error');
      log(`Please specify --platform manually`, 'info');
      process.exit(1);
    }
    log(`Detected platform: ${release.displayName} (${release.key})`, 'success');
  }

  log(`Agent version: v${manifestVersion}`, 'info');
  log(`Server URL: ${options.serverUrl}`, 'info');

  if (options.dryRun) {
    log('Dry run - would download:', 'info');
    log(`  URL: ${release.downloadUrl}`, 'info');
    log(`  File: ${release.filename}`, 'info');
    log(`  SHA256: ${release.sha256 || 'N/A (using fallback)'}`, 'info');
    process.exit(0);
  }

  const destPath = path.join(options.output, release.filename);

  try {
    log(`Downloading ${release.filename}...`, 'step');
    await download(release.downloadUrl, destPath);
    log('Download complete', 'success');

    if (!options.skipChecksum && release.sha256) {
      log('Verifying checksum...', 'step');
      try {
        await verifyChecksum(destPath, release.sha256);
        log('Checksum verified', 'success');
      } catch (checksumError) {
        log(checksumError.message, 'error');
        log('', 'info');
        log('The downloaded file does not match the expected checksum.', 'error');
        log('This could mean:', 'info');
        log('  1. The download was corrupted - try again', 'info');
        log('  2. The checksums in the manifest need updating', 'info');
        log('  3. The binary has been tampered with', 'info');
        log('', 'info');
        log('To bypass (NOT recommended for production):', 'info');
        log('  Add --skip-checksum to the command', 'info');
        fs.unlinkSync(destPath);
        process.exit(1);
      }
    } else if (!release.sha256) {
      log('Checksum not available - integrity verification skipped', 'warn');
      log('For production, ensure your server has correct checksums configured', 'warn');
    } else {
      log('Skipping checksum verification (--skip-checksum specified)', 'warn');
    }

    makeExecutable(destPath);
    log('Made executable', 'success');

    const isRoot = os.platform() !== 'win32' && process.getuid && process.getuid() === 0;
    if (os.platform() !== 'win32' && !isRoot) {
      log('Note: Installation may require sudo privileges', 'warn');
      log(`To install manually, run:`, 'info');
      log(`  sudo ${destPath} install --server-url ${options.serverUrl} --registration-token ${options.registrationToken}`, 'info');
    } else {
      log('Running agent installer...', 'step');
      await runInstall(destPath, options.serverUrl, options.registrationToken);
      log('Agent installed successfully!', 'success');
    }

    console.log('');
    log(color('Installation complete!', COLORS.green + COLORS.bright), 'success');
    log(`Agent binary: ${destPath}`, 'info');
    log(`Server: ${options.serverUrl}`, 'info');

  } catch (error) {
    log(error.message, 'error');
    process.exit(1);
  }
}

main();
