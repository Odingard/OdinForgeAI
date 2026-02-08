#!/usr/bin/env tsx
/**
 * Run connectivity diagnostics on EC2 instances
 * Usage: tsx scripts/run-connectivity-diagnostics.ts
 */

import 'dotenv/config';
import { storage } from '../server/storage';
import { AWSAdapter } from '../server/services/cloud/aws-adapter';

const NGROK_URL = process.env.PUBLIC_ODINFORGE_URL || 'https://uncleavable-jesse-inkier.ngrok-free.dev';

async function runDiagnostics() {
  console.log('🔍 Running connectivity diagnostics on EC2 instances...\n');

  // Get AWS cloud assets
  const assets = await storage.getCloudAssets();
  const ec2Assets = assets.filter(a =>
    a.assetType === 'ec2_instance' &&
    a.powerState === 'running' &&
    a.provider === 'aws'
  );

  if (ec2Assets.length === 0) {
    console.log('❌ No running EC2 instances found');
    return;
  }

  console.log(`Found ${ec2Assets.length} running EC2 instance(s):\n`);

  for (const asset of ec2Assets) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Instance: ${asset.assetName} (${asset.providerResourceId})`);
    console.log(`Platform: ${asset.rawMetadata?.platform || 'unknown'}`);
    console.log(`Region: ${asset.region}`);
    console.log(`${'='.repeat(60)}\n`);

    try {
      // Get AWS credentials
      const connection = await storage.getCloudConnection(asset.connectionId);
      if (!connection) {
        console.log(`❌ No connection found for asset ${asset.id}`);
        continue;
      }

      const credentials = connection.credentials as any;
      if (!credentials?.aws) {
        console.log(`❌ No AWS credentials found`);
        continue;
      }

      // Create AWS adapter
      const adapter = new AWSAdapter(
        credentials.aws.accessKeyId,
        credentials.aws.secretAccessKey,
        credentials.aws.region || asset.region
      );

      // Determine platform-specific diagnostic commands
      const isLinux = asset.rawMetadata?.platform?.toLowerCase() === 'linux';
      const diagnosticCommands = isLinux
        ? [
            'echo "=== OdinForge Agent Connectivity Diagnostics ==="',
            `echo "Server URL: ${NGROK_URL}"`,
            'echo ""',
            'echo "[1/6] Testing DNS resolution..."',
            'if command -v host >/dev/null 2>&1; then',
            '  host uncleavable-jesse-inkier.ngrok-free.dev || echo "DNS failed"',
            'elif command -v nslookup >/dev/null 2>&1; then',
            '  nslookup uncleavable-jesse-inkier.ngrok-free.dev || echo "DNS failed"',
            'else',
            '  echo "No DNS tools available"',
            'fi',
            'echo ""',
            'echo "[2/6] Testing HTTPS connectivity..."',
            `HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${NGROK_URL}" 2>&1)`,
            'echo "HTTP Status: $HTTP_CODE"',
            'if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then',
            '  echo "✅ Server is reachable"',
            'else',
            '  echo "❌ Server not reachable (code: $HTTP_CODE)"',
            'fi',
            'echo ""',
            'echo "[3/6] Testing agent download..."',
            `curl -I "${NGROK_URL}/api/agents/download/linux-amd64" 2>&1 | head -5`,
            'echo ""',
            'echo "[4/6] Testing general internet..."',
            'curl -s -o /dev/null -w "Google: %{http_code}\n" "https://www.google.com"',
            'echo ""',
            'echo "[5/6] Testing port 443..."',
            'if command -v nc >/dev/null 2>&1; then',
            '  timeout 5 bash -c "cat < /dev/null > /dev/tcp/uncleavable-jesse-inkier.ngrok-free.dev/443" 2>/dev/null && echo "✅ Port 443 reachable" || echo "❌ Port 443 blocked"',
            'else',
            '  echo "nc not available, skipping"',
            'fi',
            'echo ""',
            'echo "[6/6] Checking for existing agent..."',
            'if [ -f /usr/local/bin/odinforge-agent ]; then',
            '  echo "✅ Agent binary exists"',
            '  /usr/local/bin/odinforge-agent version 2>&1 || echo "Version check failed"',
            '  if systemctl is-active odinforge-agent >/dev/null 2>&1; then',
            '    echo "✅ Agent service is running"',
            '    journalctl -u odinforge-agent -n 20 --no-pager 2>&1 | tail -10',
            '  else',
            '    echo "❌ Agent service is not running"',
            '    systemctl status odinforge-agent --no-pager 2>&1 | head -20',
            '  fi',
            'else',
            '  echo "❌ Agent binary not found"',
            'fi'
          ]
        : [
            'Write-Host "=== OdinForge Agent Connectivity Diagnostics ==="',
            `Write-Host "Server URL: ${NGROK_URL}"`,
            'Write-Host ""',
            'Write-Host "[1/4] Testing DNS resolution..."',
            'try { Resolve-DnsName uncleavable-jesse-inkier.ngrok-free.dev; Write-Host "✅ DNS OK" } catch { Write-Host "❌ DNS failed" }',
            'Write-Host ""',
            'Write-Host "[2/4] Testing HTTPS connectivity..."',
            `try { $response = Invoke-WebRequest -Uri "${NGROK_URL}" -UseBasicParsing -TimeoutSec 10; Write-Host "✅ HTTP Status: $($response.StatusCode)" } catch { Write-Host "❌ Connection failed: $_" }`,
            'Write-Host ""',
            'Write-Host "[3/4] Testing agent download..."',
            `try { $headers = Invoke-WebRequest -Uri "${NGROK_URL}/api/agents/download/windows-amd64" -Method Head -UseBasicParsing -TimeoutSec 10; Write-Host "✅ Download endpoint: $($headers.StatusCode)"; Write-Host "Size: $($headers.Headers.'Content-Length')" } catch { Write-Host "❌ Download failed: $_" }`,
            'Write-Host ""',
            'Write-Host "[4/4] Checking for existing agent..."',
            'if (Test-Path "C:\\Program Files\\OdinForge\\odinforge-agent.exe") { Write-Host "✅ Agent binary exists"; $service = Get-Service -Name "OdinForge Agent" -ErrorAction SilentlyContinue; if ($service) { Write-Host "Service Status: $($service.Status)" } else { Write-Host "❌ Service not found" } } else { Write-Host "❌ Agent binary not found" }'
          ];

      console.log('Executing diagnostic commands via SSM...\n');

      const result = await adapter.executeCommandViaSSM(
        asset.providerResourceId,
        diagnosticCommands,
        isLinux ? 'Linux' : 'Windows'
      );

      if (result.commandId) {
        console.log(`✅ Commands sent successfully (Command ID: ${result.commandId})`);
        console.log(`\nWait 30-60 seconds, then check the results in AWS Console:`);
        console.log(`  Systems Manager → Run Command → ${result.commandId}`);
        console.log(`\nOr check the CloudWatch logs for the command output.\n`);
      } else if (result.error) {
        console.log(`❌ Failed to send commands: ${result.error}\n`);
      }

    } catch (error) {
      console.log(`❌ Error: ${error instanceof Error ? error.message : error}\n`);
    }
  }

  console.log('\n' + '='.repeat(60));
  console.log('Diagnostics dispatch complete!');
  console.log('Check AWS Systems Manager → Run Command for results');
  console.log('='.repeat(60) + '\n');
}

runDiagnostics()
  .then(() => {
    console.log('✅ Done');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Error:', error);
    process.exit(1);
  });
