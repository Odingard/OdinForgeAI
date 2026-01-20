# Getting Started

This guide walks you through setting up OdinForge AI and running your first security assessment.

## Prerequisites

- Access to OdinForge AI instance (self-hosted or cloud)
- Admin credentials for initial setup
- (Optional) AWS, Azure, or GCP credentials for cloud scanning

## Step 1: Login

1. Navigate to your OdinForge instance URL
2. Login with your admin credentials
3. You'll land on the main Dashboard

## Step 2: Add Your First Asset

### Option A: Manual Asset Entry

1. Go to **Assets** in the sidebar
2. Click **Add Asset**
3. Enter asset details:
   - Name (e.g., "Production Web Server")
   - Type (Server, Web Application, Database, etc.)
   - IP Address or hostname
   - Criticality level (Low, Medium, High, Critical)

### Option B: Cloud Discovery

1. Go to **Infrastructure** in the sidebar
2. Click **Add Cloud Connection**
3. Select your provider (AWS, Azure, or GCP)
4. Enter credentials:
   - **AWS**: Access Key ID and Secret Access Key
   - **Azure**: Tenant ID, Client ID, Client Secret
   - **GCP**: Service Account JSON key
5. Click **Run Discovery** to find assets

### Option C: Deploy Endpoint Agents

1. Go to **Agents** in the sidebar
2. Click **Create Token** to generate a registration token
3. Copy the installation command for your platform
4. Run on target systems:

**Linux/macOS:**
```bash
curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
```

**Windows (PowerShell as Admin):**
```powershell
irm https://YOUR_SERVER/api/agents/install.ps1 | iex
```

## Step 3: Run Your First Evaluation

### Quick Evaluation

1. Go to **Evaluations** in the sidebar
2. Click **New Evaluation**
3. Select an asset from your inventory
4. Choose an exposure type:
   - **CVE Exploitation** - For known vulnerabilities
   - **Configuration Weakness** - For misconfigurations
   - **Cloud Misconfiguration** - For cloud assets
5. Set priority level
6. Click **Start Evaluation**
7. Watch the AI analysis in real-time

### Full Assessment

For comprehensive multi-phase testing:

1. Go to **Full Assessment** in the sidebar
2. Click **New Assessment**
3. Configure:
   - Target assets
   - Phases to include (recon, vulnerability analysis, lateral movement)
   - Assessment mode (Agent-based or External-only)
4. Start the assessment
5. Monitor progress through each phase

## Step 4: Review Results

### Evaluation Results

Each evaluation provides:
- **Exploitability Score** - How likely the vulnerability can be exploited
- **Business Impact** - Potential damage from successful exploitation
- **Attack Path** - Visual graph showing attack progression
- **MITRE ATT&CK Mapping** - Techniques used by attackers
- **Remediation** - Prioritized fixes for both executives and engineers

### Dashboard Metrics

The main dashboard shows:
- Total evaluations by status
- Critical findings requiring attention
- Risk distribution across assets
- Recent activity timeline

## Step 5: Generate Reports

1. Go to **Reports** in the sidebar
2. Click **Generate Report**
3. Select report type:
   - **Executive Summary** - High-level business impact
   - **Technical Report** - Detailed findings for engineers
   - **Compliance Assessment** - Audit-ready documentation
4. Choose evaluations to include
5. Download as PDF, CSV, or JSON

## Next Steps

### Web Application Scanning

Test web apps for vulnerabilities:
1. Go to **External Recon**
2. Select **Web App Scan** tab
3. Enter target URL
4. Configure validation agents (SQLi, XSS, etc.)
5. Run the scan

### AI vs AI Simulation

Run purple team exercises:
1. Go to **Simulations** in the sidebar
2. Click **New Simulation**
3. Select target and scenario
4. Configure rounds (1-10)
5. Watch Attacker AI vs Defender AI

### Coverage Autopilot

Automate agent deployment:
1. Go to **Coverage Autopilot** in the sidebar
2. Enable auto-deploy
3. Configure deployment rules (providers, platforms)
4. Agents deploy automatically when new assets discovered

## Configuration

### Governance Controls

Before running live tests:
1. Go to **Governance** in the sidebar
2. Set **Execution Mode**:
   - **Safe** - Read-only, no active testing
   - **Simulate** - Simulated attacks only
   - **Live** - Full active testing
3. Configure **Scope Rules** to define allowed targets
4. Keep Kill Switch available for emergencies

### Best Practices

1. **Start with Safe mode** - Validate setup before active testing
2. **Define scope rules** - Prevent unintended testing
3. **Use adversary profiles** - Match testing to threat model
4. **Regular discovery** - Keep asset inventory current
5. **Review governance logs** - Audit all blocked operations
