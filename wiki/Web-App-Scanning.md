# Web Application Scanning

OdinForge AI includes comprehensive web application security testing with parallel validation agents and AI-powered analysis.

## Overview

Web application scanning combines automated reconnaissance with targeted vulnerability validation:

1. **Reconnaissance** - Crawl target, discover endpoints, detect technologies
2. **Validation** - Parallel agents test for specific vulnerability types
3. **Analysis** - AI filters false positives and assesses impact
4. **Reporting** - Consolidated findings with evidence and remediation

## Scanning Modes

### Domain Scan

Traditional reconnaissance for domains and IP addresses:

| Check | Description |
|-------|-------------|
| Port Scanning | Discover open ports and services |
| SSL/TLS Analysis | Certificate validation, cipher suites |
| HTTP Fingerprinting | Server headers, technologies |
| DNS Enumeration | Subdomains, mail servers, TXT records |
| Security Headers | CSP, HSTS, X-Frame-Options |

### Web App Scan

Targeted vulnerability testing for web applications:

| Feature | Description |
|---------|-------------|
| Target URL Input | Direct URL for testing |
| Parallel Agents | Up to 6 concurrent validation agents |
| Real-time Progress | WebSocket updates during scan |
| LLM Filtering | AI-powered false positive reduction |
| Evidence Capture | Full request/response for findings |

## Vulnerability Types

### SQL Injection (SQLi)

Tests for database query manipulation:
- Error-based injection
- Time-based blind injection
- Boolean-based blind injection
- Union-based injection

### Cross-Site Scripting (XSS)

Tests for script injection:
- Reflected XSS
- Stored XSS indicators
- DOM-based XSS patterns

### Authentication Bypass

Tests for auth circumvention:
- Parameter manipulation
- Session handling flaws
- Token validation issues
- Default credentials

### Command Injection

Tests for OS command execution:
- Shell metacharacter injection
- Command chaining
- Argument injection

### Path Traversal

Tests for directory access:
- Dot-dot-slash sequences
- Encoded traversal patterns
- Absolute path injection

### Server-Side Request Forgery (SSRF)

Tests for internal network access:
- URL parameter manipulation
- Redirect-based SSRF
- Cloud metadata access

## Running a Web App Scan

### From the UI

1. Go to **External Recon** in the sidebar
2. Select the **Web App Scan** tab
3. Enter the target URL (e.g., `https://example.com`)
4. Configure validation agents:
   - Select vulnerability types to test
   - Set concurrent agent limit
5. Click **Start Scan**
6. Monitor progress in real-time
7. Review findings when complete

### Scan Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| Target URL | Web application URL | Required |
| Concurrent Agents | Parallel validation threads | 4 |
| Vulnerability Types | Which tests to run | All |
| Timeout | Per-agent timeout | 90 seconds |

## Understanding Results

### Reconnaissance Results

After initial crawling:
- **Discovered Endpoints** - URLs found on the target
- **Technologies Detected** - Frameworks, servers, libraries
- **Attack Surface Metrics** - Forms, parameters, API endpoints
- **Security Headers** - Missing or misconfigured headers

### Validated Findings

Each confirmed vulnerability includes:

| Field | Description |
|-------|-------------|
| Severity | Critical, High, Medium, Low |
| CVSS Score | Standardized severity rating |
| Confidence | AI confidence in finding validity |
| Evidence | HTTP request/response demonstrating issue |
| Recommendation | How to fix the vulnerability |

### Evidence Artifacts

For each finding:
- Raw HTTP request that triggered the vulnerability
- Server response showing exploitation
- Timing data for time-based attacks
- Screenshot of impact (where applicable)

## Best Practices

### Before Scanning

1. **Get authorization** - Ensure you have permission to test
2. **Check scope** - Verify target is in allowed scope rules
3. **Set execution mode** - Start with Safe/Simulate before Live
4. **Notify stakeholders** - Alert operations teams if needed

### During Scanning

1. **Monitor progress** - Watch for errors or blocks
2. **Check governance logs** - Review any blocked operations
3. **Adjust as needed** - Stop if issues arise

### After Scanning

1. **Review all findings** - Check for false positives
2. **Verify critical issues** - Manually confirm high-severity findings
3. **Generate reports** - Create documentation for remediation
4. **Track remediation** - Follow up on fixes

## Integration with Full Assessments

Web app scanning integrates with full assessments:

1. Create a Full Assessment with **External-only** mode
2. Include web application targets
3. Assessment automatically runs:
   - Domain reconnaissance
   - Web app vulnerability scanning
   - AI analysis and prioritization
4. Results consolidated with other findings

## Governance Integration

All web app scanning respects governance controls:

- **Kill Switch** - Immediately stops all active scans
- **Execution Mode** - Limits testing intensity
- **Scope Rules** - Blocks out-of-scope targets
- **Rate Limiting** - Prevents overwhelming targets

Configure governance in **Governance** before running scans.
