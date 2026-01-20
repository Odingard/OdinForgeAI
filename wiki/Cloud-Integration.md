# Cloud Integration

OdinForge AI integrates with major cloud providers for automatic asset discovery and agent deployment.

## Supported Providers

| Provider | Asset Types |
|----------|-------------|
| AWS | EC2 instances, RDS databases, Lambda functions, S3 buckets, VPCs, Security Groups |
| Azure | Virtual Machines, SQL Databases, Resource Groups, Subscriptions |
| GCP | Compute Engine instances, Cloud SQL, Projects |

## Setting Up Cloud Connections

### AWS

**Required Credentials:**
- Access Key ID
- Secret Access Key
- (Optional) Session Token for temporary credentials

**Required IAM Permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "ec2:DescribeSecurityGroups",
        "rds:DescribeDBInstances",
        "lambda:ListFunctions",
        "s3:ListAllMyBuckets",
        "sts:GetCallerIdentity",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation"
      ],
      "Resource": "*"
    }
  ]
}
```

**Setup Steps:**
1. Go to **Infrastructure** in the sidebar
2. Click **Add Cloud Connection**
3. Select **AWS**
4. Enter a friendly name (e.g., "Production AWS")
5. Click **Update Credentials**
6. Enter Access Key ID and Secret Access Key
7. Click **Update**
8. Connection status shows "Connected"

### Azure

**Required Credentials:**
- Tenant ID
- Client ID (Application ID)
- Client Secret

**Required Permissions:**
- Reader role on subscriptions to discover
- Or custom role with:
  - `Microsoft.Compute/virtualMachines/read`
  - `Microsoft.Sql/servers/read`
  - `Microsoft.Resources/subscriptions/read`

**Setup Steps:**
1. Go to **Infrastructure**
2. Click **Add Cloud Connection**
3. Select **Azure**
4. Enter Tenant ID, Client ID, Client Secret
5. Connection validates and shows "Connected"

### GCP

**Required Credentials:**
- Service Account JSON key file

**Required Permissions:**
- `compute.viewer` role
- Or custom role with:
  - `compute.instances.list`
  - `resourcemanager.projects.list`

**Setup Steps:**
1. Go to **Infrastructure**
2. Click **Add Cloud Connection**
3. Select **GCP**
4. Paste Service Account JSON key
5. Connection validates and shows "Connected"

## Asset Discovery

### Running Discovery

1. Go to **Infrastructure**
2. Find your cloud connection
3. Click **Run Discovery**
4. Watch progress in real-time (WebSocket updates)
5. New assets appear in **Assets** page

### Discovery Results

Each discovered asset includes:
- Instance ID and name
- Region and availability zone
- Instance type/size
- Platform (Linux/Windows)
- Public/Private IP addresses
- Tags from cloud provider
- State (running/stopped)

### Auto-Refresh

When discovery finds new assets:
- Assets page auto-refreshes (no manual reload)
- Toast notification shows count of new assets
- Coverage Autopilot updates metrics

## Auto-Deploy Agents

### Coverage Autopilot

Automatically deploy agents to discovered cloud assets:

1. Go to **Coverage Autopilot** in sidebar
2. Enable **Auto-Deploy**
3. Configure filters:
   - **Providers** - Which cloud providers
   - **Asset Types** - EC2, VM, GCE, etc.
   - **Platforms** - Linux, Windows, etc.
4. Save configuration

### How Auto-Deploy Works

1. Cloud discovery finds new instances
2. Autopilot filters eligible assets
3. Checks governance controls (execution mode, scope)
4. Initiates agent deployment via cloud APIs:
   - **AWS**: SSM Run Command
   - **Azure**: Run Command extension
   - **GCP**: Compute API
5. Monitors deployment status
6. Updates agent inventory on success

### Deployment Options

| Option | Description | Default |
|--------|-------------|---------|
| Max Concurrent | Parallel deployments | 10 |
| Timeout | Per-deployment timeout | 300 seconds |
| Retry Failed | Retry on failure | Yes |
| Max Retries | Retry attempts | 3 |
| Skip Offline | Skip stopped instances | Yes |

### Filter Rules

Control which assets receive agents:

| Filter | Description |
|--------|-------------|
| Include Tags | Only deploy to assets with specific tags |
| Exclude Tags | Skip assets with specific tags |
| Include Regions | Only specific regions |
| Exclude Regions | Skip specific regions |
| Min Instance Size | Skip very small instances |

## Credential Security

### Encryption

- Credentials encrypted at rest using AES-256
- Encryption keys stored separately
- Keys rotated automatically

### Access Control

- Only admin users can view/modify credentials
- Credentials never exposed in API responses
- Audit logging for all credential operations

### Best Practices

1. **Use least privilege** - Only grant required permissions
2. **Rotate regularly** - Update credentials periodically
3. **Use roles where possible** - AWS IAM roles, Azure managed identity
4. **Monitor access** - Review cloud provider audit logs

## Multi-Region Support

### AWS Regions

Discovery scans all standard AWS regions:
- US East/West
- EU (Ireland, Frankfurt, London, etc.)
- Asia Pacific
- South America
- Canada
- Middle East
- Africa

### Azure Regions

Discovers across all subscriptions the service principal has access to.

### GCP Regions

Discovers across all projects the service account has access to.

## Troubleshooting

### Connection Failed

| Error | Solution |
|-------|----------|
| Invalid credentials | Verify access key/secret are correct |
| Access denied | Check IAM permissions |
| Timeout | Check network connectivity |
| Rate limited | Wait and retry |

### Discovery Issues

| Issue | Solution |
|-------|----------|
| No assets found | Check permissions for asset types |
| Partial results | Check region-specific permissions |
| Stale data | Run discovery again |

### Deployment Failures

| Error | Solution |
|-------|----------|
| SSM not configured | Install SSM agent on EC2 instances |
| Permission denied | Check deployment IAM permissions |
| Instance offline | Enable "Skip Offline" option |
| Timeout | Increase deployment timeout |
