export interface TemplateQuestion {
  id: string;
  label: string;
  type: "select" | "radio" | "checkbox" | "text";
  options?: { value: string; label: string }[];
  required?: boolean;
  helpText?: string;
}

export interface InfrastructureType {
  id: string;
  name: string;
  description: string;
  icon: string;
  versions: { value: string; label: string }[];
  questions: TemplateQuestion[];
}

export interface TemplateCategory {
  id: string;
  name: string;
  description: string;
  icon: string;
  types: InfrastructureType[];
}

const commonQuestions: Record<string, TemplateQuestion> = {
  internetExposed: {
    id: "internetExposed",
    label: "Is this system exposed to the internet?",
    type: "radio",
    options: [
      { value: "yes", label: "Yes - Publicly accessible" },
      { value: "no", label: "No - Internal network only" },
      { value: "unsure", label: "Not sure" },
    ],
    required: true,
  },
  dataSensitivity: {
    id: "dataSensitivity",
    label: "What type of data does this system handle?",
    type: "select",
    options: [
      { value: "pii", label: "PII (Personal Identifiable Information)" },
      { value: "financial", label: "Financial/Payment data" },
      { value: "healthcare", label: "Healthcare/PHI data" },
      { value: "credentials", label: "Credentials/Secrets" },
      { value: "business", label: "Business confidential" },
      { value: "public", label: "Public/Non-sensitive data" },
      { value: "unknown", label: "Not sure" },
    ],
    required: true,
  },
  patchStatus: {
    id: "patchStatus",
    label: "Patch status",
    type: "radio",
    options: [
      { value: "current", label: "Fully patched and up to date" },
      { value: "behind", label: "Behind on patches" },
      { value: "unknown", label: "Unknown/Not monitored" },
    ],
    required: true,
  },
  authMethod: {
    id: "authMethod",
    label: "Authentication method",
    type: "select",
    options: [
      { value: "none", label: "No authentication" },
      { value: "basic", label: "Username/Password only" },
      { value: "mfa", label: "Multi-factor authentication" },
      { value: "sso", label: "SSO/Enterprise authentication" },
      { value: "cert", label: "Certificate-based" },
      { value: "api_key", label: "API key" },
      { value: "unknown", label: "Not sure" },
    ],
    required: true,
  },
};

export const evaluationTemplates: TemplateCategory[] = [
  {
    id: "web_servers",
    name: "Web Servers",
    description: "Apache, Nginx, IIS, and other HTTP servers",
    icon: "Globe",
    types: [
      {
        id: "apache",
        name: "Apache HTTP Server",
        description: "Open-source web server",
        icon: "Server",
        versions: [
          { value: "2.4.58", label: "2.4.58 (Latest)" },
          { value: "2.4.57", label: "2.4.57" },
          { value: "2.4.54", label: "2.4.54" },
          { value: "2.4.51", label: "2.4.51" },
          { value: "2.4.49", label: "2.4.49 (CVE-2021-41773)" },
          { value: "2.4.48", label: "2.4.48" },
          { value: "2.2.x", label: "2.2.x (EOL)" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "modules",
            label: "Which modules are enabled?",
            type: "checkbox",
            options: [
              { value: "mod_ssl", label: "SSL/TLS (mod_ssl)" },
              { value: "mod_php", label: "PHP (mod_php)" },
              { value: "mod_cgi", label: "CGI scripts (mod_cgi)" },
              { value: "mod_proxy", label: "Reverse proxy (mod_proxy)" },
              { value: "mod_status", label: "Server status (mod_status)" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "nginx",
        name: "Nginx",
        description: "High-performance web server and reverse proxy",
        icon: "Server",
        versions: [
          { value: "1.25.x", label: "1.25.x (Latest mainline)" },
          { value: "1.24.x", label: "1.24.x (Latest stable)" },
          { value: "1.22.x", label: "1.22.x" },
          { value: "1.20.x", label: "1.20.x" },
          { value: "1.18.x", label: "1.18.x" },
          { value: "older", label: "Older than 1.18" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "config",
            label: "What is Nginx used for?",
            type: "checkbox",
            options: [
              { value: "static", label: "Serving static files" },
              { value: "reverse_proxy", label: "Reverse proxy" },
              { value: "load_balancer", label: "Load balancing" },
              { value: "ssl_termination", label: "SSL termination" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "iis",
        name: "Microsoft IIS",
        description: "Windows-based web server",
        icon: "Server",
        versions: [
          { value: "10.0", label: "IIS 10.0 (Windows Server 2016/2019/2022)" },
          { value: "8.5", label: "IIS 8.5 (Windows Server 2012 R2)" },
          { value: "8.0", label: "IIS 8.0 (Windows Server 2012)" },
          { value: "7.5", label: "IIS 7.5 (Windows Server 2008 R2)" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "features",
            label: "Which features are enabled?",
            type: "checkbox",
            options: [
              { value: "asp_net", label: "ASP.NET" },
              { value: "webdav", label: "WebDAV" },
              { value: "ftp", label: "FTP service" },
              { value: "cgi", label: "CGI" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "tomcat",
        name: "Apache Tomcat",
        description: "Java servlet container",
        icon: "Server",
        versions: [
          { value: "10.1.x", label: "10.1.x (Latest)" },
          { value: "10.0.x", label: "10.0.x" },
          { value: "9.0.x", label: "9.0.x" },
          { value: "8.5.x", label: "8.5.x" },
          { value: "8.0.x", label: "8.0.x (EOL)" },
          { value: "7.x", label: "7.x (EOL)" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "manager",
            label: "Is the Tomcat Manager accessible?",
            type: "radio",
            options: [
              { value: "yes_default", label: "Yes, with default credentials" },
              { value: "yes_custom", label: "Yes, with custom credentials" },
              { value: "no", label: "No, disabled or restricted" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
    ],
  },
  {
    id: "databases",
    name: "Databases",
    description: "SQL and NoSQL database systems",
    icon: "Database",
    types: [
      {
        id: "mysql",
        name: "MySQL",
        description: "Popular open-source relational database",
        icon: "Database",
        versions: [
          { value: "8.0.x", label: "8.0.x (Latest)" },
          { value: "5.7.x", label: "5.7.x" },
          { value: "5.6.x", label: "5.6.x (EOL)" },
          { value: "5.5.x", label: "5.5.x (EOL)" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          commonQuestions.authMethod,
          {
            id: "remote_access",
            label: "Is remote access enabled?",
            type: "radio",
            options: [
              { value: "all", label: "Yes, from any host" },
              { value: "specific", label: "Yes, from specific IPs only" },
              { value: "localhost", label: "No, localhost only" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "postgresql",
        name: "PostgreSQL",
        description: "Advanced open-source relational database",
        icon: "Database",
        versions: [
          { value: "16.x", label: "16.x (Latest)" },
          { value: "15.x", label: "15.x" },
          { value: "14.x", label: "14.x" },
          { value: "13.x", label: "13.x" },
          { value: "12.x", label: "12.x" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          commonQuestions.authMethod,
          {
            id: "pg_hba",
            label: "How is host-based authentication configured?",
            type: "radio",
            options: [
              { value: "trust", label: "Trust (no password required)" },
              { value: "md5", label: "MD5 password" },
              { value: "scram", label: "SCRAM-SHA-256" },
              { value: "cert", label: "Certificate authentication" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "mongodb",
        name: "MongoDB",
        description: "Document-oriented NoSQL database",
        icon: "Database",
        versions: [
          { value: "7.0", label: "7.0 (Latest)" },
          { value: "6.0", label: "6.0" },
          { value: "5.0", label: "5.0" },
          { value: "4.4", label: "4.4" },
          { value: "4.2", label: "4.2" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "auth_enabled",
            label: "Is authentication enabled?",
            type: "radio",
            options: [
              { value: "no", label: "No - Anyone can connect" },
              { value: "yes", label: "Yes - Credentials required" },
              { value: "unknown", label: "Not sure" },
            ],
            required: true,
          },
          {
            id: "bind_ip",
            label: "What IP is MongoDB bound to?",
            type: "radio",
            options: [
              { value: "all", label: "0.0.0.0 (All interfaces)" },
              { value: "localhost", label: "127.0.0.1 (Localhost only)" },
              { value: "specific", label: "Specific internal IPs" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "redis",
        name: "Redis",
        description: "In-memory data store",
        icon: "Database",
        versions: [
          { value: "7.2", label: "7.2 (Latest)" },
          { value: "7.0", label: "7.0" },
          { value: "6.2", label: "6.2" },
          { value: "6.0", label: "6.0" },
          { value: "5.x", label: "5.x" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "protected_mode",
            label: "Is protected mode enabled?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "requirepass",
            label: "Is a password required?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "mssql",
        name: "Microsoft SQL Server",
        description: "Enterprise relational database",
        icon: "Database",
        versions: [
          { value: "2022", label: "SQL Server 2022" },
          { value: "2019", label: "SQL Server 2019" },
          { value: "2017", label: "SQL Server 2017" },
          { value: "2016", label: "SQL Server 2016" },
          { value: "2014", label: "SQL Server 2014" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "auth_mode",
            label: "Authentication mode",
            type: "radio",
            options: [
              { value: "windows", label: "Windows Authentication only" },
              { value: "mixed", label: "Mixed Mode (SQL + Windows)" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "sa_account",
            label: "Is the SA account enabled?",
            type: "radio",
            options: [
              { value: "yes_default", label: "Yes, with default/weak password" },
              { value: "yes_strong", label: "Yes, with strong password" },
              { value: "no", label: "No, disabled" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
    ],
  },
  {
    id: "cloud_storage",
    name: "Cloud Storage",
    description: "AWS S3, Azure Blob, and other cloud storage services",
    icon: "Cloud",
    types: [
      {
        id: "aws_s3",
        name: "AWS S3 Bucket",
        description: "Amazon Simple Storage Service",
        icon: "Cloud",
        versions: [
          { value: "current", label: "Current (S3 managed service)" },
        ],
        questions: [
          {
            id: "public_access",
            label: "Is public access enabled?",
            type: "radio",
            options: [
              { value: "public_read", label: "Yes - Public read access" },
              { value: "public_write", label: "Yes - Public read/write access" },
              { value: "no", label: "No - Private only" },
              { value: "unknown", label: "Not sure" },
            ],
            required: true,
          },
          commonQuestions.dataSensitivity,
          {
            id: "encryption",
            label: "Is server-side encryption enabled?",
            type: "radio",
            options: [
              { value: "none", label: "No encryption" },
              { value: "sse_s3", label: "SSE-S3 (S3 managed keys)" },
              { value: "sse_kms", label: "SSE-KMS (KMS managed keys)" },
              { value: "sse_c", label: "SSE-C (Customer provided keys)" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "logging",
            label: "Is access logging enabled?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
      {
        id: "azure_blob",
        name: "Azure Blob Storage",
        description: "Microsoft Azure object storage",
        icon: "Cloud",
        versions: [
          { value: "current", label: "Current (Azure managed service)" },
        ],
        questions: [
          {
            id: "access_level",
            label: "Container access level",
            type: "radio",
            options: [
              { value: "private", label: "Private (no anonymous access)" },
              { value: "blob", label: "Blob (anonymous read for blobs)" },
              { value: "container", label: "Container (anonymous read for container and blobs)" },
              { value: "unknown", label: "Not sure" },
            ],
            required: true,
          },
          commonQuestions.dataSensitivity,
          {
            id: "sas_tokens",
            label: "Are SAS tokens being used?",
            type: "radio",
            options: [
              { value: "yes_long", label: "Yes, with long expiration" },
              { value: "yes_short", label: "Yes, with short expiration" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
      {
        id: "gcp_storage",
        name: "Google Cloud Storage",
        description: "GCP object storage",
        icon: "Cloud",
        versions: [
          { value: "current", label: "Current (GCP managed service)" },
        ],
        questions: [
          {
            id: "iam_access",
            label: "Who has access to this bucket?",
            type: "radio",
            options: [
              { value: "public", label: "allUsers (Public)" },
              { value: "all_authenticated", label: "allAuthenticatedUsers" },
              { value: "specific", label: "Specific IAM members only" },
              { value: "unknown", label: "Not sure" },
            ],
            required: true,
          },
          commonQuestions.dataSensitivity,
          {
            id: "uniform_access",
            label: "Is uniform bucket-level access enabled?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes (recommended)" },
              { value: "no", label: "No (using ACLs)" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
    ],
  },
  {
    id: "containers",
    name: "Containers & Kubernetes",
    description: "Docker, Kubernetes, and container orchestration",
    icon: "Box",
    types: [
      {
        id: "docker",
        name: "Docker",
        description: "Container runtime",
        icon: "Box",
        versions: [
          { value: "24.x", label: "24.x (Latest)" },
          { value: "23.x", label: "23.x" },
          { value: "20.x", label: "20.x" },
          { value: "19.x", label: "19.x" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          {
            id: "socket_exposed",
            label: "Is the Docker socket exposed?",
            type: "radio",
            options: [
              { value: "network", label: "Yes, over network (TCP)" },
              { value: "mount", label: "Yes, mounted in containers" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
            required: true,
          },
          {
            id: "privileged",
            label: "Are containers running in privileged mode?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "some", label: "Some containers" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "images",
            label: "Image source",
            type: "radio",
            options: [
              { value: "official", label: "Official/verified images only" },
              { value: "mixed", label: "Mix of official and third-party" },
              { value: "any", label: "Any available images" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
      {
        id: "kubernetes",
        name: "Kubernetes",
        description: "Container orchestration platform",
        icon: "Box",
        versions: [
          { value: "1.29", label: "1.29 (Latest)" },
          { value: "1.28", label: "1.28" },
          { value: "1.27", label: "1.27" },
          { value: "1.26", label: "1.26" },
          { value: "1.25", label: "1.25" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          {
            id: "api_access",
            label: "Is the Kubernetes API publicly accessible?",
            type: "radio",
            options: [
              { value: "public", label: "Yes, from internet" },
              { value: "vpn", label: "VPN/internal network only" },
              { value: "no", label: "No external access" },
              { value: "unknown", label: "Not sure" },
            ],
            required: true,
          },
          {
            id: "rbac",
            label: "Is RBAC enabled?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "network_policies",
            label: "Are network policies in place?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
    ],
  },
  {
    id: "network",
    name: "Network Infrastructure",
    description: "VPN, firewalls, load balancers, and network devices",
    icon: "Network",
    types: [
      {
        id: "vpn",
        name: "VPN Gateway",
        description: "Virtual Private Network endpoint",
        icon: "Shield",
        versions: [
          { value: "openvpn", label: "OpenVPN" },
          { value: "wireguard", label: "WireGuard" },
          { value: "ipsec", label: "IPSec" },
          { value: "ssl_vpn", label: "SSL VPN" },
          { value: "other", label: "Other" },
          { value: "unknown", label: "Unknown" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.authMethod,
          {
            id: "split_tunnel",
            label: "Is split tunneling enabled?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No (full tunnel)" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "mfa",
            label: "Is MFA required for VPN access?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
      {
        id: "firewall",
        name: "Firewall",
        description: "Network firewall appliance",
        icon: "Shield",
        versions: [
          { value: "pfsense", label: "pfSense" },
          { value: "palo_alto", label: "Palo Alto" },
          { value: "fortinet", label: "Fortinet FortiGate" },
          { value: "cisco_asa", label: "Cisco ASA" },
          { value: "sophos", label: "Sophos" },
          { value: "other", label: "Other" },
          { value: "unknown", label: "Unknown" },
        ],
        questions: [
          {
            id: "mgmt_access",
            label: "Is management interface accessible from internet?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "vpn_only", label: "VPN only" },
              { value: "internal", label: "Internal network only" },
              { value: "unknown", label: "Not sure" },
            ],
            required: true,
          },
          {
            id: "default_rules",
            label: "Are there any default allow rules?",
            type: "radio",
            options: [
              { value: "allow_all_out", label: "Allow all outbound" },
              { value: "allow_all", label: "Allow all (inbound and outbound)" },
              { value: "deny_all", label: "Deny all by default" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "load_balancer",
        name: "Load Balancer",
        description: "Traffic distribution appliance",
        icon: "Network",
        versions: [
          { value: "aws_alb", label: "AWS ALB/NLB" },
          { value: "azure_lb", label: "Azure Load Balancer" },
          { value: "gcp_lb", label: "GCP Load Balancer" },
          { value: "haproxy", label: "HAProxy" },
          { value: "nginx", label: "Nginx" },
          { value: "f5", label: "F5 BIG-IP" },
          { value: "other", label: "Other" },
        ],
        questions: [
          commonQuestions.internetExposed,
          {
            id: "ssl_termination",
            label: "Where does SSL termination happen?",
            type: "radio",
            options: [
              { value: "lb", label: "At the load balancer" },
              { value: "backend", label: "At backend servers" },
              { value: "both", label: "End-to-end encryption" },
              { value: "none", label: "No SSL/TLS" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "health_checks",
            label: "Are health check endpoints authenticated?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
    ],
  },
  {
    id: "identity",
    name: "Identity & Access",
    description: "Active Directory, LDAP, SSO, and IAM systems",
    icon: "Users",
    types: [
      {
        id: "active_directory",
        name: "Active Directory",
        description: "Windows domain services",
        icon: "Users",
        versions: [
          { value: "2022", label: "Windows Server 2022" },
          { value: "2019", label: "Windows Server 2019" },
          { value: "2016", label: "Windows Server 2016" },
          { value: "2012r2", label: "Windows Server 2012 R2" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          {
            id: "domain_level",
            label: "Domain functional level",
            type: "select",
            options: [
              { value: "2016", label: "Windows Server 2016" },
              { value: "2012r2", label: "Windows Server 2012 R2" },
              { value: "2012", label: "Windows Server 2012" },
              { value: "2008r2", label: "Windows Server 2008 R2" },
              { value: "older", label: "Older" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "ldaps",
            label: "Is LDAPS (LDAP over SSL) enabled?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No (plain LDAP)" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "smb_signing",
            label: "Is SMB signing required?",
            type: "radio",
            options: [
              { value: "required", label: "Required" },
              { value: "optional", label: "Optional" },
              { value: "disabled", label: "Disabled" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "krbtgt",
            label: "When was KRBTGT password last reset?",
            type: "radio",
            options: [
              { value: "recent", label: "Within last 180 days" },
              { value: "old", label: "More than 180 days ago" },
              { value: "never", label: "Never changed" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "ldap",
        name: "LDAP Server",
        description: "OpenLDAP or similar directory service",
        icon: "Users",
        versions: [
          { value: "openldap_2.6", label: "OpenLDAP 2.6.x" },
          { value: "openldap_2.5", label: "OpenLDAP 2.5.x" },
          { value: "openldap_2.4", label: "OpenLDAP 2.4.x" },
          { value: "389ds", label: "389 Directory Server" },
          { value: "other", label: "Other LDAP implementation" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          {
            id: "tls",
            label: "Is TLS/SSL enabled?",
            type: "radio",
            options: [
              { value: "starttls", label: "STARTTLS" },
              { value: "ldaps", label: "LDAPS (port 636)" },
              { value: "no", label: "Plain LDAP only" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "anon_bind",
            label: "Is anonymous bind allowed?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
    ],
  },
  {
    id: "email",
    name: "Email Systems",
    description: "Exchange, O365, and mail servers",
    icon: "Mail",
    types: [
      {
        id: "exchange",
        name: "Microsoft Exchange",
        description: "On-premises Exchange Server",
        icon: "Mail",
        versions: [
          { value: "2019", label: "Exchange 2019" },
          { value: "2016", label: "Exchange 2016" },
          { value: "2013", label: "Exchange 2013" },
          { value: "2010", label: "Exchange 2010 (EOL)" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "owa",
            label: "Is Outlook Web Access (OWA) publicly accessible?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "vpn", label: "VPN only" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "activesync",
            label: "Is ActiveSync enabled?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.patchStatus,
        ],
      },
      {
        id: "o365",
        name: "Microsoft 365 / Exchange Online",
        description: "Cloud-based email service",
        icon: "Mail",
        versions: [
          { value: "current", label: "Current (Microsoft managed)" },
        ],
        questions: [
          {
            id: "mfa",
            label: "Is MFA enabled for all users?",
            type: "radio",
            options: [
              { value: "all", label: "Yes, for all users" },
              { value: "admins", label: "Only for admins" },
              { value: "optional", label: "Optional" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
            required: true,
          },
          {
            id: "conditional_access",
            label: "Are Conditional Access policies configured?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "legacy_auth",
            label: "Is legacy authentication blocked?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes, blocked" },
              { value: "no", label: "No, still allowed" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          commonQuestions.dataSensitivity,
        ],
      },
    ],
  },
  {
    id: "applications",
    name: "Application Servers",
    description: "Node.js, Java, .NET, and Python runtimes",
    icon: "Code",
    types: [
      {
        id: "nodejs",
        name: "Node.js Application",
        description: "JavaScript runtime server",
        icon: "Code",
        versions: [
          { value: "20.x", label: "20.x LTS (Current)" },
          { value: "18.x", label: "18.x LTS" },
          { value: "16.x", label: "16.x (EOL)" },
          { value: "14.x", label: "14.x (EOL)" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "npm_audit",
            label: "Are there known vulnerabilities in dependencies?",
            type: "radio",
            options: [
              { value: "none", label: "No known vulnerabilities" },
              { value: "low", label: "Low severity only" },
              { value: "high", label: "High/Critical vulnerabilities" },
              { value: "unknown", label: "Not checked" },
            ],
          },
          {
            id: "env_vars",
            label: "How are secrets managed?",
            type: "radio",
            options: [
              { value: "vault", label: "Secrets manager (Vault, AWS Secrets, etc.)" },
              { value: "env", label: "Environment variables" },
              { value: "config", label: "Config files" },
              { value: "hardcoded", label: "Hardcoded in source" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
      {
        id: "java",
        name: "Java Application",
        description: "JVM-based application server",
        icon: "Code",
        versions: [
          { value: "21", label: "Java 21 LTS" },
          { value: "17", label: "Java 17 LTS" },
          { value: "11", label: "Java 11 LTS" },
          { value: "8", label: "Java 8" },
          { value: "older", label: "Older version" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "log4j",
            label: "Is Log4j in use?",
            type: "radio",
            options: [
              { value: "no", label: "No Log4j" },
              { value: "patched", label: "Yes, patched (2.17+)" },
              { value: "vulnerable", label: "Yes, vulnerable version" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "serialization",
            label: "Is Java deserialization used with external input?",
            type: "radio",
            options: [
              { value: "no", label: "No" },
              { value: "yes", label: "Yes" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
      {
        id: "dotnet",
        name: ".NET Application",
        description: "Microsoft .NET application",
        icon: "Code",
        versions: [
          { value: "8.0", label: ".NET 8 (Latest LTS)" },
          { value: "7.0", label: ".NET 7" },
          { value: "6.0", label: ".NET 6 LTS" },
          { value: "5.0", label: ".NET 5" },
          { value: "core_3.1", label: ".NET Core 3.1" },
          { value: "framework_4.8", label: ".NET Framework 4.8" },
          { value: "framework_older", label: ".NET Framework older" },
          { value: "unknown", label: "Unknown version" },
        ],
        questions: [
          commonQuestions.internetExposed,
          commonQuestions.dataSensitivity,
          {
            id: "viewstate",
            label: "Is ViewState encryption enabled?",
            type: "radio",
            options: [
              { value: "yes", label: "Yes" },
              { value: "no", label: "No" },
              { value: "na", label: "Not applicable (not WebForms)" },
              { value: "unknown", label: "Not sure" },
            ],
          },
          {
            id: "debugging",
            label: "Is debugging enabled in production?",
            type: "radio",
            options: [
              { value: "no", label: "No" },
              { value: "yes", label: "Yes" },
              { value: "unknown", label: "Not sure" },
            ],
          },
        ],
      },
    ],
  },
];

export function generateDescription(
  category: TemplateCategory,
  type: InfrastructureType,
  version: string,
  answers: Record<string, string | string[]>
): string {
  const lines: string[] = [];
  
  lines.push(`Infrastructure: ${type.name} (${category.name})`);
  lines.push(`Version: ${version === "unknown" ? "Unknown/Not specified" : version}`);
  
  const configDetails: string[] = [];
  
  for (const question of type.questions) {
    const answer = answers[question.id];
    if (!answer || answer === "unknown" || answer === "unsure") continue;
    
    if (Array.isArray(answer)) {
      const labels = answer
        .filter(v => v !== "unknown" && v !== "unsure")
        .map(v => question.options?.find(o => o.value === v)?.label || v);
      if (labels.length > 0) {
        configDetails.push(`${question.label}: ${labels.join(", ")}`);
      }
    } else {
      const label = question.options?.find(o => o.value === answer)?.label || answer;
      configDetails.push(`${question.label}: ${label}`);
    }
  }
  
  if (configDetails.length > 0) {
    lines.push("");
    lines.push("Configuration Details:");
    configDetails.forEach(detail => lines.push(`- ${detail}`));
  }
  
  const riskFactors: string[] = [];
  if (answers.internetExposed === "yes") riskFactors.push("Internet-exposed");
  if (["pii", "financial", "healthcare", "credentials"].includes(answers.dataSensitivity as string)) {
    riskFactors.push("Handles sensitive data");
  }
  if (answers.patchStatus === "behind") riskFactors.push("Behind on patches");
  if (answers.authMethod === "none") riskFactors.push("No authentication");
  if (answers.public_access === "public_write" || answers.public_access === "public_read") {
    riskFactors.push("Public access enabled");
  }
  if (answers.auth_enabled === "no") riskFactors.push("Authentication disabled");
  
  if (riskFactors.length > 0) {
    lines.push("");
    lines.push(`Key Risk Factors: ${riskFactors.join(", ")}`);
  }
  
  lines.push("");
  lines.push("Analysis Request:");
  lines.push("1. Identify known vulnerabilities and CVEs for this version");
  lines.push("2. Assess configuration weaknesses based on the details above");
  lines.push("3. Map potential attack vectors using MITRE ATT&CK framework");
  lines.push("4. Calculate exploitability considering real-world conditions");
  lines.push("5. Provide prioritized remediation recommendations");
  
  return lines.join("\n");
}

export function getExposureType(categoryId: string, typeId: string): string {
  const typeMap: Record<string, string> = {
    "apache": "Web Server",
    "nginx": "Web Server",
    "iis": "Web Server",
    "tomcat": "Application Server",
    "mysql": "Database",
    "postgresql": "Database",
    "mongodb": "Database",
    "redis": "Database",
    "mssql": "Database",
    "aws_s3": "Cloud Storage",
    "azure_blob": "Cloud Storage",
    "gcp_storage": "Cloud Storage",
    "docker": "Container",
    "kubernetes": "Container Orchestration",
    "vpn": "Network",
    "firewall": "Network",
    "load_balancer": "Network",
    "active_directory": "Identity",
    "ldap": "Identity",
    "exchange": "Email",
    "o365": "Email",
    "nodejs": "Application",
    "java": "Application",
    "dotnet": "Application",
  };
  
  return typeMap[typeId] || categoryId;
}

export function getPriorityFromAnswers(answers: Record<string, string | string[]>): string {
  let riskScore = 0;
  
  const isInternetExposed = answers.internetExposed === "yes" || answers.internetExposed === "unsure";
  const hasSensitiveData = ["pii", "financial", "healthcare", "credentials"].includes(answers.dataSensitivity as string);
  const isUnpatched = answers.patchStatus === "behind" || answers.patchStatus === "unknown";
  const hasWeakAuth = answers.authMethod === "none" || answers.authMethod === "basic";
  
  if (answers.internetExposed === "yes") riskScore += 4;
  if (answers.internetExposed === "unsure") riskScore += 2;
  
  if (answers.dataSensitivity === "pii") riskScore += 3;
  if (answers.dataSensitivity === "financial") riskScore += 4;
  if (answers.dataSensitivity === "healthcare") riskScore += 4;
  if (answers.dataSensitivity === "credentials") riskScore += 4;
  if (answers.dataSensitivity === "business") riskScore += 2;
  
  if (answers.patchStatus === "behind") riskScore += 3;
  if (answers.patchStatus === "unknown") riskScore += 2;
  
  if (answers.authMethod === "none") riskScore += 4;
  if (answers.authMethod === "basic") riskScore += 2;
  
  if (answers.public_access === "public_write") riskScore += 5;
  if (answers.public_access === "public_read") riskScore += 3;
  
  if (answers.auth_enabled === "no") riskScore += 5;
  if (answers.socket_exposed === "network") riskScore += 4;
  if (answers.api_access === "public") riskScore += 4;
  
  if (answers.remote_access === "all") riskScore += 3;
  if (answers.bind_ip === "all") riskScore += 3;
  if (answers.protected_mode === "no") riskScore += 2;
  if (answers.requirepass === "no") riskScore += 3;
  if (answers.sa_account === "yes_default") riskScore += 4;
  if (answers.manager === "yes_default") riskScore += 4;
  if (answers.mgmt_access === "yes") riskScore += 4;
  if (answers.mfa === "no") riskScore += 3;
  if (answers.legacy_auth === "no") riskScore += 2;
  if (answers.anon_bind === "yes") riskScore += 3;
  if (answers.privileged === "yes") riskScore += 3;
  if (answers.rbac === "no") riskScore += 2;
  if (answers.log4j === "vulnerable") riskScore += 5;
  if (answers.npm_audit === "high") riskScore += 3;
  if (answers.env_vars === "hardcoded") riskScore += 3;
  if (answers.debugging === "yes") riskScore += 2;
  
  if (isInternetExposed && hasSensitiveData) riskScore += 2;
  if (isInternetExposed && isUnpatched) riskScore += 2;
  if (isInternetExposed && hasWeakAuth) riskScore += 3;
  if (hasSensitiveData && hasWeakAuth) riskScore += 2;
  
  if (riskScore >= 10) return "critical";
  if (riskScore >= 6) return "high";
  if (riskScore >= 3) return "medium";
  return "low";
}
