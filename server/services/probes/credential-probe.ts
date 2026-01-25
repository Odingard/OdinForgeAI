import { createConnection, Socket } from "net";

export interface CredentialTestResult {
  service: string;
  port: number;
  username: string;
  success: boolean;
  responseTime: number;
  evidence?: string;
  risk: "critical" | "high" | "medium" | "low";
}

export interface CredentialProbeResult {
  target: string;
  scanStarted: Date;
  scanCompleted: Date;
  durationMs: number;
  servicesScanned: number;
  vulnerableCredentials: CredentialTestResult[];
  testedCombinations: number;
}

interface DefaultCredential {
  username: string;
  password: string;
  service?: string;
}

const DEFAULT_CREDENTIALS: Record<string, DefaultCredential[]> = {
  ssh: [
    { username: "root", password: "root" },
    { username: "root", password: "admin" },
    { username: "root", password: "password" },
    { username: "root", password: "123456" },
    { username: "root", password: "toor" },
    { username: "admin", password: "admin" },
    { username: "admin", password: "password" },
    { username: "admin", password: "1234" },
    { username: "ubuntu", password: "ubuntu" },
    { username: "pi", password: "raspberry" },
  ],
  ftp: [
    { username: "anonymous", password: "" },
    { username: "anonymous", password: "anonymous" },
    { username: "ftp", password: "ftp" },
    { username: "admin", password: "admin" },
    { username: "root", password: "root" },
    { username: "user", password: "password" },
  ],
  mysql: [
    { username: "root", password: "" },
    { username: "root", password: "root" },
    { username: "root", password: "mysql" },
    { username: "root", password: "password" },
    { username: "admin", password: "admin" },
    { username: "mysql", password: "mysql" },
  ],
  postgres: [
    { username: "postgres", password: "" },
    { username: "postgres", password: "postgres" },
    { username: "postgres", password: "password" },
    { username: "admin", password: "admin" },
  ],
  redis: [
    { username: "", password: "" },
    { username: "", password: "redis" },
    { username: "", password: "password" },
  ],
  mongodb: [
    { username: "admin", password: "admin" },
    { username: "root", password: "root" },
    { username: "mongodb", password: "mongodb" },
  ],
  telnet: [
    { username: "admin", password: "admin" },
    { username: "root", password: "root" },
    { username: "user", password: "user" },
    { username: "guest", password: "guest" },
  ],
  http_basic: [
    { username: "admin", password: "admin" },
    { username: "admin", password: "password" },
    { username: "admin", password: "1234" },
    { username: "administrator", password: "administrator" },
    { username: "root", password: "root" },
    { username: "user", password: "user" },
    { username: "test", password: "test" },
  ],
  tomcat: [
    { username: "tomcat", password: "tomcat" },
    { username: "admin", password: "admin" },
    { username: "manager", password: "manager" },
    { username: "role1", password: "role1" },
    { username: "both", password: "tomcat" },
  ],
  jenkins: [
    { username: "admin", password: "admin" },
    { username: "jenkins", password: "jenkins" },
    { username: "admin", password: "password" },
  ],
  elasticsearch: [
    { username: "elastic", password: "elastic" },
    { username: "elastic", password: "changeme" },
    { username: "admin", password: "admin" },
  ],
  rabbitmq: [
    { username: "guest", password: "guest" },
    { username: "admin", password: "admin" },
    { username: "rabbitmq", password: "rabbitmq" },
  ],
  mssql: [
    { username: "sa", password: "" },
    { username: "sa", password: "sa" },
    { username: "sa", password: "password" },
    { username: "sa", password: "Password1" },
  ],
};

const SERVICE_PORTS: Record<string, number[]> = {
  ssh: [22, 2222],
  ftp: [21],
  mysql: [3306],
  postgres: [5432],
  redis: [6379],
  mongodb: [27017],
  telnet: [23],
  http_basic: [80, 8080, 8443],
  tomcat: [8080, 8443],
  jenkins: [8080, 8443],
  elasticsearch: [9200],
  rabbitmq: [5672, 15672],
  mssql: [1433],
};

async function checkPortOpen(host: string, port: number, timeout: number = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new Socket();
    socket.setTimeout(timeout);
    
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.connect(port, host);
  });
}

async function testHTTPBasicAuth(
  host: string,
  port: number,
  username: string,
  password: string,
  path: string = "/"
): Promise<{ success: boolean; responseTime: number; evidence?: string }> {
  const startTime = Date.now();
  const protocol = port === 443 || port === 8443 ? "https" : "http";
  const url = `${protocol}://${host}:${port}${path}`;
  
  try {
    const credentials = Buffer.from(`${username}:${password}`).toString("base64");
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "Authorization": `Basic ${credentials}`,
        "User-Agent": "OdinForge-Security-Scanner/1.0",
      },
      signal: AbortSignal.timeout(5000),
    });
    
    const responseTime = Date.now() - startTime;
    const success = response.status >= 200 && response.status < 400;
    
    return {
      success,
      responseTime,
      evidence: success ? `HTTP ${response.status} - Access granted` : undefined,
    };
  } catch (error) {
    return { success: false, responseTime: Date.now() - startTime };
  }
}

async function testTomcatManager(
  host: string,
  port: number,
  username: string,
  password: string
): Promise<{ success: boolean; responseTime: number; evidence?: string }> {
  return testHTTPBasicAuth(host, port, username, password, "/manager/html");
}

async function testJenkinsAuth(
  host: string,
  port: number,
  username: string,
  password: string
): Promise<{ success: boolean; responseTime: number; evidence?: string }> {
  const startTime = Date.now();
  const protocol = port === 443 || port === 8443 ? "https" : "http";
  const url = `${protocol}://${host}:${port}/j_acegi_security_check`;
  
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "OdinForge-Security-Scanner/1.0",
      },
      body: `j_username=${encodeURIComponent(username)}&j_password=${encodeURIComponent(password)}`,
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
    
    const responseTime = Date.now() - startTime;
    const location = response.headers.get("Location") || "";
    const success = response.status === 302 && !location.includes("loginError");
    
    return {
      success,
      responseTime,
      evidence: success ? "Jenkins login redirect to dashboard" : undefined,
    };
  } catch (error) {
    return { success: false, responseTime: Date.now() - startTime };
  }
}

async function testRedis(
  host: string,
  port: number,
  password: string
): Promise<{ success: boolean; responseTime: number; evidence?: string }> {
  const startTime = Date.now();
  
  return new Promise((resolve) => {
    const socket = new Socket();
    socket.setTimeout(5000);
    let dataReceived = "";
    
    socket.on("connect", () => {
      if (password) {
        socket.write(`AUTH ${password}\r\n`);
      } else {
        socket.write("PING\r\n");
      }
    });
    
    socket.on("data", (data) => {
      dataReceived += data.toString();
      if (dataReceived.includes("+OK") || dataReceived.includes("+PONG")) {
        socket.destroy();
        resolve({
          success: true,
          responseTime: Date.now() - startTime,
          evidence: password ? "AUTH succeeded" : "No authentication required (PING responded)",
        });
      } else if (dataReceived.includes("-NOAUTH") || dataReceived.includes("-ERR")) {
        socket.destroy();
        resolve({ success: false, responseTime: Date.now() - startTime });
      }
    });
    
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ success: false, responseTime: Date.now() - startTime });
    });
    
    socket.on("error", () => {
      socket.destroy();
      resolve({ success: false, responseTime: Date.now() - startTime });
    });
    
    socket.connect(port, host);
  });
}

async function testElasticsearch(
  host: string,
  port: number,
  username: string,
  password: string
): Promise<{ success: boolean; responseTime: number; evidence?: string }> {
  const startTime = Date.now();
  
  try {
    const credentials = Buffer.from(`${username}:${password}`).toString("base64");
    const response = await fetch(`http://${host}:${port}/_cluster/health`, {
      headers: {
        "Authorization": `Basic ${credentials}`,
        "User-Agent": "OdinForge-Security-Scanner/1.0",
      },
      signal: AbortSignal.timeout(5000),
    });
    
    const responseTime = Date.now() - startTime;
    
    if (response.ok) {
      const data = await response.json();
      return {
        success: true,
        responseTime,
        evidence: `Cluster: ${data.cluster_name}, Status: ${data.status}`,
      };
    }
    
    return { success: false, responseTime };
  } catch (error) {
    return { success: false, responseTime: Date.now() - startTime };
  }
}

async function testRabbitMQ(
  host: string,
  port: number,
  username: string,
  password: string
): Promise<{ success: boolean; responseTime: number; evidence?: string }> {
  const startTime = Date.now();
  const managementPort = port === 5672 ? 15672 : port;
  
  try {
    const credentials = Buffer.from(`${username}:${password}`).toString("base64");
    const response = await fetch(`http://${host}:${managementPort}/api/overview`, {
      headers: {
        "Authorization": `Basic ${credentials}`,
        "User-Agent": "OdinForge-Security-Scanner/1.0",
      },
      signal: AbortSignal.timeout(5000),
    });
    
    const responseTime = Date.now() - startTime;
    
    if (response.ok) {
      const data = await response.json();
      return {
        success: true,
        responseTime,
        evidence: `RabbitMQ ${data.rabbitmq_version} - ${data.node}`,
      };
    }
    
    return { success: false, responseTime };
  } catch (error) {
    return { success: false, responseTime: Date.now() - startTime };
  }
}

export async function runCredentialProbe(
  target: string,
  services?: string[],
  onProgress?: (phase: string, progress: number, message: string) => void
): Promise<CredentialProbeResult> {
  const startTime = Date.now();
  const vulnerableCredentials: CredentialTestResult[] = [];
  let testedCombinations = 0;
  
  const servicesToTest = services || Object.keys(DEFAULT_CREDENTIALS);
  const totalServices = servicesToTest.length;
  let scannedServices = 0;
  
  onProgress?.("initialization", 0, `Starting credential probe against ${target}...`);
  
  for (const service of servicesToTest) {
    const ports = SERVICE_PORTS[service] || [];
    const credentials = DEFAULT_CREDENTIALS[service] || [];
    
    for (const port of ports) {
      onProgress?.("scanning", Math.round((scannedServices / totalServices) * 100), 
        `Testing ${service} on port ${port}...`);
      
      const isOpen = await checkPortOpen(target, port);
      if (!isOpen) continue;
      
      for (const cred of credentials) {
        testedCombinations++;
        let result: { success: boolean; responseTime: number; evidence?: string };
        
        switch (service) {
          case "http_basic":
            result = await testHTTPBasicAuth(target, port, cred.username, cred.password);
            break;
          case "tomcat":
            result = await testTomcatManager(target, port, cred.username, cred.password);
            break;
          case "jenkins":
            result = await testJenkinsAuth(target, port, cred.username, cred.password);
            break;
          case "redis":
            result = await testRedis(target, port, cred.password);
            break;
          case "elasticsearch":
            result = await testElasticsearch(target, port, cred.username, cred.password);
            break;
          case "rabbitmq":
            result = await testRabbitMQ(target, port, cred.username, cred.password);
            break;
          default:
            continue;
        }
        
        if (result.success) {
          vulnerableCredentials.push({
            service,
            port,
            username: cred.username,
            success: true,
            responseTime: result.responseTime,
            evidence: result.evidence,
            risk: determineRisk(service, cred.username),
          });
          break;
        }
      }
    }
    
    scannedServices++;
  }
  
  onProgress?.("completed", 100, `Found ${vulnerableCredentials.length} default credentials`);
  
  return {
    target,
    scanStarted: new Date(startTime),
    scanCompleted: new Date(),
    durationMs: Date.now() - startTime,
    servicesScanned: scannedServices,
    vulnerableCredentials,
    testedCombinations,
  };
}

function determineRisk(service: string, username: string): "critical" | "high" | "medium" | "low" {
  const criticalServices = ["ssh", "mysql", "postgres", "mssql", "redis", "mongodb"];
  const highRiskUsers = ["root", "admin", "sa", "administrator"];
  
  if (criticalServices.includes(service) && highRiskUsers.includes(username)) {
    return "critical";
  }
  if (criticalServices.includes(service) || highRiskUsers.includes(username)) {
    return "high";
  }
  if (service === "tomcat" || service === "jenkins") {
    return "high";
  }
  return "medium";
}

export function generateCredentialReport(result: CredentialProbeResult): string {
  const lines: string[] = [
    "# Credential Probe Report",
    "",
    `**Target:** ${result.target}`,
    `**Duration:** ${(result.durationMs / 1000).toFixed(1)}s`,
    `**Services Scanned:** ${result.servicesScanned}`,
    `**Credentials Tested:** ${result.testedCombinations}`,
    `**Vulnerabilities Found:** ${result.vulnerableCredentials.length}`,
    "",
  ];
  
  if (result.vulnerableCredentials.length > 0) {
    lines.push("## Vulnerable Credentials Found");
    lines.push("");
    
    const bySeverity = {
      critical: result.vulnerableCredentials.filter(v => v.risk === "critical"),
      high: result.vulnerableCredentials.filter(v => v.risk === "high"),
      medium: result.vulnerableCredentials.filter(v => v.risk === "medium"),
      low: result.vulnerableCredentials.filter(v => v.risk === "low"),
    };
    
    for (const [severity, creds] of Object.entries(bySeverity)) {
      if (creds.length === 0) continue;
      
      lines.push(`### ${severity.toUpperCase()} Risk`);
      lines.push("");
      
      for (const cred of creds) {
        lines.push(`- **${cred.service}** on port ${cred.port}`);
        lines.push(`  - Username: \`${cred.username}\``);
        lines.push(`  - Evidence: ${cred.evidence || "Login successful"}`);
        lines.push(`  - Response Time: ${cred.responseTime}ms`);
        lines.push("");
      }
    }
  } else {
    lines.push("## No Default Credentials Found");
    lines.push("");
    lines.push("No services were found using default or weak credentials.");
  }
  
  lines.push("## Recommendations");
  lines.push("");
  lines.push("1. Change all default credentials immediately");
  lines.push("2. Implement strong password policies");
  lines.push("3. Use SSH keys instead of password authentication where possible");
  lines.push("4. Enable account lockout policies");
  lines.push("5. Implement network segmentation for sensitive services");
  
  return lines.join("\n");
}
