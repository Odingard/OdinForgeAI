import { randomUUID } from "crypto";

export interface MetasploitSession {
  id: string;
  type: "shell" | "meterpreter";
  targetHost: string;
  targetPort: number;
  moduleUsed: string;
  createdAt: Date;
  status: "active" | "closed" | "stale";
  platform: string;
  arch: string;
  sessionData: SessionData;
}

export interface SessionData {
  username?: string;
  uid?: string;
  gid?: string;
  hostname?: string;
  workingDirectory?: string;
  sysinfo?: Record<string, string>;
}

export interface ExploitResult {
  id: string;
  module: string;
  target: string;
  port: number;
  status: "success" | "failed" | "no_session" | "timeout";
  session?: MetasploitSession;
  output: string[];
  timing: {
    startTime: Date;
    endTime: Date;
    durationMs: number;
  };
  vulnerabilityInfo?: VulnerabilityInfo;
  mitreAttackMappings: MitreMapping[];
}

export interface VulnerabilityInfo {
  cveId?: string;
  cvssScore?: number;
  description: string;
  references: string[];
}

export interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
}

export interface ModuleInfo {
  name: string;
  fullName: string;
  type: "exploit" | "auxiliary" | "post" | "payload";
  rank: "excellent" | "great" | "good" | "normal" | "average" | "low" | "manual";
  description: string;
  authors: string[];
  cveIds: string[];
  platform: string[];
  arch: string[];
  targets: string[];
  options: ModuleOption[];
}

export interface ModuleOption {
  name: string;
  type: string;
  required: boolean;
  default?: string;
  description: string;
}

export interface ExploitRequest {
  module: string;
  target: string;
  port: number;
  options?: Record<string, unknown>;
  payload?: string;
  payloadOptions?: Record<string, unknown>;
}

const COMMON_MODULES: ModuleInfo[] = [
  {
    name: "ms17_010_eternalblue",
    fullName: "exploit/windows/smb/ms17_010_eternalblue",
    type: "exploit",
    rank: "excellent",
    description: "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
    authors: ["Sean Dillon", "Dylan Davis", "Equation Group"],
    cveIds: ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"],
    platform: ["windows"],
    arch: ["x86", "x64"],
    targets: ["Windows 7", "Windows 2008 R2", "Windows 2012"],
    options: [
      { name: "RHOSTS", type: "address", required: true, description: "Target address" },
      { name: "RPORT", type: "port", required: true, default: "445", description: "SMB port" },
    ],
  },
  {
    name: "apache_struts2_content_type_ognl",
    fullName: "exploit/multi/http/apache_struts2_content_type_ognl",
    type: "exploit",
    rank: "excellent",
    description: "Apache Struts Jakarta Multipart Parser OGNL Injection",
    authors: ["Nike.Zheng", "wvu"],
    cveIds: ["CVE-2017-5638"],
    platform: ["linux", "windows"],
    arch: ["x86", "x64"],
    targets: ["Unix", "Windows"],
    options: [
      { name: "RHOSTS", type: "address", required: true, description: "Target address" },
      { name: "RPORT", type: "port", required: true, default: "8080", description: "HTTP port" },
      { name: "TARGETURI", type: "string", required: true, default: "/struts2-showcase/", description: "Target path" },
    ],
  },
  {
    name: "weblogic_deserialize",
    fullName: "exploit/multi/misc/weblogic_deserialize",
    type: "exploit",
    rank: "excellent",
    description: "Oracle WebLogic Server Deserialization RCE",
    authors: ["Jang", "xxlegend"],
    cveIds: ["CVE-2017-10271", "CVE-2019-2725"],
    platform: ["linux", "windows"],
    arch: ["x86", "x64"],
    targets: ["Unix", "Windows"],
    options: [
      { name: "RHOSTS", type: "address", required: true, description: "Target address" },
      { name: "RPORT", type: "port", required: true, default: "7001", description: "WebLogic port" },
    ],
  },
  {
    name: "tomcat_mgr_upload",
    fullName: "exploit/multi/http/tomcat_mgr_upload",
    type: "exploit",
    rank: "excellent",
    description: "Apache Tomcat Manager Application Upload Authenticated Code Execution",
    authors: ["rangercha"],
    cveIds: [],
    platform: ["linux", "windows"],
    arch: ["x86", "x64"],
    targets: ["Java Universal"],
    options: [
      { name: "RHOSTS", type: "address", required: true, description: "Target address" },
      { name: "RPORT", type: "port", required: true, default: "8080", description: "HTTP port" },
      { name: "HttpUsername", type: "string", required: true, description: "Manager username" },
      { name: "HttpPassword", type: "string", required: true, description: "Manager password" },
    ],
  },
  {
    name: "jenkins_script_console",
    fullName: "exploit/multi/http/jenkins_script_console",
    type: "exploit",
    rank: "excellent",
    description: "Jenkins Script Console Unauthenticated RCE",
    authors: ["altonjx", "jas502n"],
    cveIds: ["CVE-2018-1000861"],
    platform: ["linux", "windows"],
    arch: ["x86", "x64"],
    targets: ["Unix", "Windows"],
    options: [
      { name: "RHOSTS", type: "address", required: true, description: "Target address" },
      { name: "RPORT", type: "port", required: true, default: "8080", description: "HTTP port" },
    ],
  },
];

const MITRE_MAPPINGS: Record<string, MitreMapping[]> = {
  "ms17_010_eternalblue": [
    { techniqueId: "T1210", techniqueName: "Exploitation of Remote Services", tactic: "lateral-movement" },
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access" },
  ],
  "apache_struts2_content_type_ognl": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access" },
    { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "execution" },
  ],
  "weblogic_deserialize": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access" },
    { techniqueId: "T1055", techniqueName: "Process Injection", tactic: "defense-evasion" },
  ],
  "tomcat_mgr_upload": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access" },
    { techniqueId: "T1505.003", techniqueName: "Web Shell", tactic: "persistence" },
  ],
  "jenkins_script_console": [
    { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "initial-access" },
    { techniqueId: "T1059.007", techniqueName: "JavaScript/Groovy", tactic: "execution" },
  ],
};

class MetasploitService {
  private sessions: Map<string, MetasploitSession> = new Map();

  async listModules(type?: "exploit" | "auxiliary" | "post"): Promise<ModuleInfo[]> {
    if (type) {
      return COMMON_MODULES.filter(m => m.type === type);
    }
    return COMMON_MODULES;
  }

  async searchModules(query: string): Promise<ModuleInfo[]> {
    const queryLower = query.toLowerCase();
    return COMMON_MODULES.filter(m =>
      m.name.toLowerCase().includes(queryLower) ||
      m.description.toLowerCase().includes(queryLower) ||
      m.cveIds.some(cve => cve.toLowerCase().includes(queryLower))
    );
  }

  async getModuleInfo(moduleName: string): Promise<ModuleInfo | null> {
    return COMMON_MODULES.find(m => m.name === moduleName || m.fullName === moduleName) || null;
  }

  async runExploit(request: ExploitRequest): Promise<ExploitResult> {
    const startTime = new Date();
    const output: string[] = [];
    
    const moduleInfo = await this.getModuleInfo(request.module);
    
    output.push(`[*] Starting exploit ${request.module}`);
    output.push(`[*] Target: ${request.target}:${request.port}`);
    
    if (!moduleInfo) {
      output.push(`[-] Module not found: ${request.module}`);
      return {
        id: `exploit-${randomUUID().slice(0, 8)}`,
        module: request.module,
        target: request.target,
        port: request.port,
        status: "failed",
        output,
        timing: {
          startTime,
          endTime: new Date(),
          durationMs: Date.now() - startTime.getTime(),
        },
        mitreAttackMappings: [],
      };
    }

    output.push(`[*] Using module: ${moduleInfo.fullName}`);
    output.push(`[*] Module rank: ${moduleInfo.rank}`);
    
    if (request.payload) {
      output.push(`[*] Payload: ${request.payload}`);
    }

    await this.simulateDelay(500, 2000);

    const exploitSuccessful = Math.random() > 0.3;
    
    if (exploitSuccessful) {
      output.push(`[+] Exploit completed successfully!`);
      
      const sessionType = Math.random() > 0.5 ? "meterpreter" : "shell";
      
      if (sessionType === "meterpreter") {
        output.push(`[+] Meterpreter session established!`);
        
        const session: MetasploitSession = {
          id: `session-${randomUUID().slice(0, 8)}`,
          type: "meterpreter",
          targetHost: request.target,
          targetPort: request.port,
          moduleUsed: moduleInfo.fullName,
          createdAt: new Date(),
          status: "active",
          platform: moduleInfo.platform[0],
          arch: moduleInfo.arch[0],
          sessionData: {
            username: "SYSTEM",
            uid: "S-1-5-18",
            hostname: `TARGET-${Math.random().toString(36).slice(2, 8).toUpperCase()}`,
            workingDirectory: "C:\\Windows\\System32",
            sysinfo: {
              OS: "Windows Server 2016 (Build 14393)",
              Architecture: "x64",
              Domain: "WORKGROUP",
              MeterpreterVersion: "meterpreter x64/windows",
            },
          },
        };
        
        this.sessions.set(session.id, session);
        
        output.push(`[+] Session ID: ${session.id}`);
        output.push(`[+] Session type: ${session.type}`);
        output.push(`[+] Target: ${session.targetHost}:${session.targetPort}`);
        
        return {
          id: `exploit-${randomUUID().slice(0, 8)}`,
          module: request.module,
          target: request.target,
          port: request.port,
          status: "success",
          session,
          output,
          timing: {
            startTime,
            endTime: new Date(),
            durationMs: Date.now() - startTime.getTime(),
          },
          vulnerabilityInfo: moduleInfo.cveIds.length > 0 ? {
            cveId: moduleInfo.cveIds[0],
            cvssScore: 9.8,
            description: moduleInfo.description,
            references: [`https://nvd.nist.gov/vuln/detail/${moduleInfo.cveIds[0]}`],
          } : undefined,
          mitreAttackMappings: MITRE_MAPPINGS[moduleInfo.name] || [],
        };
      } else {
        output.push(`[+] Command shell session established!`);
        
        const session: MetasploitSession = {
          id: `session-${randomUUID().slice(0, 8)}`,
          type: "shell",
          targetHost: request.target,
          targetPort: request.port,
          moduleUsed: moduleInfo.fullName,
          createdAt: new Date(),
          status: "active",
          platform: moduleInfo.platform[0],
          arch: moduleInfo.arch[0],
          sessionData: {
            username: "www-data",
            uid: "33",
            gid: "33",
            hostname: `target-${Math.random().toString(36).slice(2, 8)}`,
            workingDirectory: "/var/www/html",
          },
        };
        
        this.sessions.set(session.id, session);
        
        output.push(`[+] Session ID: ${session.id}`);
        
        return {
          id: `exploit-${randomUUID().slice(0, 8)}`,
          module: request.module,
          target: request.target,
          port: request.port,
          status: "success",
          session,
          output,
          timing: {
            startTime,
            endTime: new Date(),
            durationMs: Date.now() - startTime.getTime(),
          },
          vulnerabilityInfo: moduleInfo.cveIds.length > 0 ? {
            cveId: moduleInfo.cveIds[0],
            cvssScore: 9.8,
            description: moduleInfo.description,
            references: [`https://nvd.nist.gov/vuln/detail/${moduleInfo.cveIds[0]}`],
          } : undefined,
          mitreAttackMappings: MITRE_MAPPINGS[moduleInfo.name] || [],
        };
      }
    } else {
      output.push(`[-] Exploit failed - target may not be vulnerable or unreachable`);
      
      return {
        id: `exploit-${randomUUID().slice(0, 8)}`,
        module: request.module,
        target: request.target,
        port: request.port,
        status: "no_session",
        output,
        timing: {
          startTime,
          endTime: new Date(),
          durationMs: Date.now() - startTime.getTime(),
        },
        mitreAttackMappings: MITRE_MAPPINGS[moduleInfo.name] || [],
      };
    }
  }

  async listSessions(): Promise<MetasploitSession[]> {
    return Array.from(this.sessions.values());
  }

  async getSession(sessionId: string): Promise<MetasploitSession | null> {
    return this.sessions.get(sessionId) || null;
  }

  async executeSessionCommand(sessionId: string, command: string): Promise<string[]> {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return ["[-] Session not found"];
    }

    if (session.status !== "active") {
      return ["[-] Session is not active"];
    }

    await this.simulateDelay(100, 500);

    const output: string[] = [];
    
    if (session.type === "meterpreter") {
      output.push(`meterpreter > ${command}`);
      
      if (command === "sysinfo") {
        output.push(`Computer    : ${session.sessionData.hostname}`);
        output.push(`OS          : ${session.sessionData.sysinfo?.OS || "Unknown"}`);
        output.push(`Architecture: ${session.sessionData.sysinfo?.Architecture || session.arch}`);
        output.push(`Domain      : ${session.sessionData.sysinfo?.Domain || "WORKGROUP"}`);
        output.push(`Meterpreter : ${session.sessionData.sysinfo?.MeterpreterVersion || "meterpreter"}`);
      } else if (command === "getuid") {
        output.push(`Server username: ${session.sessionData.hostname}\\${session.sessionData.username}`);
      } else if (command === "pwd") {
        output.push(session.sessionData.workingDirectory || "C:\\");
      } else if (command === "hashdump") {
        output.push("Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::");
        output.push("Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::");
      } else {
        output.push(`[*] Command executed: ${command}`);
        output.push("[*] (simulated output)");
      }
    } else {
      output.push(`$ ${command}`);
      
      if (command === "id") {
        output.push(`uid=${session.sessionData.uid}(${session.sessionData.username}) gid=${session.sessionData.gid}(${session.sessionData.username})`);
      } else if (command === "whoami") {
        output.push(session.sessionData.username || "unknown");
      } else if (command === "pwd") {
        output.push(session.sessionData.workingDirectory || "/tmp");
      } else if (command === "uname -a") {
        output.push("Linux target-server 5.4.0-generic #1 SMP x86_64 GNU/Linux");
      } else {
        output.push(`(simulated output for: ${command})`);
      }
    }

    return output;
  }

  async closeSession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return false;
    }

    session.status = "closed";
    return true;
  }

  private simulateDelay(minMs: number, maxMs: number): Promise<void> {
    const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}

export const metasploitService = new MetasploitService();
