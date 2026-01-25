import * as net from "net";
import * as http from "http";
import * as https from "https";
import { URL } from "url";

export interface ConnectionResult {
  success: boolean;
  connected: boolean;
  portOpen: boolean;
  responseReceived: boolean;
  authResult?: "success" | "failure" | "unknown";
  banner?: string;
  responseData?: string;
  error?: string;
  timing: {
    connectMs: number;
    totalMs: number;
  };
  evidence: Record<string, unknown>;
}

export interface ProtocolConnectionRequest {
  targetHost: string;
  port: number;
  protocol: "smb" | "winrm" | "ssh" | "rdp" | "wmi";
  username?: string;
  domain?: string;
  credential?: string;
  credentialType?: "password" | "ntlm_hash" | "kerberos_ticket" | "ssh_key";
  timeout?: number;
}

const BLOCKED_HOSTS = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,
  /^::1$/,
  /^0\.0\.0\.0$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /\.gov$/i,
  /\.mil$/i,
];

const DEFAULT_PORTS = {
  smb: 445,
  winrm: 5985,
  winrms: 5986,
  ssh: 22,
  rdp: 3389,
  wmi: 135,
};

function validateTarget(host: string): { valid: boolean; reason?: string } {
  for (const pattern of BLOCKED_HOSTS) {
    if (pattern.test(host)) {
      return { valid: false, reason: `Host "${host}" is blocked by safety rules` };
    }
  }
  return { valid: true };
}

async function tcpConnect(
  host: string,
  port: number,
  timeout: number = 5000
): Promise<{ connected: boolean; banner?: string; error?: string; timing: number }> {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const socket = new net.Socket();
    let banner = "";
    let resolved = false;

    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
      }
    };

    socket.setTimeout(timeout);

    socket.on("connect", () => {
      const connectTime = Date.now() - startTime;
      socket.setTimeout(2000);
      
      setTimeout(() => {
        cleanup();
        resolve({ connected: true, banner: banner || undefined, timing: Date.now() - startTime });
      }, 500);
    });

    socket.on("data", (data) => {
      banner += data.toString("utf8").slice(0, 1024);
    });

    socket.on("timeout", () => {
      cleanup();
      resolve({ connected: false, error: "Connection timeout", timing: Date.now() - startTime });
    });

    socket.on("error", (err) => {
      cleanup();
      resolve({ connected: false, error: err.message, timing: Date.now() - startTime });
    });

    socket.on("close", () => {
      cleanup();
    });

    try {
      socket.connect(port, host);
    } catch (err) {
      cleanup();
      resolve({ connected: false, error: (err as Error).message, timing: Date.now() - startTime });
    }
  });
}

async function testSMB(
  request: ProtocolConnectionRequest
): Promise<ConnectionResult> {
  const startTime = Date.now();
  const port = request.port || DEFAULT_PORTS.smb;
  const timeout = request.timeout || 10000;

  const validation = validateTarget(request.targetHost);
  if (!validation.valid) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: validation.reason,
      timing: { connectMs: 0, totalMs: 0 },
      evidence: { blocked: true, reason: validation.reason },
    };
  }

  const tcpResult = await tcpConnect(request.targetHost, port, timeout);
  
  if (!tcpResult.connected) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: tcpResult.error,
      timing: { connectMs: tcpResult.timing, totalMs: Date.now() - startTime },
      evidence: { tcpConnect: false, error: tcpResult.error },
    };
  }

  const evidence: Record<string, unknown> = {
    protocol: "SMB",
    port,
    tcpConnect: true,
    banner: tcpResult.banner,
  };

  if (tcpResult.banner) {
    const smbSignatures = [
      /SMB/i,
      /Windows/i,
      /Samba/i,
      /\x00SMB/,
      /microsoft-ds/i,
    ];
    
    const isSmbService = smbSignatures.some(sig => sig.test(tcpResult.banner!));
    evidence.smbService = isSmbService;
  }

  const authResult = request.username && request.credential ? "unknown" : undefined;
  evidence.authAttempted = !!request.username;
  evidence.authResult = authResult;

  return {
    success: true,
    connected: true,
    portOpen: true,
    responseReceived: !!tcpResult.banner,
    banner: tcpResult.banner,
    authResult,
    timing: { connectMs: tcpResult.timing, totalMs: Date.now() - startTime },
    evidence,
  };
}

async function testWinRM(
  request: ProtocolConnectionRequest
): Promise<ConnectionResult> {
  const startTime = Date.now();
  const port = request.port || DEFAULT_PORTS.winrm;
  const useHttps = port === 5986;
  const timeout = request.timeout || 10000;

  const validation = validateTarget(request.targetHost);
  if (!validation.valid) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: validation.reason,
      timing: { connectMs: 0, totalMs: 0 },
      evidence: { blocked: true, reason: validation.reason },
    };
  }

  return new Promise((resolve) => {
    const protocol = useHttps ? https : http;
    const url = `${useHttps ? "https" : "http"}://${request.targetHost}:${port}/wsman`;
    
    const reqOptions = {
      method: "POST",
      hostname: request.targetHost,
      port,
      path: "/wsman",
      headers: {
        "Content-Type": "application/soap+xml;charset=UTF-8",
        "User-Agent": "OdinForge-AEV/1.0",
      },
      timeout,
      rejectUnauthorized: false,
    };

    const req = protocol.request(reqOptions, (res) => {
      let data = "";
      res.on("data", (chunk) => {
        data += chunk.toString().slice(0, 4096);
      });
      res.on("end", () => {
        const evidence: Record<string, unknown> = {
          protocol: "WinRM",
          port,
          url,
          statusCode: res.statusCode,
          headers: res.headers,
          responsePreview: data.slice(0, 512),
        };

        const winrmActive = res.statusCode === 401 || 
                           res.statusCode === 403 || 
                           res.statusCode === 200 ||
                           (res.headers["www-authenticate"] && 
                            (res.headers["www-authenticate"].includes("Negotiate") ||
                             res.headers["www-authenticate"].includes("Kerberos") ||
                             res.headers["www-authenticate"].includes("Basic")));

        evidence.winrmActive = winrmActive;
        evidence.authMethods = res.headers["www-authenticate"];

        resolve({
          success: true,
          connected: true,
          portOpen: true,
          responseReceived: true,
          responseData: data.slice(0, 512),
          timing: { connectMs: Date.now() - startTime, totalMs: Date.now() - startTime },
          evidence,
        });
      });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({
        success: false,
        connected: false,
        portOpen: false,
        responseReceived: false,
        error: "Connection timeout",
        timing: { connectMs: timeout, totalMs: Date.now() - startTime },
        evidence: { timeout: true },
      });
    });

    req.on("error", (err) => {
      const isConnectError = err.message.includes("ECONNREFUSED") || 
                            err.message.includes("EHOSTUNREACH") ||
                            err.message.includes("ETIMEDOUT");
      resolve({
        success: !isConnectError,
        connected: !isConnectError,
        portOpen: !err.message.includes("ECONNREFUSED"),
        responseReceived: false,
        error: err.message,
        timing: { connectMs: Date.now() - startTime, totalMs: Date.now() - startTime },
        evidence: { error: err.message, connectError: isConnectError },
      });
    });

    req.end();
  });
}

async function testSSH(
  request: ProtocolConnectionRequest
): Promise<ConnectionResult> {
  const startTime = Date.now();
  const port = request.port || DEFAULT_PORTS.ssh;
  const timeout = request.timeout || 10000;

  const validation = validateTarget(request.targetHost);
  if (!validation.valid) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: validation.reason,
      timing: { connectMs: 0, totalMs: 0 },
      evidence: { blocked: true, reason: validation.reason },
    };
  }

  const tcpResult = await tcpConnect(request.targetHost, port, timeout);
  
  const evidence: Record<string, unknown> = {
    protocol: "SSH",
    port,
    tcpConnect: tcpResult.connected,
    banner: tcpResult.banner,
  };

  if (!tcpResult.connected) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: tcpResult.error,
      timing: { connectMs: tcpResult.timing, totalMs: Date.now() - startTime },
      evidence,
    };
  }

  if (tcpResult.banner) {
    const sshMatch = tcpResult.banner.match(/SSH-[\d\.]+-(.+)/);
    if (sshMatch) {
      evidence.sshVersion = sshMatch[0];
      evidence.serverSoftware = sshMatch[1];
    }
    
    evidence.isSSH = tcpResult.banner.startsWith("SSH-");
  }

  return {
    success: true,
    connected: true,
    portOpen: true,
    responseReceived: !!tcpResult.banner,
    banner: tcpResult.banner,
    timing: { connectMs: tcpResult.timing, totalMs: Date.now() - startTime },
    evidence,
  };
}

async function testRDP(
  request: ProtocolConnectionRequest
): Promise<ConnectionResult> {
  const startTime = Date.now();
  const port = request.port || DEFAULT_PORTS.rdp;
  const timeout = request.timeout || 10000;

  const validation = validateTarget(request.targetHost);
  if (!validation.valid) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: validation.reason,
      timing: { connectMs: 0, totalMs: 0 },
      evidence: { blocked: true, reason: validation.reason },
    };
  }

  const tcpResult = await tcpConnect(request.targetHost, port, timeout);
  
  const evidence: Record<string, unknown> = {
    protocol: "RDP",
    port,
    tcpConnect: tcpResult.connected,
  };

  if (!tcpResult.connected) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: tcpResult.error,
      timing: { connectMs: tcpResult.timing, totalMs: Date.now() - startTime },
      evidence,
    };
  }

  evidence.rdpServiceActive = true;

  return {
    success: true,
    connected: true,
    portOpen: true,
    responseReceived: false,
    timing: { connectMs: tcpResult.timing, totalMs: Date.now() - startTime },
    evidence,
  };
}

async function testWMI(
  request: ProtocolConnectionRequest
): Promise<ConnectionResult> {
  const startTime = Date.now();
  const port = request.port || DEFAULT_PORTS.wmi;
  const timeout = request.timeout || 10000;

  const validation = validateTarget(request.targetHost);
  if (!validation.valid) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: validation.reason,
      timing: { connectMs: 0, totalMs: 0 },
      evidence: { blocked: true, reason: validation.reason },
    };
  }

  const tcpResult = await tcpConnect(request.targetHost, port, timeout);
  
  const evidence: Record<string, unknown> = {
    protocol: "WMI/RPC",
    port,
    tcpConnect: tcpResult.connected,
  };

  if (!tcpResult.connected) {
    return {
      success: false,
      connected: false,
      portOpen: false,
      responseReceived: false,
      error: tcpResult.error,
      timing: { connectMs: tcpResult.timing, totalMs: Date.now() - startTime },
      evidence,
    };
  }

  evidence.rpcServiceActive = true;

  return {
    success: true,
    connected: true,
    portOpen: true,
    responseReceived: false,
    timing: { connectMs: tcpResult.timing, totalMs: Date.now() - startTime },
    evidence,
  };
}

export async function testProtocolConnection(
  request: ProtocolConnectionRequest
): Promise<ConnectionResult> {
  switch (request.protocol) {
    case "smb":
      return testSMB(request);
    case "winrm":
      return testWinRM(request);
    case "ssh":
      return testSSH(request);
    case "rdp":
      return testRDP(request);
    case "wmi":
      return testWMI(request);
    default:
      return {
        success: false,
        connected: false,
        portOpen: false,
        responseReceived: false,
        error: `Unknown protocol: ${request.protocol}`,
        timing: { connectMs: 0, totalMs: 0 },
        evidence: {},
      };
  }
}

export async function probeHost(
  host: string,
  protocols: ("smb" | "winrm" | "ssh" | "rdp" | "wmi")[] = ["smb", "winrm", "ssh"],
  timeout: number = 5000
): Promise<{ host: string; results: Record<string, ConnectionResult> }> {
  const results: Record<string, ConnectionResult> = {};

  for (const protocol of protocols) {
    results[protocol] = await testProtocolConnection({
      targetHost: host,
      port: DEFAULT_PORTS[protocol],
      protocol,
      timeout,
    });
  }

  return { host, results };
}

export const protocolConnectors = {
  testProtocolConnection,
  probeHost,
  validateTarget,
  DEFAULT_PORTS,
};
