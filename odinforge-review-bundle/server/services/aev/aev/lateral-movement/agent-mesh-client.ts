/**
 * Agent Mesh Client
 * 
 * Interface for coordinating with deployed endpoint agents.
 * Manages agent registration, communication, and task distribution.
 */

export interface AgentInfo {
  id: string;
  hostname: string;
  ip: string;
  os: "windows" | "linux" | "macos";
  status: "active" | "inactive" | "pending" | "compromised";
  lastSeen: Date;
  capabilities: string[];
  metadata?: Record<string, any>;
}

export interface AgentTask {
  id: string;
  type: "exec" | "upload" | "download" | "scan" | "harvest" | "persist";
  command?: string;
  payload?: string;
  target?: string;
  timeout: number;
}

export interface AgentTaskResult {
  taskId: string;
  agentId: string;
  success: boolean;
  output?: string;
  error?: string;
  executionTimeMs: number;
  capturedAt: Date;
}

export interface MeshTopology {
  agents: AgentInfo[];
  connections: AgentConnection[];
  pivotChains: string[][];
}

interface AgentConnection {
  sourceId: string;
  targetId: string;
  protocol: string;
  latencyMs: number;
  bandwidth?: number;
}

export class AgentMeshClient {
  private agents: Map<string, AgentInfo> = new Map();
  private connections: AgentConnection[] = [];
  private taskQueue: Map<string, AgentTask[]> = new Map();
  private taskResults: Map<string, AgentTaskResult> = new Map();

  async registerAgent(agent: AgentInfo): Promise<boolean> {
    if (this.agents.has(agent.id)) {
      const existing = this.agents.get(agent.id)!;
      existing.lastSeen = new Date();
      existing.status = agent.status;
      return true;
    }

    this.agents.set(agent.id, {
      ...agent,
      lastSeen: new Date(),
    });

    return true;
  }

  async getAgent(id: string): Promise<AgentInfo | undefined> {
    return this.agents.get(id);
  }

  async listAgents(): Promise<AgentInfo[]> {
    return Array.from(this.agents.values());
  }

  async getActiveAgents(): Promise<AgentInfo[]> {
    const now = Date.now();
    const timeout = 5 * 60 * 1000;

    return Array.from(this.agents.values()).filter(agent => {
      const lastSeen = agent.lastSeen.getTime();
      return agent.status === "active" && (now - lastSeen) < timeout;
    });
  }

  async submitTask(agentId: string, task: AgentTask): Promise<string> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    if (agent.status !== "active") {
      throw new Error(`Agent ${agentId} is not active`);
    }

    const existingTasks = this.taskQueue.get(agentId) || [];
    existingTasks.push(task);
    this.taskQueue.set(agentId, existingTasks);

    setTimeout(() => {
      this.simulateTaskExecution(agentId, task);
    }, 100);

    return task.id;
  }

  async getTaskResult(taskId: string): Promise<AgentTaskResult | undefined> {
    return this.taskResults.get(taskId);
  }

  async waitForTask(taskId: string, timeout: number = 30000): Promise<AgentTaskResult> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const result = this.taskResults.get(taskId);
      if (result) {
        return result;
      }
      await new Promise(r => setTimeout(r, 100));
    }

    throw new Error(`Task ${taskId} timed out`);
  }

  async addConnection(connection: AgentConnection): Promise<void> {
    const exists = this.connections.some(
      c => c.sourceId === connection.sourceId && c.targetId === connection.targetId
    );

    if (!exists) {
      this.connections.push(connection);
    }
  }

  async getTopology(): Promise<MeshTopology> {
    const agents = Array.from(this.agents.values());
    const pivotChains = this.calculatePivotChains();

    return {
      agents,
      connections: this.connections,
      pivotChains,
    };
  }

  async findPathToTarget(sourceId: string, targetIp: string): Promise<string[]> {
    const targetAgent = Array.from(this.agents.values()).find(
      a => a.ip === targetIp
    );

    if (targetAgent) {
      return this.findShortestPath(sourceId, targetAgent.id);
    }

    const reachableAgents = await this.getAgentsInNetwork(targetIp);
    if (reachableAgents.length > 0) {
      return this.findShortestPath(sourceId, reachableAgents[0].id);
    }

    return [];
  }

  private async getAgentsInNetwork(targetIp: string): Promise<AgentInfo[]> {
    const targetNetwork = targetIp.split(".").slice(0, 3).join(".");
    
    return Array.from(this.agents.values()).filter(agent => {
      const agentNetwork = agent.ip.split(".").slice(0, 3).join(".");
      return agentNetwork === targetNetwork;
    });
  }

  private findShortestPath(sourceId: string, targetId: string): string[] {
    if (sourceId === targetId) {
      return [sourceId];
    }

    const queue: string[][] = [[sourceId]];
    const visited = new Set<string>([sourceId]);

    while (queue.length > 0) {
      const path = queue.shift()!;
      const current = path[path.length - 1];

      const neighbors = this.connections
        .filter(c => c.sourceId === current || c.targetId === current)
        .map(c => c.sourceId === current ? c.targetId : c.sourceId);

      for (const neighbor of neighbors) {
        if (neighbor === targetId) {
          return [...path, neighbor];
        }

        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push([...path, neighbor]);
        }
      }
    }

    return [];
  }

  private calculatePivotChains(): string[][] {
    const chains: string[][] = [];
    const visited = new Set<string>();

    const agentValues = Array.from(this.agents.values());
    for (const agent of agentValues) {
      if (!visited.has(agent.id)) {
        const chain = this.buildChainFrom(agent.id, visited);
        if (chain.length > 1) {
          chains.push(chain);
        }
      }
    }

    return chains;
  }

  private buildChainFrom(startId: string, visited: Set<string>): string[] {
    const chain: string[] = [startId];
    visited.add(startId);

    let current = startId;
    let foundNext = true;

    while (foundNext) {
      foundNext = false;

      for (const conn of this.connections) {
        let nextId: string | null = null;

        if (conn.sourceId === current && !visited.has(conn.targetId)) {
          nextId = conn.targetId;
        } else if (conn.targetId === current && !visited.has(conn.sourceId)) {
          nextId = conn.sourceId;
        }

        if (nextId) {
          chain.push(nextId);
          visited.add(nextId);
          current = nextId;
          foundNext = true;
          break;
        }
      }
    }

    return chain;
  }

  private simulateTaskExecution(agentId: string, task: AgentTask): void {
    const executionTime = 50 + Math.random() * 200;

    setTimeout(() => {
      const success = Math.random() > 0.1;
      let output = "";

      switch (task.type) {
        case "exec":
          output = success
            ? `Command executed: ${task.command}\nOutput: simulated output`
            : "Command execution failed";
          break;

        case "scan":
          output = success
            ? `Scan completed. Found 5 open ports on ${task.target}`
            : "Scan failed: timeout";
          break;

        case "harvest":
          output = success
            ? "Credentials harvested: 3 password hashes, 1 Kerberos ticket"
            : "Credential harvest failed: access denied";
          break;

        case "upload":
          output = success ? "File uploaded successfully" : "Upload failed";
          break;

        case "download":
          output = success ? "File downloaded successfully" : "Download failed";
          break;

        case "persist":
          output = success
            ? "Persistence mechanism installed"
            : "Persistence installation failed";
          break;
      }

      const result: AgentTaskResult = {
        taskId: task.id,
        agentId,
        success,
        output,
        error: success ? undefined : "Operation failed",
        executionTimeMs: executionTime,
        capturedAt: new Date(),
      };

      this.taskResults.set(task.id, result);

      const tasks = this.taskQueue.get(agentId) || [];
      const index = tasks.findIndex(t => t.id === task.id);
      if (index !== -1) {
        tasks.splice(index, 1);
        this.taskQueue.set(agentId, tasks);
      }
    }, executionTime);
  }

  async heartbeatAgent(agentId: string): Promise<boolean> {
    const agent = this.agents.get(agentId);
    if (!agent) return false;

    agent.lastSeen = new Date();
    agent.status = "active";
    return true;
  }

  async removeAgent(agentId: string): Promise<boolean> {
    this.connections = this.connections.filter(
      c => c.sourceId !== agentId && c.targetId !== agentId
    );

    this.taskQueue.delete(agentId);

    return this.agents.delete(agentId);
  }

  async clearMesh(): Promise<void> {
    this.agents.clear();
    this.connections = [];
    this.taskQueue.clear();
    this.taskResults.clear();
  }
}
