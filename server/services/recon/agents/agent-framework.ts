// ═══════════════════════════════════════════════════════════════════════════════
//  OdinForge Agent Framework
//
//  Every recon finding gets routed to a specialized agent that:
//  1. Receives the finding
//  2. Plans its attack/verification steps
//  3. Executes each step
//  4. Produces a structured result with evidence
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Agent Task Lifecycle ────────────────────────────────────────────────────

export type AgentStatus = 'queued' | 'running' | 'success' | 'failed' | 'skipped'

export interface AgentStep {
  name: string
  description: string
  status: AgentStatus
  startedAt: string | null
  completedAt: string | null
  duration: number
  output: string | null
  error: string | null
}

export interface AgentTask {
  id: string
  agentName: string
  findingType: string
  target: string
  status: AgentStatus
  priority: 'critical' | 'high' | 'medium' | 'low'
  steps: AgentStep[]
  startedAt: string
  completedAt: string | null
  duration: number
  result: AgentResult | null
}

export interface AgentResult {
  verified: boolean
  exploitable: boolean
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  evidence: Evidence[]
  recommendations: string[]
  rawOutput: string
  cweId: string | null
  cvssScore: number | null
}

export interface Evidence {
  type: 'request' | 'response' | 'screenshot' | 'log' | 'diff' | 'payload' | 'proof'
  label: string
  content: string
}

// ─── Agent Event System ──────────────────────────────────────────────────────

export type AgentEventType = 'task:start' | 'task:complete' | 'step:start' | 'step:complete' | 'step:error' | 'agent:log'

export interface AgentEvent {
  type: AgentEventType
  agentName: string
  taskId: string
  timestamp: string
  data: Record<string, any>
}

export type AgentEventHandler = (event: AgentEvent) => void

// ─── Base Agent ──────────────────────────────────────────────────────────────

export abstract class BaseAgent {
  abstract name: string
  abstract description: string
  abstract handles: string[]  // Finding types this agent processes

  private eventHandlers: AgentEventHandler[] = []

  onEvent(handler: AgentEventHandler): void {
    this.eventHandlers.push(handler)
  }

  protected emit(event: AgentEvent): void {
    for (const handler of this.eventHandlers) {
      try { handler(event) } catch { /* don't let handler errors kill the agent */ }
    }
  }

  protected log(taskId: string, message: string): void {
    this.emit({
      type: 'agent:log',
      agentName: this.name,
      taskId,
      timestamp: new Date().toISOString(),
      data: { message }
    })
  }

  // The subclass defines its concrete step list
  abstract plan(finding: any): { name: string; description: string }[]

  // The subclass executes a single step and returns output
  abstract executeStep(stepName: string, finding: any, previousSteps: AgentStep[]): Promise<string>

  // Build the final result from all completed steps
  abstract analyze(finding: any, steps: AgentStep[]): AgentResult

  // Run the full agent pipeline
  async run(finding: any, taskId: string): Promise<AgentTask> {
    const task: AgentTask = {
      id: taskId,
      agentName: this.name,
      findingType: finding._findingType ?? 'unknown',
      target: finding._target ?? 'unknown',
      status: 'running',
      priority: finding._priority ?? 'medium',
      steps: [],
      startedAt: new Date().toISOString(),
      completedAt: null,
      duration: 0,
      result: null
    }

    this.emit({
      type: 'task:start',
      agentName: this.name,
      taskId,
      timestamp: task.startedAt,
      data: { finding }
    })

    const planned = this.plan(finding)

    for (const planned_step of planned) {
      const step: AgentStep = {
        name: planned_step.name,
        description: planned_step.description,
        status: 'running',
        startedAt: new Date().toISOString(),
        completedAt: null,
        duration: 0,
        output: null,
        error: null
      }

      this.emit({
        type: 'step:start',
        agentName: this.name,
        taskId,
        timestamp: step.startedAt!,
        data: { stepName: step.name }
      })

      try {
        const output = await this.executeStep(step.name, finding, task.steps)
        step.output = output
        step.status = 'success'
      } catch (err: any) {
        step.error = err.message ?? String(err)
        step.status = 'failed'
        this.emit({
          type: 'step:error',
          agentName: this.name,
          taskId,
          timestamp: new Date().toISOString(),
          data: { stepName: step.name, error: step.error }
        })
      }

      step.completedAt = new Date().toISOString()
      step.duration = new Date(step.completedAt).getTime() - new Date(step.startedAt ?? step.completedAt).getTime()
      task.steps.push(step)

      this.emit({
        type: 'step:complete',
        agentName: this.name,
        taskId,
        timestamp: step.completedAt,
        data: { stepName: step.name, status: step.status }
      })

      // If a critical step fails, abort the pipeline
      if (step.status === 'failed' && step.name.startsWith('verify')) break
    }

    // Analyze all step results into the final verdict
    task.result = this.analyze(finding, task.steps)
    task.status = task.steps.some(s => s.status === 'failed') ? 'failed' : 'success'
    task.completedAt = new Date().toISOString()
    task.duration = new Date(task.completedAt).getTime() - new Date(task.startedAt).getTime()

    this.emit({
      type: 'task:complete',
      agentName: this.name,
      taskId,
      timestamp: task.completedAt,
      data: { status: task.status, result: task.result }
    })

    return task
  }
}

// ─── Agent Registry ──────────────────────────────────────────────────────────

export class AgentRegistry {
  private agents: Map<string, BaseAgent> = new Map()
  private findingTypeMap: Map<string, BaseAgent[]> = new Map()

  register(agent: BaseAgent): void {
    this.agents.set(agent.name, agent)
    for (const findingType of agent.handles) {
      const existing = this.findingTypeMap.get(findingType) ?? []
      existing.push(agent)
      this.findingTypeMap.set(findingType, existing)
    }
  }

  getAgentsForFinding(findingType: string): BaseAgent[] {
    return this.findingTypeMap.get(findingType) ?? []
  }

  getAgent(name: string): BaseAgent | undefined {
    return this.agents.get(name)
  }

  listAgents(): { name: string; description: string; handles: string[] }[] {
    return Array.from(this.agents.values()).map(a => ({
      name: a.name,
      description: a.description,
      handles: a.handles
    }))
  }
}
