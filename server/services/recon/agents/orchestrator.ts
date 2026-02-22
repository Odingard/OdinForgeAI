// ═══════════════════════════════════════════════════════════════════════════════
//  Agent Orchestrator
//
//  The brain of the operation:
//  1. Takes raw recon results
//  2. Extracts every individual finding
//  3. Routes each finding to the correct specialized agent
//  4. Runs all agents (with concurrency control)
//  5. Aggregates results into a final attack report
// ═══════════════════════════════════════════════════════════════════════════════

import {
  AgentRegistry, AgentTask, AgentEvent, AgentEventHandler, BaseAgent
} from './agent-framework'
import { DnsAgent } from './dns-agent'
import { SslTlsAgent } from './ssl-tls-agent'
import { PortServiceAgent } from './port-service-agent'
import { CorsAgent } from './cors-agent'
import { HeaderSecurityAgent } from './header-security-agent'
import { ApiEndpointAgent } from './api-endpoint-agent'
import { extractAllFindings, RoutedFinding } from './finding-router'
import type { FullReconResult } from '../index'

// ─── Agent Run Report ────────────────────────────────────────────────────────

export interface AgentRunReport {
  target: string
  startedAt: string
  completedAt: string
  duration: number
  totalFindings: number
  totalTasks: number
  tasks: AgentTask[]
  summary: {
    verified: number
    exploitable: number
    criticalFindings: number
    highFindings: number
    mediumFindings: number
    lowFindings: number
  }
  topExploitable: {
    finding: string
    agent: string
    severity: string
    target: string
    cwe: string | null
    cvss: number | null
  }[]
}

// ─── Orchestrator ────────────────────────────────────────────────────────────

export class AgentOrchestrator {
  private registry: AgentRegistry
  private eventHandlers: AgentEventHandler[] = []
  private taskCounter = 0

  constructor() {
    this.registry = new AgentRegistry()
    this.registerAllAgents()
  }

  private registerAllAgents(): void {
    const agents: BaseAgent[] = [
      new DnsAgent(),
      new SslTlsAgent(),
      new PortServiceAgent(),
      new CorsAgent(),
      new HeaderSecurityAgent(),
      new ApiEndpointAgent(),
    ]

    for (const agent of agents) {
      agent.onEvent((event) => {
        for (const handler of this.eventHandlers) {
          handler(event)
        }
      })
      this.registry.register(agent)
    }
  }

  onEvent(handler: AgentEventHandler): void {
    this.eventHandlers.push(handler)
  }

  listAgents(): { name: string; description: string; handles: string[] }[] {
    return this.registry.listAgents()
  }

  private nextTaskId(): string {
    return `task-${++this.taskCounter}-${Date.now().toString(36)}`
  }

  async runFinding(finding: RoutedFinding): Promise<AgentTask[]> {
    const agents = this.registry.getAgentsForFinding(finding._findingType)

    if (agents.length === 0) {
      console.log(`[ORCHESTRATOR] No agent registered for finding type: ${finding._findingType}`)
      return []
    }

    const tasks: AgentTask[] = []
    for (const agent of agents) {
      const taskId = this.nextTaskId()
      console.log(`[ORCHESTRATOR] Dispatching ${finding._findingType} → ${agent.name} (${taskId})`)
      const task = await agent.run(finding, taskId)
      tasks.push(task)
    }
    return tasks
  }

  async runFromRecon(
    recon: FullReconResult,
    options: {
      concurrency?: number
      maxFindings?: number
      priorityFilter?: ('critical' | 'high' | 'medium' | 'low')[]
    } = {}
  ): Promise<AgentRunReport> {
    const {
      concurrency = 3,
      maxFindings = 200,
      priorityFilter
    } = options

    const startedAt = new Date().toISOString()
    const startTime = Date.now()

    let findings = extractAllFindings(recon)
    console.log(`[ORCHESTRATOR] Extracted ${findings.length} findings from recon results`)

    if (priorityFilter) {
      findings = findings.filter(f => priorityFilter.includes(f._priority))
      console.log(`[ORCHESTRATOR] Filtered to ${findings.length} findings (priorities: ${priorityFilter.join(', ')})`)
    }

    findings = findings.slice(0, maxFindings)

    const allTasks: AgentTask[] = []
    for (let i = 0; i < findings.length; i += concurrency) {
      const batch = findings.slice(i, i + concurrency)
      console.log(`[ORCHESTRATOR] Processing batch ${Math.floor(i / concurrency) + 1}/${Math.ceil(findings.length / concurrency)}`)

      const batchResults = await Promise.all(
        batch.map(finding => this.runFinding(finding))
      )
      for (const tasks of batchResults) {
        allTasks.push(...tasks)
      }
    }

    let verified = 0, exploitable = 0
    let critical = 0, high = 0, medium = 0, low = 0
    const topExploitable: AgentRunReport['topExploitable'] = []

    for (const task of allTasks) {
      if (!task.result) continue
      if (task.result.verified) verified++
      if (task.result.exploitable) exploitable++

      switch (task.result.severity) {
        case 'critical': critical++; break
        case 'high': high++; break
        case 'medium': medium++; break
        case 'low': low++; break
      }

      if (task.result.exploitable) {
        topExploitable.push({
          finding: task.findingType,
          agent: task.agentName,
          severity: task.result.severity,
          target: task.target,
          cwe: task.result.cweId,
          cvss: task.result.cvssScore,
        })
      }
    }

    topExploitable.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))

    const completedAt = new Date().toISOString()

    return {
      target: recon.target.host,
      startedAt,
      completedAt,
      duration: Date.now() - startTime,
      totalFindings: findings.length,
      totalTasks: allTasks.length,
      tasks: allTasks,
      summary: {
        verified,
        exploitable,
        criticalFindings: critical,
        highFindings: high,
        mediumFindings: medium,
        lowFindings: low,
      },
      topExploitable: topExploitable.slice(0, 25),
    }
  }

  async runFindings(
    findings: RoutedFinding[],
    options: { concurrency?: number } = {}
  ): Promise<AgentTask[]> {
    const { concurrency = 3 } = options
    const allTasks: AgentTask[] = []

    for (let i = 0; i < findings.length; i += concurrency) {
      const batch = findings.slice(i, i + concurrency)
      const batchResults = await Promise.all(
        batch.map(finding => this.runFinding(finding))
      )
      for (const tasks of batchResults) {
        allTasks.push(...tasks)
      }
    }

    return allTasks
  }
}

// ─── Convenience: Full Pipeline (Recon → Extract → Agent → Report) ───────────

import { runFullRecon } from '../index'
import type { ReconTarget } from '../types'

export async function runFullPipeline(
  target: ReconTarget,
  options: {
    reconOptions?: Parameters<typeof runFullRecon>[1]
    agentOptions?: Parameters<AgentOrchestrator['runFromRecon']>[1]
    onEvent?: AgentEventHandler
  } = {}
): Promise<{ recon: FullReconResult; agentReport: AgentRunReport }> {
  console.log(`\n${'═'.repeat(60)}`)
  console.log(`  OdinForge Full Pipeline: ${target.host}`)
  console.log(`${'═'.repeat(60)}\n`)

  console.log('[PIPELINE] Phase 1: Reconnaissance...')
  const recon = await runFullRecon(target, options.reconOptions)
  console.log(`[PIPELINE] Recon complete: ${recon.summary.totalEndpoints} endpoints, ${recon.summary.totalIssues} issues\n`)

  console.log('[PIPELINE] Phase 2: Agent exploitation & verification...')
  const orchestrator = new AgentOrchestrator()
  if (options.onEvent) orchestrator.onEvent(options.onEvent)

  const agentReport = await orchestrator.runFromRecon(recon, options.agentOptions)

  console.log(`\n${'═'.repeat(60)}`)
  console.log(`  Pipeline Complete: ${target.host}`)
  console.log(`  Recon Duration: ${(recon.duration / 1000).toFixed(1)}s`)
  console.log(`  Agent Duration: ${(agentReport.duration / 1000).toFixed(1)}s`)
  console.log(`  Findings: ${agentReport.totalFindings} extracted, ${agentReport.summary.verified} verified, ${agentReport.summary.exploitable} exploitable`)
  console.log(`  Severity: ${agentReport.summary.criticalFindings} critical, ${agentReport.summary.highFindings} high, ${agentReport.summary.mediumFindings} medium`)
  console.log(`${'═'.repeat(60)}\n`)

  return { recon, agentReport }
}
