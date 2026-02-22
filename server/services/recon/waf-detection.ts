import * as https from 'https'
import * as http from 'http'
import type { WafFingerprint, WafDetectionResult } from './types'

interface WafSignature {
  name: string
  headerIndicators: { header: string; pattern: RegExp }[]
  bodyIndicators: RegExp[]
  statusCodeIndicators: number[]
}

// WAF fingerprint database — matched against both normal and hostile responses
const WAF_SIGNATURES: WafSignature[] = [
  {
    name: 'Cloudflare',
    headerIndicators: [
      { header: 'server', pattern: /cloudflare/i },
      { header: 'cf-ray', pattern: /.+/ },
      { header: 'cf-cache-status', pattern: /.+/ },
    ],
    bodyIndicators: [/Attention Required|Cloudflare Ray ID/i],
    statusCodeIndicators: [403, 503]
  },
  {
    name: 'AWS WAF',
    headerIndicators: [
      { header: 'x-amzn-requestid', pattern: /.+/ },
      { header: 'x-amz-cf-id', pattern: /.+/ },
    ],
    bodyIndicators: [/AWS WAF|Request blocked/i],
    statusCodeIndicators: [403]
  },
  {
    name: 'Akamai',
    headerIndicators: [
      { header: 'server', pattern: /AkamaiGHost/i },
      { header: 'x-akamai-transformed', pattern: /.+/ },
    ],
    bodyIndicators: [/Access Denied.*Akamai|Reference\s#\d+\.\w+/i],
    statusCodeIndicators: [403]
  },
  {
    name: 'Imperva / Incapsula',
    headerIndicators: [
      { header: 'x-cdn', pattern: /Incapsula/i },
      { header: 'x-iinfo', pattern: /.+/ },
    ],
    bodyIndicators: [/Incapsula incident|_Incapsula_Resource/i],
    statusCodeIndicators: [403]
  },
  {
    name: 'Sucuri',
    headerIndicators: [
      { header: 'server', pattern: /Sucuri/i },
      { header: 'x-sucuri-id', pattern: /.+/ },
    ],
    bodyIndicators: [/Sucuri WebSite Firewall|Access Denied - Sucuri/i],
    statusCodeIndicators: [403]
  },
  {
    name: 'F5 BIG-IP ASM',
    headerIndicators: [
      { header: 'server', pattern: /BIG-IP|BigIP/i },
    ],
    bodyIndicators: [/The requested URL was rejected/i],
    statusCodeIndicators: [403]
  },
  {
    name: 'ModSecurity',
    headerIndicators: [
      { header: 'server', pattern: /Mod_Security|NOYB/i },
    ],
    bodyIndicators: [/ModSecurity|Not Acceptable|406 Not Acceptable/i],
    statusCodeIndicators: [403, 406]
  },
  {
    name: 'Fastly',
    headerIndicators: [
      { header: 'server', pattern: /Varnish/i },
      { header: 'x-served-by', pattern: /cache-/i },
      { header: 'via', pattern: /varnish/i },
    ],
    bodyIndicators: [/Fastly error/i],
    statusCodeIndicators: [403, 503]
  },
  {
    name: 'Azure Front Door',
    headerIndicators: [
      { header: 'x-azure-ref', pattern: /.+/ },
    ],
    bodyIndicators: [/Azure Front Door|Our services aren't available right now/i],
    statusCodeIndicators: [403]
  },
  {
    name: 'Barracuda',
    headerIndicators: [
      { header: 'server', pattern: /Barracuda/i },
    ],
    bodyIndicators: [/Barracuda Web Application Firewall/i],
    statusCodeIndicators: [403]
  },
]

// Fetch a URL with optional attack payload to trigger WAF responses
async function probe(
  url: string,
  options: { path?: string; headers?: Record<string, string> } = {}
): Promise<{ statusCode: number; headers: Record<string, string>; body: string } | null> {
  const fullUrl = options.path ? `${url}${options.path}` : url
  return new Promise((resolve) => {
    const client = fullUrl.startsWith('https') ? https : http
    const req = client.get(fullUrl, {
      timeout: 8000,
      rejectUnauthorized: false,
      headers: options.headers ?? {}
    }, (res) => {
      const headers: Record<string, string> = {}
      for (const [key, value] of Object.entries(res.headers)) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value ?? '')
      }
      let body = ''
      res.on('data', (chunk) => { body += chunk.toString().substring(0, 20000) })
      res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, headers, body }))
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

export async function analyzeWaf(url: string): Promise<WafDetectionResult> {
  // Step 1: Normal request to get baseline headers
  const normalResponse = await probe(url)
  if (!normalResponse) {
    return { url, detected: false, waf: null, bypassHints: [] }
  }

  // Step 2: Hostile request designed to trigger WAF block pages
  const hostileResponse = await probe(url, {
    path: `/?id=1' OR 1=1--`,
    headers: { 'User-Agent': 'sqlmap/1.0' }
  })

  // Step 3: XSS probe
  const xssResponse = await probe(url, {
    path: `/?q=<script>alert(1)</script>`
  })

  // Combine all responses for fingerprinting
  const responses = [normalResponse, hostileResponse, xssResponse].filter(Boolean) as {
    statusCode: number
    headers: Record<string, string>
    body: string
  }[]

  let bestMatch: WafFingerprint | null = null
  let bestConfidence = 0

  for (const sig of WAF_SIGNATURES) {
    const indicators: string[] = []
    let confidence = 0

    for (const response of responses) {
      // Check headers
      for (const hi of sig.headerIndicators) {
        const val = response.headers[hi.header]
        if (val && hi.pattern.test(val)) {
          indicators.push(`Header ${hi.header}: ${val}`)
          confidence += 25
        }
      }

      // Check body
      for (const bi of sig.bodyIndicators) {
        if (bi.test(response.body)) {
          indicators.push(`Body pattern: ${bi.source.substring(0, 40)}`)
          confidence += 30
        }
      }

      // Check hostile response status codes
      if (response !== normalResponse && sig.statusCodeIndicators.includes(response.statusCode)) {
        indicators.push(`Block status: ${response.statusCode}`)
        confidence += 15
      }
    }

    if (confidence > bestConfidence && indicators.length > 0) {
      bestConfidence = confidence
      bestMatch = {
        name: sig.name,
        confidence: Math.min(confidence, 100),
        indicators
      }
    }
  }

  // Generate bypass hints based on the detected WAF
  const bypassHints: string[] = []
  if (bestMatch) {
    bypassHints.push('Try URL encoding payloads (%27 instead of single quote)')
    bypassHints.push('Test with different HTTP methods (PUT, PATCH, DELETE)')
    bypassHints.push('Try case variation in payloads (SeLeCt instead of SELECT)')
    bypassHints.push('Use HTTP/2 or HTTP/3 if supported')

    if (bestMatch.name === 'Cloudflare') {
      bypassHints.push('Look for origin IP via historical DNS records or Shodan')
      bypassHints.push('Check for subdomains that bypass Cloudflare proxy')
    }
    if (bestMatch.name === 'ModSecurity') {
      bypassHints.push('Test for paranoia level — low levels miss obfuscated payloads')
    }
  }

  return {
    url,
    detected: bestMatch !== null,
    waf: bestMatch,
    bypassHints
  }
}
