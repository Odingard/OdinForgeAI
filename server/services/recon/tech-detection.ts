import * as https from 'https'
import * as http from 'http'
import type { DetectedTechnology, TechDetectionResult } from './types'

// Fingerprint signatures — regex patterns to match against response headers and body
interface TechSignature {
  name: string
  category: DetectedTechnology['category']
  headerPatterns?: { header: string; pattern: RegExp; versionGroup?: number }[]
  bodyPatterns?: { pattern: RegExp; versionGroup?: number }[]
  cookiePatterns?: { pattern: RegExp }[]
}

const SIGNATURES: TechSignature[] = [
  // ── Servers ────────────────────────────────────────────────────────────────
  { name: 'Nginx',       category: 'server',    headerPatterns: [{ header: 'server', pattern: /nginx\/?(\S+)?/i, versionGroup: 1 }] },
  { name: 'Apache',      category: 'server',    headerPatterns: [{ header: 'server', pattern: /Apache\/?(\S+)?/i, versionGroup: 1 }] },
  { name: 'IIS',         category: 'server',    headerPatterns: [{ header: 'server', pattern: /Microsoft-IIS\/?(\S+)?/i, versionGroup: 1 }] },
  { name: 'Cloudflare',  category: 'cdn',       headerPatterns: [{ header: 'server', pattern: /cloudflare/i }, { header: 'cf-ray', pattern: /.+/ }] },
  { name: 'AWS ALB',     category: 'cdn',       headerPatterns: [{ header: 'server', pattern: /awselb/i }] },
  { name: 'Vercel',      category: 'cdn',       headerPatterns: [{ header: 'server', pattern: /Vercel/i }, { header: 'x-vercel-id', pattern: /.+/ }] },
  { name: 'Netlify',     category: 'cdn',       headerPatterns: [{ header: 'server', pattern: /Netlify/i }] },

  // ── Frameworks ─────────────────────────────────────────────────────────────
  { name: 'Express',     category: 'framework', headerPatterns: [{ header: 'x-powered-by', pattern: /Express/i }] },
  { name: 'Django',      category: 'framework', headerPatterns: [{ header: 'x-frame-options', pattern: /.+/ }], cookiePatterns: [{ pattern: /csrftoken/ }] },
  { name: 'Rails',       category: 'framework', headerPatterns: [{ header: 'x-powered-by', pattern: /Phusion Passenger/i }], cookiePatterns: [{ pattern: /_session_id/ }] },
  { name: 'Laravel',     category: 'framework', cookiePatterns: [{ pattern: /laravel_session/ }], headerPatterns: [{ header: 'x-powered-by', pattern: /Laravel/i }] },
  { name: 'ASP.NET',     category: 'framework', headerPatterns: [{ header: 'x-aspnet-version', pattern: /(\S+)/i, versionGroup: 1 }, { header: 'x-powered-by', pattern: /ASP\.NET/i }] },
  { name: 'Spring',      category: 'framework', headerPatterns: [{ header: 'x-application-context', pattern: /.+/ }] },
  { name: 'FastAPI',     category: 'framework', bodyPatterns: [{ pattern: /FastAPI/i }] },
  { name: 'Next.js',     category: 'framework', headerPatterns: [{ header: 'x-nextjs-cache', pattern: /.+/ }], bodyPatterns: [{ pattern: /_next\/static/i }] },
  { name: 'Nuxt.js',     category: 'framework', bodyPatterns: [{ pattern: /__nuxt/i }] },

  // ── CMS ────────────────────────────────────────────────────────────────────
  { name: 'WordPress',   category: 'cms',       bodyPatterns: [{ pattern: /wp-content|wp-includes/i }], headerPatterns: [{ header: 'link', pattern: /wp-json/i }] },
  { name: 'Drupal',      category: 'cms',       headerPatterns: [{ header: 'x-generator', pattern: /Drupal\s*(\S+)?/i, versionGroup: 1 }], bodyPatterns: [{ pattern: /Drupal\.settings/i }] },
  { name: 'Joomla',      category: 'cms',       bodyPatterns: [{ pattern: /\/media\/jui\//i }], headerPatterns: [{ header: 'x-content-encoded-by', pattern: /Joomla/i }] },
  { name: 'Ghost',       category: 'cms',       bodyPatterns: [{ pattern: /ghost-(?:url|api)/i }] },

  // ── Languages ──────────────────────────────────────────────────────────────
  { name: 'PHP',         category: 'language',  headerPatterns: [{ header: 'x-powered-by', pattern: /PHP\/?(\S+)?/i, versionGroup: 1 }] },
  { name: 'Java',        category: 'language',  headerPatterns: [{ header: 'x-powered-by', pattern: /Servlet|JSP/i }] },

  // ── Analytics ──────────────────────────────────────────────────────────────
  { name: 'Google Analytics', category: 'analytics', bodyPatterns: [{ pattern: /google-analytics\.com|gtag\//i }] },
  { name: 'Segment',     category: 'analytics', bodyPatterns: [{ pattern: /cdn\.segment\.com|analytics\.js/i }] },
  { name: 'Hotjar',      category: 'analytics', bodyPatterns: [{ pattern: /static\.hotjar\.com/i }] },

  // ── Other ──────────────────────────────────────────────────────────────────
  { name: 'GraphQL',     category: 'other',     bodyPatterns: [{ pattern: /graphql|__schema/i }] },
  { name: 'Swagger UI',  category: 'other',     bodyPatterns: [{ pattern: /swagger-ui|SwaggerUIBundle/i }] },
  { name: 'React',       category: 'framework', bodyPatterns: [{ pattern: /__NEXT_DATA__|react-root|data-reactroot|_reactRootContainer/i }] },
  { name: 'Vue.js',      category: 'framework', bodyPatterns: [{ pattern: /vue\.(?:min\.)?js|data-v-[a-f0-9]/i }] },
  { name: 'Angular',     category: 'framework', bodyPatterns: [{ pattern: /ng-version=|angular\.(?:min\.)?js/i }] },
]

// Fetch the page headers + body for fingerprinting
async function fetchPage(url: string): Promise<{ headers: Record<string, string>; body: string; cookies: string } | null> {
  return new Promise((resolve) => {
    const client = url.startsWith('https') ? https : http
    const req = client.get(url, { timeout: 8000, rejectUnauthorized: false }, (res) => {
      const headers: Record<string, string> = {}
      for (const [key, value] of Object.entries(res.headers)) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value ?? '')
      }
      const cookies = (res.headers['set-cookie'] ?? []).join('; ')
      let body = ''
      res.on('data', (chunk) => { body += chunk.toString().substring(0, 50000) })
      res.on('end', () => resolve({ headers, body, cookies }))
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

export async function analyzeTech(url: string): Promise<TechDetectionResult> {
  const page = await fetchPage(url)
  const technologies: DetectedTechnology[] = []

  if (!page) {
    return { url, technologies: [], serverHeader: null, poweredBy: null }
  }

  for (const sig of SIGNATURES) {
    let matched = false
    let version: string | null = null
    let confidence = 0
    let via = ''

    // Check headers
    if (sig.headerPatterns) {
      for (const hp of sig.headerPatterns) {
        const headerVal = page.headers[hp.header]
        if (headerVal) {
          const match = headerVal.match(hp.pattern)
          if (match) {
            matched = true
            confidence += 40
            via = `header:${hp.header}`
            if (hp.versionGroup && match[hp.versionGroup]) {
              version = match[hp.versionGroup]
              confidence += 20
            }
          }
        }
      }
    }

    // Check body
    if (sig.bodyPatterns) {
      for (const bp of sig.bodyPatterns) {
        const match = page.body.match(bp.pattern)
        if (match) {
          matched = true
          confidence += 30
          via = via ? `${via},body` : 'body'
          if (bp.versionGroup && match[bp.versionGroup]) {
            version = match[bp.versionGroup]
            confidence += 20
          }
        }
      }
    }

    // Check cookies
    if (sig.cookiePatterns) {
      for (const cp of sig.cookiePatterns) {
        if (cp.pattern.test(page.cookies)) {
          matched = true
          confidence += 30
          via = via ? `${via},cookie` : 'cookie'
        }
      }
    }

    if (matched) {
      technologies.push({
        name: sig.name,
        category: sig.category,
        version,
        confidence: Math.min(confidence, 100),
        detectedVia: via
      })
    }
  }

  return {
    url,
    technologies: technologies.sort((a, b) => b.confidence - a.confidence),
    serverHeader: page.headers['server'] ?? null,
    poweredBy: page.headers['x-powered-by'] ?? null
  }
}
