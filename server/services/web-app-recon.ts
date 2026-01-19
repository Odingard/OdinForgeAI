import OpenAI from "openai";

const OPENAI_TIMEOUT_MS = 90000; // 90 second timeout to prevent hanging

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

export interface DiscoveredEndpoint {
  url: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  path: string;
  type: "api" | "form" | "page" | "static" | "websocket" | "graphql";
  parameters: EndpointParameter[];
  authentication: "none" | "cookie" | "bearer" | "basic" | "api_key" | "unknown";
  description?: string;
  riskIndicators: string[];
  priority: "high" | "medium" | "low";
}

export interface EndpointParameter {
  name: string;
  location: "query" | "body" | "path" | "header" | "cookie";
  type: "string" | "number" | "boolean" | "file" | "json" | "unknown";
  required: boolean;
  sampleValue?: string;
  vulnerabilityPotential: ("sqli" | "xss" | "command_injection" | "path_traversal" | "ssrf" | "auth_bypass")[];
}

export interface DiscoveredForm {
  url: string;
  action: string;
  method: string;
  fields: {
    name: string;
    type: string;
    required: boolean;
  }[];
  hasFileUpload: boolean;
  hasCsrfToken: boolean;
}

export interface WebAppReconResult {
  targetUrl: string;
  scanStarted: Date;
  scanCompleted: Date;
  durationMs: number;
  
  applicationInfo: {
    title?: string;
    technologies: string[];
    frameworks: string[];
    server?: string;
    securityHeaders: Record<string, string>;
    missingSecurityHeaders: string[];
  };
  
  endpoints: DiscoveredEndpoint[];
  forms: DiscoveredForm[];
  
  attackSurface: {
    totalEndpoints: number;
    highPriorityEndpoints: number;
    inputParameters: number;
    apiEndpoints: number;
    authenticationPoints: number;
    fileUploadPoints: number;
  };
  
  securityObservations: string[];
  recommendedTestOrder: string[];
}

export type ReconProgressCallback = (
  phase: string,
  progress: number,
  message: string
) => void;

async function fetchWithTimeout(url: string, timeout: number = 10000): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "OdinForge-Security-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function discoverFromRobotsTxt(baseUrl: string): Promise<string[]> {
  const paths: string[] = [];
  try {
    const robotsUrl = new URL("/robots.txt", baseUrl).toString();
    const response = await fetchWithTimeout(robotsUrl, 5000);
    if (response.ok) {
      const text = await response.text();
      const lines = text.split("\n");
      for (const line of lines) {
        const match = line.match(/^(Disallow|Allow):\s*(.+)/i);
        if (match) {
          const path = match[2].trim();
          if (path && path !== "/" && !path.includes("*")) {
            paths.push(path);
          }
        }
      }
    }
  } catch (error) {
    // Robots.txt not available
  }
  return paths;
}

async function discoverFromSitemap(baseUrl: string): Promise<string[]> {
  const paths: string[] = [];
  try {
    const sitemapUrl = new URL("/sitemap.xml", baseUrl).toString();
    const response = await fetchWithTimeout(sitemapUrl, 5000);
    if (response.ok) {
      const text = await response.text();
      const locMatches = Array.from(text.matchAll(/<loc>([^<]+)<\/loc>/g));
      for (const match of locMatches) {
        try {
          const url = new URL(match[1]);
          paths.push(url.pathname);
        } catch {
          // Invalid URL
        }
      }
    }
  } catch (error) {
    // Sitemap not available
  }
  return paths.slice(0, 50); // Limit to prevent overwhelming
}

async function analyzeSecurityHeaders(response: Response): Promise<{
  present: Record<string, string>;
  missing: string[];
}> {
  const securityHeaders = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
  ];
  
  const present: Record<string, string> = {};
  const missing: string[] = [];
  
  for (const header of securityHeaders) {
    const value = response.headers.get(header);
    if (value) {
      present[header] = value;
    } else {
      missing.push(header);
    }
  }
  
  return { present, missing };
}

async function detectTechnologies(html: string, headers: Headers): Promise<{
  technologies: string[];
  frameworks: string[];
}> {
  const technologies: Set<string> = new Set();
  const frameworks: Set<string> = new Set();
  
  // Server header
  const server = headers.get("server");
  if (server) {
    technologies.add(server.split("/")[0]);
  }
  
  // Powered by
  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    technologies.add(poweredBy);
  }
  
  // HTML analysis
  if (html.includes("__NEXT_DATA__") || html.includes("_next/")) {
    frameworks.add("Next.js");
  }
  if (html.includes("ng-app") || html.includes("ng-controller")) {
    frameworks.add("Angular");
  }
  if (html.includes("data-reactroot") || html.includes("__REACT_DEVTOOLS")) {
    frameworks.add("React");
  }
  if (html.includes("Vue") || html.includes("v-if") || html.includes("v-for")) {
    frameworks.add("Vue.js");
  }
  if (html.includes("wp-content") || html.includes("wp-includes")) {
    frameworks.add("WordPress");
  }
  if (html.includes("Drupal") || html.includes("drupal.js")) {
    frameworks.add("Drupal");
  }
  if (html.includes("jquery") || html.includes("jQuery")) {
    technologies.add("jQuery");
  }
  if (html.includes("bootstrap")) {
    technologies.add("Bootstrap");
  }
  
  return {
    technologies: Array.from(technologies),
    frameworks: Array.from(frameworks),
  };
}

function extractLinksFromHtml(html: string, baseUrl: string): string[] {
  const paths: Set<string> = new Set();
  
  // Extract href links
  const hrefMatches = Array.from(html.matchAll(/href=["']([^"']+)["']/g));
  for (const match of hrefMatches) {
    try {
      const url = new URL(match[1], baseUrl);
      if (url.origin === new URL(baseUrl).origin) {
        paths.add(url.pathname + url.search);
      }
    } catch {
      // Invalid URL
    }
  }
  
  // Extract form actions
  const actionMatches = Array.from(html.matchAll(/action=["']([^"']+)["']/g));
  for (const match of actionMatches) {
    try {
      const url = new URL(match[1], baseUrl);
      if (url.origin === new URL(baseUrl).origin) {
        paths.add(url.pathname);
      }
    } catch {
      // Invalid URL
    }
  }
  
  // Extract API endpoints from JavaScript
  const apiMatches = Array.from(html.matchAll(/["'](\/api\/[^"']+)["']/g));
  for (const match of apiMatches) {
    paths.add(match[1].split("?")[0]);
  }
  
  // Extract fetch/axios calls
  const fetchMatches = Array.from(html.matchAll(/(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["']([^"']+)["']/g));
  for (const match of fetchMatches) {
    try {
      const url = new URL(match[1], baseUrl);
      if (url.origin === new URL(baseUrl).origin) {
        paths.add(url.pathname);
      }
    } catch {
      if (match[1].startsWith("/")) {
        paths.add(match[1].split("?")[0]);
      }
    }
  }
  
  return Array.from(paths).slice(0, 100);
}

function extractFormsFromHtml(html: string, baseUrl: string): DiscoveredForm[] {
  const forms: DiscoveredForm[] = [];
  
  const formMatches = Array.from(html.matchAll(/<form[^>]*>[\s\S]*?<\/form>/gi));
  for (const formMatch of formMatches) {
    const formHtml = formMatch[0];
    
    // Extract action
    const actionMatch = formHtml.match(/action=["']([^"']*)["']/i);
    let action = actionMatch ? actionMatch[1] : "";
    try {
      action = new URL(action, baseUrl).pathname;
    } catch {
      action = action || "/";
    }
    
    // Extract method
    const methodMatch = formHtml.match(/method=["']([^"']*)["']/i);
    const method = methodMatch ? methodMatch[1].toUpperCase() : "GET";
    
    // Extract fields
    const fields: DiscoveredForm["fields"] = [];
    const inputMatches = Array.from(formHtml.matchAll(/<input[^>]*>/gi));
    for (const inputMatch of inputMatches) {
      const input = inputMatch[0];
      const nameMatch = input.match(/name=["']([^"']*)["']/i);
      const typeMatch = input.match(/type=["']([^"']*)["']/i);
      const required = input.includes("required");
      
      if (nameMatch) {
        fields.push({
          name: nameMatch[1],
          type: typeMatch ? typeMatch[1] : "text",
          required,
        });
      }
    }
    
    // Check for file upload and CSRF
    const hasFileUpload = formHtml.includes('type="file"') || formHtml.includes("type='file'");
    const hasCsrfToken = formHtml.includes("csrf") || formHtml.includes("_token") || formHtml.includes("authenticity_token");
    
    if (fields.length > 0) {
      forms.push({
        url: baseUrl,
        action,
        method,
        fields,
        hasFileUpload,
        hasCsrfToken,
      });
    }
  }
  
  return forms;
}

function determineVulnerabilityPotential(param: EndpointParameter): EndpointParameter["vulnerabilityPotential"] {
  const potential: EndpointParameter["vulnerabilityPotential"] = [];
  const name = param.name.toLowerCase();
  
  // SQL Injection indicators
  if (["id", "user_id", "userid", "uid", "category", "product", "item", "order", "search", "q", "query", "filter", "sort", "page"].some(k => name.includes(k))) {
    potential.push("sqli");
  }
  
  // XSS indicators
  if (["name", "title", "description", "content", "message", "comment", "body", "text", "value", "search", "q", "query"].some(k => name.includes(k))) {
    potential.push("xss");
  }
  
  // Command Injection indicators
  if (["cmd", "command", "exec", "execute", "run", "shell", "ping", "host", "ip", "domain"].some(k => name.includes(k))) {
    potential.push("command_injection");
  }
  
  // Path Traversal indicators
  if (["file", "path", "filename", "filepath", "document", "doc", "template", "include", "load", "read", "download"].some(k => name.includes(k))) {
    potential.push("path_traversal");
  }
  
  // SSRF indicators
  if (["url", "uri", "link", "href", "redirect", "callback", "webhook", "fetch", "load", "image", "img", "src"].some(k => name.includes(k))) {
    potential.push("ssrf");
  }
  
  // Auth Bypass indicators
  if (["admin", "role", "permission", "access", "auth", "token", "session", "user", "login", "password", "key"].some(k => name.includes(k))) {
    potential.push("auth_bypass");
  }
  
  return potential;
}

async function analyzeEndpointsWithAI(
  paths: string[],
  forms: DiscoveredForm[],
  baseUrl: string,
  technologies: string[]
): Promise<DiscoveredEndpoint[]> {
  if (paths.length === 0 && forms.length === 0) {
    return [];
  }
  
  const prompt = `Analyze these discovered web application endpoints and forms for security testing prioritization:

Base URL: ${baseUrl}
Technologies Detected: ${technologies.join(", ") || "Unknown"}

Discovered Paths:
${paths.slice(0, 50).map(p => `- ${p}`).join("\n")}

Discovered Forms:
${forms.map(f => `- ${f.method} ${f.action} (fields: ${f.fields.map(field => field.name).join(", ")})`).join("\n")}

For each endpoint, analyze and return as JSON:
{
  "endpoints": [
    {
      "url": "full url",
      "method": "GET|POST|PUT|DELETE|PATCH",
      "path": "/api/path",
      "type": "api|form|page|static|websocket|graphql",
      "parameters": [
        {
          "name": "param_name",
          "location": "query|body|path|header|cookie",
          "type": "string|number|boolean|file|json|unknown",
          "required": true|false,
          "vulnerabilityPotential": ["sqli", "xss", "command_injection", "path_traversal", "ssrf", "auth_bypass"]
        }
      ],
      "authentication": "none|cookie|bearer|basic|api_key|unknown",
      "description": "What this endpoint does",
      "riskIndicators": ["list of security concerns"],
      "priority": "high|medium|low"
    }
  ],
  "testOrder": ["endpoint paths in recommended test order, highest risk first"]
}

Focus on:
1. API endpoints (especially those handling user input)
2. Authentication/authorization endpoints
3. File upload/download endpoints
4. Admin or privileged endpoints
5. Search/filter functionality
6. User-generated content endpoints`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a security analyst identifying attack vectors in web applications. Respond only with valid JSON." },
        { role: "user", content: prompt },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 4096,
    });

    const result = JSON.parse(response.choices[0]?.message?.content || "{}");
    
    return (result.endpoints || []).map((ep: any) => ({
      url: ep.url || `${baseUrl}${ep.path}`,
      method: ep.method || "GET",
      path: ep.path || "",
      type: ep.type || "page",
      parameters: (ep.parameters || []).map((p: any) => ({
        name: p.name,
        location: p.location || "query",
        type: p.type || "string",
        required: p.required || false,
        sampleValue: p.sampleValue,
        vulnerabilityPotential: p.vulnerabilityPotential || determineVulnerabilityPotential(p),
      })),
      authentication: ep.authentication || "unknown",
      description: ep.description,
      riskIndicators: ep.riskIndicators || [],
      priority: ep.priority || "medium",
    }));
  } catch (error) {
    console.error("[WebAppRecon] AI analysis error:", error);
    
    // Fallback: convert paths to basic endpoints
    return paths.slice(0, 30).map(path => ({
      url: `${baseUrl}${path}`,
      method: "GET" as const,
      path,
      type: path.includes("/api/") ? "api" as const : "page" as const,
      parameters: [],
      authentication: "unknown" as const,
      description: undefined,
      riskIndicators: [],
      priority: path.includes("/api/") || path.includes("admin") ? "high" as const : "medium" as const,
    }));
  }
}

export async function runWebAppReconnaissance(
  targetUrl: string,
  onProgress?: ReconProgressCallback
): Promise<WebAppReconResult> {
  const startTime = Date.now();
  
  onProgress?.("initialization", 5, "Starting web application reconnaissance...");
  
  // Validate target URL
  let baseUrl: string;
  try {
    const url = new URL(targetUrl);
    baseUrl = url.origin;
  } catch {
    throw new Error(`Invalid target URL: ${targetUrl}`);
  }
  
  onProgress?.("crawling", 10, "Fetching target application...");
  
  // Fetch main page
  let mainPageHtml = "";
  let mainResponse: Response | null = null;
  try {
    mainResponse = await fetchWithTimeout(targetUrl, 15000);
    mainPageHtml = await mainResponse.text();
  } catch (error) {
    console.error("[WebAppRecon] Failed to fetch main page:", error);
    throw new Error(`Cannot reach target: ${targetUrl}`);
  }
  
  onProgress?.("analysis", 20, "Analyzing security headers...");
  
  // Analyze security headers
  const headerAnalysis = await analyzeSecurityHeaders(mainResponse);
  
  onProgress?.("detection", 30, "Detecting technologies...");
  
  // Detect technologies
  const techAnalysis = await detectTechnologies(mainPageHtml, mainResponse.headers);
  
  // Get title
  const titleMatch = mainPageHtml.match(/<title>([^<]+)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : undefined;
  
  onProgress?.("discovery", 40, "Discovering endpoints from robots.txt...");
  
  // Discover paths from various sources
  const robotsPaths = await discoverFromRobotsTxt(baseUrl);
  
  onProgress?.("discovery", 50, "Checking sitemap...");
  const sitemapPaths = await discoverFromSitemap(baseUrl);
  
  onProgress?.("extraction", 60, "Extracting links and forms from HTML...");
  const htmlPaths = extractLinksFromHtml(mainPageHtml, baseUrl);
  const forms = extractFormsFromHtml(mainPageHtml, baseUrl);
  
  // Combine all discovered paths
  const allPaths = Array.from(new Set([...robotsPaths, ...sitemapPaths, ...htmlPaths]));
  
  onProgress?.("ai_analysis", 70, `Analyzing ${allPaths.length} discovered paths with AI...`);
  
  // AI analysis of endpoints
  const endpoints = await analyzeEndpointsWithAI(
    allPaths,
    forms,
    baseUrl,
    [...techAnalysis.technologies, ...techAnalysis.frameworks]
  );
  
  onProgress?.("scoring", 85, "Calculating attack surface metrics...");
  
  // Calculate attack surface metrics
  const attackSurface = {
    totalEndpoints: endpoints.length,
    highPriorityEndpoints: endpoints.filter(e => e.priority === "high").length,
    inputParameters: endpoints.reduce((sum, e) => sum + e.parameters.length, 0),
    apiEndpoints: endpoints.filter(e => e.type === "api").length,
    authenticationPoints: endpoints.filter(e => 
      e.path.includes("login") || 
      e.path.includes("auth") || 
      e.path.includes("signin") ||
      e.parameters.some(p => ["password", "token", "key"].some(k => p.name.toLowerCase().includes(k)))
    ).length,
    fileUploadPoints: forms.filter(f => f.hasFileUpload).length + 
      endpoints.filter(e => e.parameters.some(p => p.type === "file")).length,
  };
  
  // Generate security observations
  const securityObservations: string[] = [];
  
  if (headerAnalysis.missing.length > 0) {
    securityObservations.push(`Missing security headers: ${headerAnalysis.missing.join(", ")}`);
  }
  
  if (forms.some(f => !f.hasCsrfToken)) {
    securityObservations.push("Some forms lack CSRF protection tokens");
  }
  
  if (attackSurface.fileUploadPoints > 0) {
    securityObservations.push(`${attackSurface.fileUploadPoints} file upload point(s) detected - potential for arbitrary file upload`);
  }
  
  if (endpoints.some(e => e.path.includes("admin") && e.authentication === "none")) {
    securityObservations.push("Admin endpoints appear to lack authentication");
  }
  
  // Recommended test order (high priority first)
  const recommendedTestOrder = [
    ...endpoints.filter(e => e.priority === "high").map(e => e.path),
    ...endpoints.filter(e => e.priority === "medium").map(e => e.path),
    ...endpoints.filter(e => e.priority === "low").map(e => e.path),
  ].slice(0, 20);
  
  onProgress?.("complete", 100, "Web application reconnaissance complete");
  
  const scanCompleted = new Date();
  
  return {
    targetUrl,
    scanStarted: new Date(startTime),
    scanCompleted,
    durationMs: scanCompleted.getTime() - startTime,
    applicationInfo: {
      title,
      technologies: techAnalysis.technologies,
      frameworks: techAnalysis.frameworks,
      server: mainResponse.headers.get("server") || undefined,
      securityHeaders: headerAnalysis.present,
      missingSecurityHeaders: headerAnalysis.missing,
    },
    endpoints,
    forms,
    attackSurface,
    securityObservations,
    recommendedTestOrder,
  };
}

export function summarizeReconResult(result: WebAppReconResult): string {
  return `Web Application Reconnaissance Summary:
Target: ${result.targetUrl}
Duration: ${(result.durationMs / 1000).toFixed(1)}s

Application: ${result.applicationInfo.title || "Unknown"}
Technologies: ${[...result.applicationInfo.technologies, ...result.applicationInfo.frameworks].join(", ") || "Not detected"}

Attack Surface:
- ${result.attackSurface.totalEndpoints} total endpoints (${result.attackSurface.highPriorityEndpoints} high priority)
- ${result.attackSurface.inputParameters} input parameters
- ${result.attackSurface.apiEndpoints} API endpoints
- ${result.attackSurface.authenticationPoints} authentication points
- ${result.attackSurface.fileUploadPoints} file upload points

Security Observations:
${result.securityObservations.map(o => `- ${o}`).join("\n") || "- No immediate concerns identified"}`;
}
