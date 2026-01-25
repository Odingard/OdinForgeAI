import SwaggerParser from "@apidevtools/swagger-parser";
import YAML from "yaml";
import { randomUUID } from "crypto";
import type { InsertApiDefinition, InsertApiEndpoint } from "@shared/schema";

export interface ParsedOpenAPISpec {
  definition: InsertApiDefinition;
  endpoints: InsertApiEndpoint[];
}

export interface VulnerabilityPotential {
  sqli: number;
  xss: number;
  authBypass: number;
  idor: number;
  injection: number;
  ssrf: number;
}

class OpenAPIParserService {
  async parseSpec(
    specContent: string,
    organizationId: string,
    tenantId: string = "default",
    createdBy?: string
  ): Promise<ParsedOpenAPISpec> {
    let spec: any;
    
    try {
      spec = JSON.parse(specContent);
    } catch {
      try {
        spec = YAML.parse(specContent);
      } catch (yamlError) {
        throw new Error("Invalid spec format: must be valid JSON or YAML");
      }
    }

    const api = await SwaggerParser.validate(spec);
    
    const definitionId = `api-${randomUUID()}`;
    const specVersion = this.detectSpecVersion(api);
    const servers = this.extractServers(api);
    const securitySchemes = this.extractSecuritySchemes(api);
    
    const endpoints: InsertApiEndpoint[] = [];
    const paths = (api as any).paths || {};
    
    for (const [path, pathItem] of Object.entries(paths)) {
      const methods = ["get", "post", "put", "delete", "patch", "options", "head"];
      
      for (const method of methods) {
        const operation = (pathItem as any)[method];
        if (!operation) continue;
        
        const endpoint = this.parseEndpoint(
          definitionId,
          organizationId,
          path,
          method.toUpperCase(),
          operation,
          pathItem as any,
          api
        );
        
        endpoints.push(endpoint);
      }
    }

    const definition: InsertApiDefinition = {
      organizationId,
      tenantId,
      name: (api as any).info?.title || "Untitled API",
      description: (api as any).info?.description,
      version: (api as any).info?.version,
      specVersion,
      baseUrl: servers[0]?.url,
      rawSpec: specContent,
      servers,
      securitySchemes,
      totalEndpoints: Object.keys(paths).length,
      totalOperations: endpoints.length,
      status: "active",
      createdBy,
    };

    return { definition, endpoints };
  }

  private detectSpecVersion(api: any): string {
    if (api.openapi) {
      if (api.openapi.startsWith("3.1")) return "openapi-3.1";
      if (api.openapi.startsWith("3.0")) return "openapi-3.0";
      return `openapi-${api.openapi}`;
    }
    if (api.swagger) {
      return `swagger-${api.swagger}`;
    }
    return "unknown";
  }

  private extractServers(api: any): Array<{ url: string; description?: string }> {
    if (api.servers) {
      return api.servers.map((s: any) => ({
        url: s.url,
        description: s.description,
      }));
    }
    
    if (api.host) {
      const scheme = api.schemes?.[0] || "https";
      const basePath = api.basePath || "";
      return [{ url: `${scheme}://${api.host}${basePath}` }];
    }
    
    return [];
  }

  private extractSecuritySchemes(api: any): Record<string, any> {
    if (api.components?.securitySchemes) {
      return api.components.securitySchemes;
    }
    
    if (api.securityDefinitions) {
      return api.securityDefinitions;
    }
    
    return {};
  }

  private parseEndpoint(
    apiDefinitionId: string,
    organizationId: string,
    path: string,
    method: string,
    operation: any,
    pathItem: any,
    api: any
  ): InsertApiEndpoint {
    const parameters = this.extractParameters(operation, pathItem);
    const requestBody = this.extractRequestBody(operation);
    const responses = this.extractResponses(operation);
    const security = operation.security || (api as any).security || [];
    
    const vulnerabilityPotential = this.analyzeVulnerabilityPotential(
      path,
      method,
      parameters,
      requestBody
    );
    
    const priority = this.calculatePriority(vulnerabilityPotential, method, security);

    return {
      apiDefinitionId,
      organizationId,
      path,
      method,
      operationId: operation.operationId,
      summary: operation.summary,
      description: operation.description,
      tags: operation.tags || [],
      parameters,
      requestBody,
      responses,
      security,
      vulnerabilityPotential,
      priority,
      scanStatus: "pending",
      findingsCount: 0,
    };
  }

  private extractParameters(operation: any, pathItem: any): any[] {
    const params: any[] = [];
    
    const allParams = [
      ...(pathItem.parameters || []),
      ...(operation.parameters || []),
    ];

    for (const param of allParams) {
      const resolvedParam = param.$ref ? this.resolveRef(param.$ref) : param;
      
      params.push({
        name: resolvedParam.name,
        in: resolvedParam.in,
        required: resolvedParam.required || false,
        type: resolvedParam.schema?.type || resolvedParam.type || "string",
        format: resolvedParam.schema?.format || resolvedParam.format,
        description: resolvedParam.description,
        enum: resolvedParam.schema?.enum || resolvedParam.enum,
      });
    }

    return params;
  }

  private extractRequestBody(operation: any): any | null {
    if (!operation.requestBody) return null;

    const content = operation.requestBody.content || {};
    const contentTypes = Object.keys(content);
    
    let schema = null;
    for (const contentType of contentTypes) {
      if (content[contentType]?.schema) {
        schema = content[contentType].schema;
        break;
      }
    }

    return {
      required: operation.requestBody.required || false,
      contentTypes,
      schema,
    };
  }

  private extractResponses(operation: any): Record<string, any> {
    const responses: Record<string, any> = {};
    
    for (const [code, response] of Object.entries(operation.responses || {})) {
      const resp = response as any;
      const content = resp.content || {};
      
      responses[code] = {
        description: resp.description,
        contentTypes: Object.keys(content),
        schema: content[Object.keys(content)[0]]?.schema,
      };
    }

    return responses;
  }

  private resolveRef(ref: string): any {
    return { name: ref.split("/").pop(), in: "unknown", required: false };
  }

  private analyzeVulnerabilityPotential(
    path: string,
    method: string,
    parameters: any[],
    requestBody: any
  ): VulnerabilityPotential {
    const potential: VulnerabilityPotential = {
      sqli: 0,
      xss: 0,
      authBypass: 0,
      idor: 0,
      injection: 0,
      ssrf: 0,
    };

    const hasIdParam = parameters.some(p => 
      /id$/i.test(p.name) || p.name === "id" || /\{.*id\}/i.test(path)
    );
    if (hasIdParam) {
      potential.idor = 0.7;
      potential.sqli = 0.5;
    }

    const hasQueryParams = parameters.some(p => p.in === "query");
    if (hasQueryParams) {
      potential.sqli = Math.max(potential.sqli, 0.4);
      potential.xss = 0.5;
    }

    if (requestBody) {
      potential.sqli = Math.max(potential.sqli, 0.6);
      potential.xss = Math.max(potential.xss, 0.6);
      potential.injection = 0.5;
    }

    const hasUrlParam = parameters.some(p => 
      /url|uri|link|redirect|callback|webhook/i.test(p.name)
    );
    if (hasUrlParam) {
      potential.ssrf = 0.8;
    }

    const authPatterns = /auth|login|token|session|password|register|signup|verify/i;
    if (authPatterns.test(path)) {
      potential.authBypass = 0.6;
    }

    if (method === "POST" || method === "PUT" || method === "PATCH") {
      potential.sqli = Math.max(potential.sqli, 0.4);
      potential.injection = Math.max(potential.injection, 0.4);
    }

    const hasFileUpload = requestBody?.contentTypes?.includes("multipart/form-data");
    if (hasFileUpload) {
      potential.injection = Math.max(potential.injection, 0.7);
    }

    return potential;
  }

  private calculatePriority(
    potential: VulnerabilityPotential,
    method: string,
    security: any[]
  ): "critical" | "high" | "medium" | "low" {
    const maxScore = Math.max(
      potential.sqli,
      potential.xss,
      potential.authBypass,
      potential.idor,
      potential.injection,
      potential.ssrf
    );

    const isUnauthenticated = !security || security.length === 0;
    const isMutating = ["POST", "PUT", "PATCH", "DELETE"].includes(method);

    if (maxScore >= 0.7 && isUnauthenticated && isMutating) return "critical";
    if (maxScore >= 0.6 || (isUnauthenticated && isMutating)) return "high";
    if (maxScore >= 0.4) return "medium";
    return "low";
  }

  async parseFromUrl(url: string, organizationId: string, tenantId?: string, createdBy?: string): Promise<ParsedOpenAPISpec> {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Failed to fetch spec from URL: ${response.statusText}`);
    }
    const specContent = await response.text();
    return this.parseSpec(specContent, organizationId, tenantId, createdBy);
  }
}

export const openAPIParserService = new OpenAPIParserService();
