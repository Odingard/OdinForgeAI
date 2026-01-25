export interface SchemaValidationResult {
  valid: boolean;
  errors: SchemaValidationError[];
  warnings: SchemaValidationWarning[];
  anomalies: ResponseAnomaly[];
}

export interface SchemaValidationError {
  path: string;
  message: string;
  expected: string;
  actual: string;
  severity: "error" | "warning";
}

export interface SchemaValidationWarning {
  path: string;
  message: string;
  recommendation: string;
}

export interface ResponseAnomaly {
  type: AnomalyType;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  evidence: string;
  location?: string;
  mitreAttackId?: string;
}

export type AnomalyType =
  | "type_mismatch"
  | "missing_required_field"
  | "unexpected_field"
  | "null_in_non_nullable"
  | "enum_violation"
  | "format_violation"
  | "boundary_violation"
  | "array_length_violation"
  | "sensitive_data_exposure"
  | "error_disclosure"
  | "timing_anomaly"
  | "status_code_mismatch"
  | "content_type_mismatch"
  | "schema_deviation";

export interface ExpectedResponse {
  statusCode?: number | number[];
  contentType?: string;
  schema?: JsonSchema;
  headers?: Record<string, string>;
  maxResponseTime?: number;
}

export interface JsonSchema {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: any[];
  format?: string;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minItems?: number;
  maxItems?: number;
  nullable?: boolean;
  additionalProperties?: boolean | JsonSchema;
}

class ResponseValidator {
  validate(
    responseBody: string,
    statusCode: number,
    responseHeaders: Record<string, string>,
    responseTimeMs: number,
    expected: ExpectedResponse
  ): SchemaValidationResult {
    const errors: SchemaValidationError[] = [];
    const warnings: SchemaValidationWarning[] = [];
    const anomalies: ResponseAnomaly[] = [];

    if (expected.statusCode !== undefined) {
      const expectedCodes = Array.isArray(expected.statusCode) 
        ? expected.statusCode 
        : [expected.statusCode];
      
      if (!expectedCodes.includes(statusCode)) {
        anomalies.push({
          type: "status_code_mismatch",
          severity: statusCode >= 500 ? "high" : "medium",
          description: `Unexpected status code: ${statusCode}`,
          evidence: `Expected ${expectedCodes.join(" or ")}, got ${statusCode}`,
        });
      }
    }

    if (expected.contentType) {
      const actualContentType = responseHeaders["content-type"] || "";
      if (!actualContentType.includes(expected.contentType)) {
        anomalies.push({
          type: "content_type_mismatch",
          severity: "low",
          description: `Unexpected content type`,
          evidence: `Expected ${expected.contentType}, got ${actualContentType}`,
        });
      }
    }

    if (expected.maxResponseTime && responseTimeMs > expected.maxResponseTime) {
      anomalies.push({
        type: "timing_anomaly",
        severity: responseTimeMs > expected.maxResponseTime * 3 ? "high" : "medium",
        description: `Response time exceeded threshold`,
        evidence: `Expected <${expected.maxResponseTime}ms, got ${responseTimeMs}ms`,
      });
    }

    this.checkSensitiveDataExposure(responseBody, statusCode, anomalies);

    this.checkErrorDisclosure(responseBody, statusCode, anomalies);

    if (expected.schema && responseBody) {
      let parsedBody: any;
      try {
        parsedBody = JSON.parse(responseBody);
        this.validateSchema(parsedBody, expected.schema, "", errors, anomalies);
      } catch {
        if (responseHeaders["content-type"]?.includes("application/json")) {
          errors.push({
            path: "$",
            message: "Response body is not valid JSON",
            expected: "valid JSON",
            actual: responseBody.slice(0, 100),
            severity: "error",
          });
        }
      }
    }

    this.generateWarnings(errors, anomalies, warnings);

    return {
      valid: errors.filter(e => e.severity === "error").length === 0,
      errors,
      warnings,
      anomalies,
    };
  }

  private validateSchema(
    value: any,
    schema: JsonSchema,
    path: string,
    errors: SchemaValidationError[],
    anomalies: ResponseAnomaly[]
  ): void {
    const currentPath = path || "$";

    if (value === null) {
      if (schema.nullable !== true && schema.type !== "null") {
        anomalies.push({
          type: "null_in_non_nullable",
          severity: "medium",
          description: `Null value in non-nullable field`,
          evidence: `Path: ${currentPath}`,
          location: currentPath,
        });
      }
      return;
    }

    if (value === undefined) {
      return;
    }

    if (schema.type) {
      const types = Array.isArray(schema.type) ? schema.type : [schema.type];
      const actualType = this.getJsonType(value);
      
      if (!types.includes(actualType) && !(schema.nullable && value === null)) {
        anomalies.push({
          type: "type_mismatch",
          severity: "medium",
          description: `Type mismatch at ${currentPath}`,
          evidence: `Expected ${types.join(" | ")}, got ${actualType}`,
          location: currentPath,
        });
        errors.push({
          path: currentPath,
          message: `Type mismatch`,
          expected: types.join(" | "),
          actual: actualType,
          severity: "error",
        });
      }
    }

    if (schema.enum && !schema.enum.includes(value)) {
      anomalies.push({
        type: "enum_violation",
        severity: "medium",
        description: `Enum violation at ${currentPath}`,
        evidence: `Value "${value}" not in allowed values: [${schema.enum.join(", ")}]`,
        location: currentPath,
      });
    }

    if (typeof value === "string") {
      if (schema.minLength !== undefined && value.length < schema.minLength) {
        anomalies.push({
          type: "boundary_violation",
          severity: "low",
          description: `String too short at ${currentPath}`,
          evidence: `Length ${value.length} < minLength ${schema.minLength}`,
          location: currentPath,
        });
      }
      if (schema.maxLength !== undefined && value.length > schema.maxLength) {
        anomalies.push({
          type: "boundary_violation",
          severity: "low",
          description: `String too long at ${currentPath}`,
          evidence: `Length ${value.length} > maxLength ${schema.maxLength}`,
          location: currentPath,
        });
      }
      if (schema.pattern) {
        try {
          const regex = new RegExp(schema.pattern);
          if (!regex.test(value)) {
            anomalies.push({
              type: "format_violation",
              severity: "low",
              description: `Pattern mismatch at ${currentPath}`,
              evidence: `Value "${value.slice(0, 50)}" doesn't match pattern "${schema.pattern}"`,
              location: currentPath,
            });
          }
        } catch {
        }
      }
      if (schema.format) {
        this.validateFormat(value, schema.format, currentPath, anomalies);
      }
    }

    if (typeof value === "number") {
      if (schema.minimum !== undefined && value < schema.minimum) {
        anomalies.push({
          type: "boundary_violation",
          severity: "medium",
          description: `Number below minimum at ${currentPath}`,
          evidence: `Value ${value} < minimum ${schema.minimum}`,
          location: currentPath,
        });
      }
      if (schema.maximum !== undefined && value > schema.maximum) {
        anomalies.push({
          type: "boundary_violation",
          severity: "medium",
          description: `Number above maximum at ${currentPath}`,
          evidence: `Value ${value} > maximum ${schema.maximum}`,
          location: currentPath,
        });
      }
    }

    if (Array.isArray(value)) {
      if (schema.minItems !== undefined && value.length < schema.minItems) {
        anomalies.push({
          type: "array_length_violation",
          severity: "low",
          description: `Array too short at ${currentPath}`,
          evidence: `Length ${value.length} < minItems ${schema.minItems}`,
          location: currentPath,
        });
      }
      if (schema.maxItems !== undefined && value.length > schema.maxItems) {
        anomalies.push({
          type: "array_length_violation",
          severity: "low",
          description: `Array too long at ${currentPath}`,
          evidence: `Length ${value.length} > maxItems ${schema.maxItems}`,
          location: currentPath,
        });
      }
      if (schema.items) {
        value.forEach((item, index) => {
          this.validateSchema(item, schema.items!, `${currentPath}[${index}]`, errors, anomalies);
        });
      }
    }

    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      if (schema.required) {
        for (const requiredField of schema.required) {
          if (!(requiredField in value)) {
            anomalies.push({
              type: "missing_required_field",
              severity: "medium",
              description: `Missing required field`,
              evidence: `Field "${requiredField}" is required but missing at ${currentPath}`,
              location: `${currentPath}.${requiredField}`,
            });
            errors.push({
              path: `${currentPath}.${requiredField}`,
              message: `Missing required field`,
              expected: "present",
              actual: "missing",
              severity: "error",
            });
          }
        }
      }

      if (schema.properties) {
        for (const [key, propSchema] of Object.entries(schema.properties)) {
          if (key in value) {
            this.validateSchema(value[key], propSchema, `${currentPath}.${key}`, errors, anomalies);
          }
        }
      }

      if (schema.additionalProperties === false && schema.properties) {
        const allowedKeys = Object.keys(schema.properties);
        for (const key of Object.keys(value)) {
          if (!allowedKeys.includes(key)) {
            anomalies.push({
              type: "unexpected_field",
              severity: "low",
              description: `Unexpected field in response`,
              evidence: `Field "${key}" at ${currentPath} is not defined in schema`,
              location: `${currentPath}.${key}`,
            });
          }
        }
      }
    }
  }

  private getJsonType(value: any): string {
    if (value === null) return "null";
    if (Array.isArray(value)) return "array";
    return typeof value;
  }

  private validateFormat(
    value: string,
    format: string,
    path: string,
    anomalies: ResponseAnomaly[]
  ): void {
    const formatValidators: Record<string, RegExp> = {
      email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
      uri: /^https?:\/\/.+/,
      uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      "date-time": /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,
      date: /^\d{4}-\d{2}-\d{2}$/,
      time: /^\d{2}:\d{2}:\d{2}/,
      ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
      ipv6: /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
    };

    const validator = formatValidators[format];
    if (validator && !validator.test(value)) {
      anomalies.push({
        type: "format_violation",
        severity: "low",
        description: `Invalid ${format} format at ${path}`,
        evidence: `Value "${value.slice(0, 50)}" doesn't match ${format} format`,
        location: path,
      });
    }
  }

  private checkSensitiveDataExposure(
    responseBody: string,
    statusCode: number,
    anomalies: ResponseAnomaly[]
  ): void {
    const sensitivePatterns = [
      { 
        pattern: /password\s*[:=]\s*["'][^"']+["']/gi, 
        type: "password",
        severity: "critical" as const,
        mitreId: "T1552.001"
      },
      { 
        pattern: /["']?api[_-]?key["']?\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']/gi, 
        type: "api_key",
        severity: "critical" as const,
        mitreId: "T1552.004"
      },
      { 
        pattern: /["']?secret["']?\s*[:=]\s*["'][^"']{10,}["']/gi, 
        type: "secret",
        severity: "critical" as const,
        mitreId: "T1552.004"
      },
      { 
        pattern: /["']?token["']?\s*[:=]\s*["'][A-Za-z0-9._-]{20,}["']/gi, 
        type: "token",
        severity: "high" as const,
        mitreId: "T1528"
      },
      { 
        pattern: /["']?private[_-]?key["']?\s*[:=]/gi, 
        type: "private_key",
        severity: "critical" as const,
        mitreId: "T1552.004"
      },
      { 
        pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g, 
        type: "pem_private_key",
        severity: "critical" as const,
        mitreId: "T1552.004"
      },
      { 
        pattern: /\b(?:\d{4}[-\s]?){4}\b/g, 
        type: "credit_card",
        severity: "critical" as const,
        mitreId: "T1552.001"
      },
      { 
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g, 
        type: "ssn",
        severity: "critical" as const,
        mitreId: "T1552.001"
      },
    ];

    if (statusCode >= 400) {
      for (const { pattern, type, severity, mitreId } of sensitivePatterns) {
        const matches = responseBody.match(pattern);
        if (matches && matches.length > 0) {
          anomalies.push({
            type: "sensitive_data_exposure",
            severity,
            description: `Potential ${type} exposure in error response`,
            evidence: `Found ${matches.length} potential ${type} pattern(s) in ${statusCode} response`,
            mitreAttackId: mitreId,
          });
        }
      }
    }
  }

  private checkErrorDisclosure(
    responseBody: string,
    statusCode: number,
    anomalies: ResponseAnomaly[]
  ): void {
    if (statusCode < 400) return;

    const disclosurePatterns = [
      { 
        pattern: /at\s+[\w.]+\s*\([^)]*:\d+:\d+\)/g, 
        type: "stack_trace",
        severity: "high" as const,
        mitreId: "T1592.004"
      },
      { 
        pattern: /File\s+["'][^"']+["'],\s+line\s+\d+/gi, 
        type: "python_traceback",
        severity: "high" as const,
        mitreId: "T1592.004"
      },
      { 
        pattern: /\/(?:var|home|opt|usr|etc)\/[^\s"'<>]+/g, 
        type: "file_path",
        severity: "medium" as const,
        mitreId: "T1592.004"
      },
      { 
        pattern: /[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*/g, 
        type: "windows_path",
        severity: "medium" as const,
        mitreId: "T1592.004"
      },
      { 
        pattern: /mysql|postgresql|oracle|sqlite|mongodb|redis/gi, 
        type: "database_type",
        severity: "low" as const,
        mitreId: "T1592.002"
      },
      { 
        pattern: /(?:php|java|python|node|ruby)\s*(?:version\s*)?[\d.]+/gi, 
        type: "runtime_version",
        severity: "low" as const,
        mitreId: "T1592.002"
      },
      { 
        pattern: /(?:apache|nginx|iis|express|tomcat)\s*[\d.]+/gi, 
        type: "server_version",
        severity: "low" as const,
        mitreId: "T1592.002"
      },
    ];

    for (const { pattern, type, severity, mitreId } of disclosurePatterns) {
      const matches = responseBody.match(pattern);
      if (matches && matches.length > 0) {
        anomalies.push({
          type: "error_disclosure",
          severity,
          description: `${type.replace(/_/g, " ")} disclosed in error response`,
          evidence: `Found ${type} patterns in ${statusCode} response: ${matches.slice(0, 3).join(", ")}`,
          mitreAttackId: mitreId,
        });
      }
    }
  }

  private generateWarnings(
    errors: SchemaValidationError[],
    anomalies: ResponseAnomaly[],
    warnings: SchemaValidationWarning[]
  ): void {
    const criticalAnomalies = anomalies.filter(a => a.severity === "critical");
    if (criticalAnomalies.length > 0) {
      warnings.push({
        path: "$",
        message: `${criticalAnomalies.length} critical security anomalies detected`,
        recommendation: "Review and address all critical findings before production deployment",
      });
    }

    const sensitiveExposures = anomalies.filter(a => a.type === "sensitive_data_exposure");
    if (sensitiveExposures.length > 0) {
      warnings.push({
        path: "$",
        message: "Sensitive data may be exposed in responses",
        recommendation: "Implement proper error handling to avoid leaking sensitive information",
      });
    }

    const typeErrors = errors.filter(e => e.message.includes("Type mismatch"));
    if (typeErrors.length > 3) {
      warnings.push({
        path: "$",
        message: `Multiple type mismatches (${typeErrors.length}) suggest schema drift`,
        recommendation: "Update API documentation or fix response handling",
      });
    }
  }

  createSchemaFromSample(sampleResponse: any): JsonSchema {
    return this.inferSchema(sampleResponse);
  }

  private inferSchema(value: any): JsonSchema {
    if (value === null) {
      return { type: "null" };
    }

    if (Array.isArray(value)) {
      const schema: JsonSchema = { type: "array" };
      if (value.length > 0) {
        schema.items = this.inferSchema(value[0]);
      }
      return schema;
    }

    if (typeof value === "object") {
      const schema: JsonSchema = {
        type: "object",
        properties: {},
        required: [],
      };
      for (const [key, val] of Object.entries(value)) {
        schema.properties![key] = this.inferSchema(val);
        if (val !== null && val !== undefined) {
          schema.required!.push(key);
        }
      }
      return schema;
    }

    if (typeof value === "string") {
      const schema: JsonSchema = { type: "string" };
      
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        schema.format = "email";
      } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) {
        schema.format = "date-time";
      } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
        schema.format = "uuid";
      } else if (/^https?:\/\//.test(value)) {
        schema.format = "uri";
      }
      
      return schema;
    }

    if (typeof value === "number") {
      return { type: Number.isInteger(value) ? "integer" : "number" };
    }

    if (typeof value === "boolean") {
      return { type: "boolean" };
    }

    return {};
  }
}

export const responseValidator = new ResponseValidator();
