import { ValidatingHttpClient } from "../validating-http-client";
import { getSqliPayloads, getSqliPayloadsByDb } from "../payloads/sqli-payloads";
import type { Payload, PayloadExecutionContext, PayloadResult } from "../payloads/payload-types";
import { buildPayloadRequest } from "../payloads/payload-types";
import type { ValidationContext } from "../validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

export interface SqliValidationResult {
  vulnerable: boolean;
  confidence: number;
  verdict: ValidationVerdict;
  technique: "error_based" | "time_based" | "boolean_based" | "union_based" | null;
  dbType: "mysql" | "postgresql" | "mssql" | "oracle" | "sqlite" | "unknown" | null;
  payloadResults: PayloadResult[];
  evidence: string;
  recommendations: string[];
}

interface TimeBasedResult {
  payload: Payload;
  baselineTime: number;
  testTime: number;
  difference: number;
}

interface BooleanBasedResult {
  truePayload: Payload;
  falsePayload: Payload;
  trueResponse: string;
  falseResponse: string;
  lengthDifference: number;
}

const DB_ERROR_PATTERNS: Record<string, RegExp[]> = {
  mysql: [
    /mysql_fetch/i,
    /You have an error in your SQL syntax/i,
    /mysql_num_rows/i,
    /MySqlClient/i,
    /MySQL Query fail/i,
    /SQL syntax.*MySQL/i,
    /Warning.*mysql/i,
    /MySqlException/i,
  ],
  postgresql: [
    /PostgreSQL.*ERROR/i,
    /pg_query/i,
    /pg_exec/i,
    /PG::SyntaxError/i,
    /PSQLException/i,
    /valid PostgreSQL result/i,
  ],
  mssql: [
    /Driver.*SQL[\-\_\ ]*Server/i,
    /OLE DB.*SQL Server/i,
    /SQLServer JDBC Driver/i,
    /SqlClient/i,
    /SQLSTATE/i,
    /\[Microsoft\]\[ODBC SQL Server/i,
    /Unclosed quotation mark/i,
  ],
  oracle: [
    /ORA-[0-9]{5}/i,
    /Oracle error/i,
    /Oracle.*Driver/i,
    /OracleException/i,
  ],
  sqlite: [
    /SQLite\/JDBCDriver/i,
    /SQLite\.Exception/i,
    /sqlite3\.OperationalError/i,
    /SQLITE_ERROR/i,
  ],
};

const GENERIC_SQL_ERROR_PATTERNS = [
  /SQL syntax/i,
  /SQLSTATE/i,
  /syntax error/i,
  /unclosed quotation/i,
  /quoted string not properly terminated/i,
  /unexpected end of SQL/i,
  /invalid query/i,
];

export class SqliValidator {
  private client: ValidatingHttpClient;
  private context?: ValidationContext;

  constructor(context?: ValidationContext) {
    this.client = new ValidatingHttpClient();
    this.context = context;
  }

  async validate(executionContext: PayloadExecutionContext): Promise<SqliValidationResult> {
    const payloadResults: PayloadResult[] = [];
    let detectedTechnique: SqliValidationResult["technique"] = null;
    let detectedDbType: SqliValidationResult["dbType"] = null;
    let highestConfidence = 0;
    let evidence = "";

    const baselineResponse = await this.getBaselineResponse(executionContext);
    if (!baselineResponse) {
      return this.createErrorResult("Failed to establish baseline response");
    }

    const errorResult = await this.testErrorBased(executionContext, baselineResponse);
    if (errorResult.vulnerable) {
      detectedTechnique = "error_based";
      detectedDbType = errorResult.dbType;
      highestConfidence = Math.max(highestConfidence, errorResult.confidence);
      evidence = errorResult.evidence;
      payloadResults.push(...errorResult.payloadResults);
    }

    const timeResult = await this.testTimeBased(executionContext);
    if (timeResult.vulnerable && timeResult.confidence > highestConfidence) {
      detectedTechnique = "time_based";
      highestConfidence = timeResult.confidence;
      evidence = timeResult.evidence;
      payloadResults.push(...timeResult.payloadResults);
    }

    const booleanResult = await this.testBooleanBased(executionContext, baselineResponse);
    if (booleanResult.vulnerable && booleanResult.confidence > highestConfidence) {
      detectedTechnique = "boolean_based";
      highestConfidence = booleanResult.confidence;
      evidence = booleanResult.evidence;
      payloadResults.push(...booleanResult.payloadResults);
    }

    const vulnerable = highestConfidence >= 50;
    const verdict = this.determineVerdict(highestConfidence);

    return {
      vulnerable,
      confidence: highestConfidence,
      verdict,
      technique: detectedTechnique,
      dbType: detectedDbType || "unknown",
      payloadResults,
      evidence,
      recommendations: this.generateRecommendations(detectedTechnique, detectedDbType),
    };
  }

  private async getBaselineResponse(ctx: PayloadExecutionContext): Promise<{ body: string; time: number; status: number } | null> {
    try {
      const req = this.buildRequest(ctx, ctx.originalValue || "1");
      const startTime = Date.now();
      const { response } = await this.client.request({
        url: req.url,
        method: ctx.httpMethod,
        headers: { ...ctx.headers, ...req.headers },
        body: req.body,
        timeout: ctx.timeout || 10000,
      });
      const endTime = Date.now();

      return {
        body: response.body,
        time: endTime - startTime,
        status: response.statusCode,
      };
    } catch (error) {
      console.error("[SqliValidator] Failed to get baseline:", error);
      return null;
    }
  }

  private async testErrorBased(
    ctx: PayloadExecutionContext,
    baseline: { body: string; time: number; status: number }
  ): Promise<{ vulnerable: boolean; confidence: number; dbType: SqliValidationResult["dbType"]; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getSqliPayloads("error_based");
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let detectedDb: SqliValidationResult["dbType"] = null;
    let bestEvidence = "";

    for (const payload of payloads.slice(0, 7)) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...req.headers },
          body: req.body,
          timeout: ctx.timeout || 10000,
        });

        const matchedIndicators: string[] = [];
        let confidence = 0;
        let dbType: SqliValidationResult["dbType"] = null;

        for (const [db, patterns] of Object.entries(DB_ERROR_PATTERNS)) {
          for (const pattern of patterns) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`DB Error: ${db}`);
              dbType = db as SqliValidationResult["dbType"];
              confidence = 85;
              break;
            }
          }
          if (dbType) break;
        }

        if (!dbType) {
          for (const pattern of GENERIC_SQL_ERROR_PATTERNS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push("Generic SQL error");
              confidence = 70;
              break;
            }
          }
        }

        for (const indicator of payload.successIndicators) {
          if (response.body.toLowerCase().includes(indicator.toLowerCase())) {
            matchedIndicators.push(indicator);
            confidence = Math.max(confidence, 60);
          }
        }

        // Detect auth bypass SQLi: if baseline returned 4xx/5xx and this
        // OR-based payload flipped the response to 200, it's a strong indicator.
        const isOrPayload = /\bOR\b/i.test(payload.value);
        if (isOrPayload && baseline.status >= 400 && response.statusCode === 200) {
          const bodyLenDiff = Math.abs(response.body.length - baseline.body.length);
          if (bodyLenDiff > 50) {
            matchedIndicators.push(`Auth bypass: status ${baseline.status}→${response.statusCode}`);
            confidence = Math.max(confidence, 90);
            // Check for JWT / auth token in response
            if (/token|jwt|auth|session/i.test(response.body)) {
              matchedIndicators.push("Auth token in response");
              confidence = Math.max(confidence, 95);
            }
          }
        }

        const result: PayloadResult = {
          payloadId: payload.id,
          payload: payload.value,
          success: confidence >= 50,
          confidence,
          responseCode: response.statusCode,
          responseTime: response.timing.durationMs,
          matchedIndicators,
          evidence: matchedIndicators.length > 0 ? `Response contained: ${matchedIndicators.join(", ")}` : "",
          verdict: this.determineVerdict(confidence),
        };
        results.push(result);

        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          detectedDb = dbType;
          bestEvidence = result.evidence;
        }
      } catch (error) {
        results.push({
          payloadId: payload.id,
          payload: payload.value,
          success: false,
          confidence: 0,
          responseCode: 0,
          responseTime: 0,
          matchedIndicators: [],
          evidence: `Error: ${error instanceof Error ? error.message : "Unknown"}`,
          verdict: "error",
        });
      }
    }

    return {
      vulnerable: maxConfidence >= 50,
      confidence: maxConfidence,
      dbType: detectedDb,
      evidence: bestEvidence,
      payloadResults: results,
    };
  }

  private async testTimeBased(ctx: PayloadExecutionContext): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getSqliPayloads("time_based");
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    const expectedDelay = 5000;
    const tolerance = 1000;

    for (const payload of payloads.slice(0, 3)) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const startTime = Date.now();
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...req.headers },
          body: req.body,
          timeout: 15000,
        });
        const responseTime = Date.now() - startTime;

        const isDelayed = responseTime >= (expectedDelay - tolerance);
        const confidence = isDelayed ? Math.min(90, 50 + ((responseTime - expectedDelay + tolerance) / 100)) : 0;

        const result: PayloadResult = {
          payloadId: payload.id,
          payload: payload.value,
          success: isDelayed,
          confidence,
          responseCode: response.statusCode,
          responseTime,
          matchedIndicators: isDelayed ? [`Response delayed by ${responseTime}ms`] : [],
          evidence: isDelayed ? `Time-based injection confirmed: ${responseTime}ms delay (expected ~${expectedDelay}ms)` : "",
          verdict: this.determineVerdict(confidence),
        };
        results.push(result);

        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          bestEvidence = result.evidence;
        }
      } catch (error) {
        results.push({
          payloadId: payload.id,
          payload: payload.value,
          success: false,
          confidence: 0,
          responseCode: 0,
          responseTime: 0,
          matchedIndicators: [],
          evidence: `Error: ${error instanceof Error ? error.message : "Unknown"}`,
          verdict: "error",
        });
      }
    }

    return {
      vulnerable: maxConfidence >= 50,
      confidence: maxConfidence,
      evidence: bestEvidence,
      payloadResults: results,
    };
  }

  private async testBooleanBased(
    ctx: PayloadExecutionContext,
    baseline: { body: string; time: number; status: number }
  ): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getSqliPayloads("boolean_based");
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    const truePayloads = payloads.filter(p => p.value.includes("1=1") || p.value.includes("'1'='1"));
    const falsePayloads = payloads.filter(p => p.value.includes("1=2") || p.value.includes("'1'='2"));

    for (let i = 0; i < Math.min(truePayloads.length, falsePayloads.length, 2); i++) {
      const truePayload = truePayloads[i];
      const falsePayload = falsePayloads[i];

      try {
        const trueReq = this.buildRequest(ctx, truePayload.value);
        const { response: trueResponse } = await this.client.request({
          url: trueReq.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...trueReq.headers },
          body: trueReq.body,
          timeout: ctx.timeout || 10000,
        });

        const falseReq = this.buildRequest(ctx, falsePayload.value);
        const { response: falseResponse } = await this.client.request({
          url: falseReq.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...falseReq.headers },
          body: falseReq.body,
          timeout: ctx.timeout || 10000,
        });

        const lengthDiff = Math.abs(trueResponse.body.length - falseResponse.body.length);
        const statusDiff = trueResponse.statusCode !== falseResponse.statusCode;
        const baselineSimilar = Math.abs(trueResponse.body.length - baseline.body.length) < 50;

        let confidence = 0;
        if (statusDiff) confidence = 75;
        else if (lengthDiff > 100 && baselineSimilar) confidence = 70;
        else if (lengthDiff > 50 && baselineSimilar) confidence = 55;

        const vulnerable = confidence >= 50;
        const evidence = vulnerable
          ? `Boolean-based detection: TRUE response (${trueResponse.body.length} bytes) differs from FALSE (${falseResponse.body.length} bytes)`
          : "";

        results.push({
          payloadId: truePayload.id,
          payload: truePayload.value,
          success: vulnerable,
          confidence,
          responseCode: trueResponse.statusCode,
          responseTime: trueResponse.timing.durationMs,
          matchedIndicators: vulnerable ? [`Length difference: ${lengthDiff} bytes`] : [],
          evidence,
          verdict: this.determineVerdict(confidence),
        });

        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          bestEvidence = evidence;
        }
      } catch (error) {
        results.push({
          payloadId: truePayload.id,
          payload: truePayload.value,
          success: false,
          confidence: 0,
          responseCode: 0,
          responseTime: 0,
          matchedIndicators: [],
          evidence: `Error: ${error instanceof Error ? error.message : "Unknown"}`,
          verdict: "error",
        });
      }
    }

    return {
      vulnerable: maxConfidence >= 50,
      confidence: maxConfidence,
      evidence: bestEvidence,
      payloadResults: results,
    };
  }

  private buildRequest(ctx: PayloadExecutionContext, payloadValue: string) {
    return buildPayloadRequest(ctx, payloadValue);
  }

  private determineVerdict(confidence: number): ValidationVerdict {
    if (confidence >= 80) return "confirmed";
    if (confidence >= 50) return "likely";
    if (confidence >= 20) return "theoretical";
    return "false_positive";
  }

  private generateRecommendations(technique: SqliValidationResult["technique"], dbType: SqliValidationResult["dbType"]): string[] {
    const recommendations: string[] = [
      "Use parameterized queries (prepared statements) for all database operations",
      "Implement input validation and sanitization",
      "Apply the principle of least privilege to database accounts",
      "Enable detailed error logging but return generic errors to users",
    ];

    if (technique === "error_based") {
      recommendations.push("Disable detailed database error messages in production");
    }

    if (dbType === "mysql") {
      recommendations.push("Enable MySQL strict mode");
      recommendations.push("Use mysqli or PDO with prepared statements");
    } else if (dbType === "postgresql") {
      recommendations.push("Use pg_prepare and pg_execute for queries");
    }

    return recommendations;
  }

  private createErrorResult(message: string): SqliValidationResult {
    return {
      vulnerable: false,
      confidence: 0,
      verdict: "error",
      technique: null,
      dbType: null,
      payloadResults: [],
      evidence: message,
      recommendations: [],
    };
  }
}

export function createSqliValidator(context?: ValidationContext): SqliValidator {
  return new SqliValidator(context);
}
