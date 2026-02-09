import OpenAI from "openai";
import { db } from "../../db";
import { securityPolicies } from "@shared/schema";
import { sql, desc, and, eq } from "drizzle-orm";

const openaiForChat = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY || process.env.OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined,
});

const openaiForEmbeddings = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
});

export interface PolicySearchResult {
  id: number;
  content: string;
  metadata: Record<string, any>;
  similarity: number;
  organizationId: string | null;
}

export interface PolicySearchOptions {
  organizationId?: string;
  policyType?: string;
  limit?: number;
  minSimilarity?: number;
}

/**
 * Generate embedding for a query using OpenAI
 */
async function generateQueryEmbedding(query: string): Promise<number[]> {
  const response = await openaiForEmbeddings.embeddings.create({
    model: "text-embedding-ada-002",
    input: query,
  });
  return response.data[0].embedding;
}

/**
 * Search security policies using semantic similarity
 */
export async function searchPolicies(
  query: string,
  options: PolicySearchOptions = {}
): Promise<PolicySearchResult[]> {
  const { organizationId, policyType, limit = 5, minSimilarity = 0.7 } = options;

  console.log(`[RAG] Searching policies for: "${query.substring(0, 50)}..."`);
  
  // Generate embedding for the query
  const queryEmbedding = await generateQueryEmbedding(query);
  const embeddingStr = `[${queryEmbedding.join(",")}]`;

  // Build the query with cosine similarity
  // pgvector uses <=> for cosine distance (1 - similarity)
  const results = await db.execute(sql`
    SELECT 
      id,
      content,
      metadata,
      organization_id as "organizationId",
      1 - (embedding <=> ${embeddingStr}::vector) as similarity
    FROM security_policies
    WHERE embedding IS NOT NULL
    ${organizationId ? sql`AND (organization_id = ${organizationId} OR organization_id IS NULL)` : sql``}
    ${policyType ? sql`AND metadata->>'policyType' = ${policyType}` : sql``}
    ORDER BY embedding <=> ${embeddingStr}::vector
    LIMIT ${limit}
  `);

  // Filter by minimum similarity and format results
  const filteredResults = (results.rows as any[])
    .filter((row) => row.similarity >= minSimilarity)
    .map((row) => ({
      id: row.id,
      content: row.content,
      metadata: row.metadata || {},
      similarity: parseFloat(row.similarity),
      organizationId: row.organizationId,
    }));

  console.log(`[RAG] Found ${filteredResults.length} relevant policies (min similarity: ${minSimilarity})`);
  
  return filteredResults;
}

/**
 * Get policy context for AI agents
 * Returns formatted context string for injection into agent prompts
 */
export async function getPolicyContext(
  query: string,
  options: PolicySearchOptions = {}
): Promise<string> {
  const policies = await searchPolicies(query, { ...options, limit: 3 });
  
  if (policies.length === 0) {
    return "";
  }

  const contextParts = policies.map((policy, index) => {
    const type = policy.metadata.policyType || "general";
    const filename = policy.metadata.filename || "unknown";
    return `=== POLICY ${index + 1} (${type} - ${filename}, relevance: ${(policy.similarity * 100).toFixed(1)}%) ===
${policy.content}`;
  });

  return `
### RULES OF ENGAGEMENT CONTEXT ###
The following security policies are relevant to this assessment. You MUST comply with these rules:

${contextParts.join("\n\n")}

### END POLICY CONTEXT ###
`;
}

/**
 * Check if an action is permitted based on policies
 */
export async function checkPolicyCompliance(
  action: string,
  context: {
    targetType?: string;
    executionMode?: string;
    organizationId?: string;
  } = {}
): Promise<{
  permitted: boolean;
  relevantPolicies: PolicySearchResult[];
  reasoning: string;
}> {
  // Search for policies related to this action
  const relevantPolicies = await searchPolicies(
    `${action} ${context.targetType || ""} ${context.executionMode || ""}`,
    { organizationId: context.organizationId, limit: 5, minSimilarity: 0.6 }
  );

  if (relevantPolicies.length === 0) {
    return {
      permitted: true,
      relevantPolicies: [],
      reasoning: "No specific policies found for this action. Proceeding with default permissions.",
    };
  }

  // Use AI to determine if action is permitted based on policies
  const policyContext = relevantPolicies
    .map((p) => p.content)
    .join("\n---\n");

  const response = await openaiForChat.chat.completions.create({
    model: "gpt-4o",
    messages: [
      {
        role: "system",
        content: `You are a security policy compliance checker. Analyze if the proposed action is permitted based on the organization's security policies. Be strict about safety and compliance.`,
      },
      {
        role: "user",
        content: `Action: ${action}
Target Type: ${context.targetType || "unknown"}
Execution Mode: ${context.executionMode || "unknown"}

Relevant Policies:
${policyContext}

Is this action permitted? Respond with JSON:
{
  "permitted": true/false,
  "reasoning": "explanation of why this is or is not permitted"
}`,
      },
    ],
    response_format: { type: "json_object" },
  });

  const result = JSON.parse(response.choices[0].message.content || "{}");

  return {
    permitted: result.permitted ?? true,
    relevantPolicies,
    reasoning: result.reasoning || "Unable to determine compliance.",
  };
}

/**
 * Get all policies for an organization (for management UI)
 */
export async function listPolicies(
  organizationId?: string,
  policyType?: string
): Promise<Array<{
  id: number;
  content: string;
  metadata: Record<string, any> | null;
  organizationId: string | null;
  createdAt: Date | null;
}>> {
  const conditions = [];
  
  if (organizationId) {
    conditions.push(eq(securityPolicies.organizationId, organizationId));
  }
  
  if (policyType) {
    conditions.push(sql`metadata->>'policyType' = ${policyType}`);
  }

  const results = await db
    .select({
      id: securityPolicies.id,
      content: securityPolicies.content,
      metadata: securityPolicies.metadata,
      organizationId: securityPolicies.organizationId,
      createdAt: securityPolicies.createdAt,
    })
    .from(securityPolicies)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(securityPolicies.createdAt));

  return results;
}

/**
 * Delete a policy by ID
 */
export async function deletePolicy(id: number): Promise<boolean> {
  const result = await db
    .delete(securityPolicies)
    .where(eq(securityPolicies.id, id));
  
  return true;
}

/**
 * Get policy statistics
 */
export async function getPolicyStats(organizationId?: string): Promise<{
  totalPolicies: number;
  byType: Record<string, number>;
  lastUpdated: Date | null;
}> {
  const baseQuery = organizationId
    ? sql`WHERE organization_id = ${organizationId} OR organization_id IS NULL`
    : sql``;

  const countResult = await db.execute(sql`
    SELECT COUNT(*) as count FROM security_policies ${baseQuery}
  `);

  const typeResult = await db.execute(sql`
    SELECT 
      COALESCE(metadata->>'policyType', 'other') as policy_type,
      COUNT(*) as count
    FROM security_policies
    ${baseQuery}
    GROUP BY metadata->>'policyType'
  `);

  const lastUpdatedResult = await db.execute(sql`
    SELECT MAX(updated_at) as last_updated FROM security_policies ${baseQuery}
  `);

  const byType: Record<string, number> = {};
  for (const row of typeResult.rows as any[]) {
    byType[row.policy_type] = parseInt(row.count);
  }

  return {
    totalPolicies: parseInt((countResult.rows[0] as any)?.count || "0"),
    byType,
    lastUpdated: (lastUpdatedResult.rows[0] as any)?.last_updated || null,
  };
}
