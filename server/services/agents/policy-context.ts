import { getPolicyContext, checkPolicyCompliance } from "../rag/policy-search";

export interface PolicyContextOptions {
  organizationId?: string;
  executionMode?: "safe" | "simulation" | "live";
  targetType?: string;
}

const POLICY_CONTEXT_TEMPLATE = `
### RULES OF ENGAGEMENT ###
You MUST follow these organizational security policies during this assessment.
Violating these policies is strictly prohibited.

`;

const DEFAULT_POLICY_REMINDER = `
### RULES OF ENGAGEMENT REMINDER ###
Follow standard penetration testing ethics and best practices:
- Only test authorized systems within scope
- Do not exfiltrate real customer data
- Report critical findings immediately
- Avoid denial of service conditions
- Respect rate limits and testing windows
`;

export async function getAgentPolicyContext(
  agentType: string,
  targetDescription: string,
  options: PolicyContextOptions = {}
): Promise<string> {
  const { organizationId, executionMode = "safe", targetType } = options;
  
  try {
    const query = `${agentType} security testing ${targetDescription} ${executionMode} mode permissions and restrictions`;
    
    const context = await getPolicyContext(query, {
      organizationId,
      limit: 3,
      minSimilarity: 0.6,
    });
    
    if (context && context.trim().length > 0) {
      return `${POLICY_CONTEXT_TEMPLATE}
Current Execution Mode: ${executionMode.toUpperCase()}
Target Type: ${targetType || "general"}

${context}

IMPORTANT: If any action would violate these policies, you must refuse and explain why.
`;
    }
    
    return `${DEFAULT_POLICY_REMINDER}
Current Execution Mode: ${executionMode.toUpperCase()}
`;
  } catch (error) {
    console.warn(`[PolicyContext] Failed to fetch policy context for ${agentType}:`, error);
    return `${DEFAULT_POLICY_REMINDER}
Current Execution Mode: ${executionMode.toUpperCase()}
`;
  }
}

export async function validateAgentAction(
  action: string,
  context: PolicyContextOptions = {}
): Promise<{
  permitted: boolean;
  reasoning: string;
}> {
  try {
    const result = await checkPolicyCompliance(action, {
      targetType: context.targetType,
      executionMode: context.executionMode,
      organizationId: context.organizationId,
    });
    
    return {
      permitted: result.permitted,
      reasoning: result.reasoning,
    };
  } catch (error) {
    console.warn("[PolicyContext] Failed to validate action:", error);
    return {
      permitted: true,
      reasoning: "Unable to validate against policies, proceeding with default permissions.",
    };
  }
}

export function formatExecutionModeConstraints(mode: "safe" | "simulation" | "live"): string {
  switch (mode) {
    case "safe":
      return `
SAFE MODE CONSTRAINTS:
- Only passive reconnaissance is permitted
- NO exploit execution
- NO credential testing
- NO fuzzing with payloads
- Report potential vulnerabilities without attempting exploitation
`;
    case "simulation":
      return `
SIMULATION MODE CONSTRAINTS:
- Exploit validation without actual exploitation
- Rate-limited scanning only
- NO persistence mechanisms
- All changes must be reversible
- Automatic rollback of any modifications
`;
    case "live":
      return `
LIVE MODE CONSTRAINTS:
- Full exploitation permitted with explicit authorization
- Active monitoring required during testing
- Immediate notification of successful exploits
- Complete evidence collection for all actions
- Exercise caution with destructive operations
`;
    default:
      return "";
  }
}
