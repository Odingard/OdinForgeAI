/**
 * Business Logic Attack Framework
 * 
 * Modules for testing business logic vulnerabilities including:
 * - IDOR (Insecure Direct Object Reference)
 * - Race conditions
 * - Price/quantity manipulation
 * - Workflow bypass
 * - Mass assignment
 */

export { BusinessLogicEngine } from "./engine";
export { IdorTestModule } from "./idor-tests";
export { RaceConditionModule } from "./race-conditions";
export { WorkflowBypassModule } from "./workflow-bypass";
export type { BusinessLogicScenario, ScenarioResult } from "./engine";
