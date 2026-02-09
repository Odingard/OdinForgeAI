import { useQuery } from "@tanstack/react-query";

export interface CoverageMetrics {
  assetCoverage: {
    totalActiveAssets: number;
    assetsEvaluatedLast30d: number;
    coveragePercent: number;
  };
  techniqueCoverage: {
    totalTactics: number;
    tacticsExercised: number;
    coveragePercent: number;
    uniqueTechniqueIds: number;
  };
  tacticalBreakdown: Array<{
    tactic: string;
    displayName: string;
    techniqueCount: number;
    covered: boolean;
  }>;
}

export interface CoverageGaps {
  staleAssets: Array<{
    id: string;
    assetIdentifier: string;
    displayName: string | null;
    assetType: string;
    lastEvaluatedAt: string | null;
    daysSinceEvaluation: number | null;
  }>;
  untestedTactics: Array<{
    tactic: string;
    displayName: string;
  }>;
  totalGaps: number;
}

export function useCoverageMetrics() {
  return useQuery<CoverageMetrics>({
    queryKey: ["/api/aev-coverage"],
    refetchInterval: 60000,
  });
}

export function useCoverageGaps() {
  return useQuery<CoverageGaps>({
    queryKey: ["/api/aev-coverage/gaps"],
    refetchInterval: 60000,
  });
}
