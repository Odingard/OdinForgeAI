/**
 * useLaunchReadiness — fetches the launch readiness report for a completed run.
 */

import { useQuery } from "@tanstack/react-query";
import type { LaunchReadinessReport } from "@/types/launch-readiness";

export function useLaunchReadiness(runId: string | null | undefined) {
  const { data, isLoading, error } = useQuery<LaunchReadinessReport>({
    queryKey: ["/api/launch-readiness", runId],
    queryFn: async () => {
      const token = localStorage.getItem("odinforge_access_token");
      const res = await fetch(`/api/launch-readiness/${runId}`, {
        credentials: "include",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    enabled: !!runId,
    staleTime: 60_000,
  });

  return { report: data ?? null, isLoading, error };
}
