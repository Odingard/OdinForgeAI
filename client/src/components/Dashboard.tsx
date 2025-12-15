import { useState } from "react";
import { 
  Zap, 
  Target, 
  ShieldCheck, 
  AlertTriangle, 
  Activity, 
  Play, 
  RefreshCw,
  Plus
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatCard } from "./StatCard";
import { FilterBar } from "./FilterBar";
import { EvaluationTable, Evaluation } from "./EvaluationTable";
import { NewEvaluationModal, EvaluationFormData } from "./NewEvaluationModal";
import { ProgressModal } from "./ProgressModal";
import { EvaluationDetail } from "./EvaluationDetail";

// todo: remove mock functionality
const mockEvaluations: Evaluation[] = [
  {
    id: "aev-001",
    assetId: "web-api-gateway",
    exposureType: "cve",
    priority: "critical",
    status: "completed",
    exploitable: true,
    score: 87,
    confidence: 0.92,
    createdAt: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: "aev-002",
    assetId: "auth-service",
    exposureType: "business_logic",
    priority: "high",
    status: "completed",
    exploitable: true,
    score: 72,
    confidence: 0.85,
    createdAt: new Date(Date.now() - 7200000).toISOString(),
  },
  {
    id: "aev-003",
    assetId: "payment-processor",
    exposureType: "api_abuse",
    priority: "critical",
    status: "in_progress",
    createdAt: new Date(Date.now() - 1800000).toISOString(),
  },
  {
    id: "aev-004",
    assetId: "db-cluster-01",
    exposureType: "misconfiguration",
    priority: "medium",
    status: "completed",
    exploitable: false,
    score: 28,
    confidence: 0.78,
    createdAt: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    id: "aev-005",
    assetId: "cdn-edge-node",
    exposureType: "network",
    priority: "low",
    status: "completed",
    exploitable: false,
    score: 15,
    confidence: 0.95,
    createdAt: new Date(Date.now() - 172800000).toISOString(),
  },
  {
    id: "aev-006",
    assetId: "user-session-mgr",
    exposureType: "behavior",
    priority: "high",
    status: "pending",
    createdAt: new Date(Date.now() - 600000).toISOString(),
  },
];

// todo: remove mock functionality
const mockDetailEvaluation = {
  id: "aev-001",
  assetId: "web-api-gateway",
  exposureType: "cve",
  priority: "critical",
  description: "CVE-2024-1234 - Critical remote code execution vulnerability in API gateway authentication module. The vulnerability allows unauthenticated attackers to execute arbitrary code via specially crafted HTTP headers.",
  status: "completed",
  exploitable: true,
  score: 87,
  confidence: 0.92,
  createdAt: new Date(Date.now() - 3600000).toISOString(),
  duration: 45000,
  attackPath: [
    {
      id: 1,
      title: "Initial Access via Malformed Header",
      description: "Exploit CVE-2024-1234 by sending crafted X-Forwarded-For header to bypass authentication",
      technique: "T1190",
      severity: "critical" as const,
    },
    {
      id: 2,
      title: "Privilege Escalation",
      description: "Leverage misconfigured IAM role to gain elevated permissions in the container runtime",
      technique: "T1068",
      severity: "high" as const,
    },
    {
      id: 3,
      title: "Lateral Movement to Database",
      description: "Use compromised service account credentials to access internal database cluster",
      technique: "T1021",
      severity: "high" as const,
    },
    {
      id: 4,
      title: "Data Exfiltration",
      description: "Extract sensitive customer PII and payment information via DNS tunneling",
      technique: "T1048",
      severity: "critical" as const,
    },
  ],
  recommendations: [
    {
      id: "rec-1",
      title: "Apply Security Patch",
      description: "Update API gateway to version 3.2.1 which includes the fix for CVE-2024-1234",
      priority: "critical" as const,
      type: "remediation" as const,
    },
    {
      id: "rec-2",
      title: "Restrict IAM Permissions",
      description: "Implement least-privilege access for container runtime service accounts",
      priority: "high" as const,
      type: "remediation" as const,
    },
    {
      id: "rec-3",
      title: "Enable WAF Rules",
      description: "Deploy web application firewall rules to block malformed header attacks",
      priority: "high" as const,
      type: "compensating" as const,
    },
    {
      id: "rec-4",
      title: "Network Segmentation",
      description: "Isolate API gateway from direct database access using network policies",
      priority: "medium" as const,
      type: "compensating" as const,
    },
  ],
};

export function Dashboard() {
  const [filter, setFilter] = useState("all");
  const [showNewModal, setShowNewModal] = useState(false);
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [activeEvaluation, setActiveEvaluation] = useState<{ assetId: string; id: string } | null>(null);
  const [selectedEvaluation, setSelectedEvaluation] = useState<typeof mockDetailEvaluation | null>(null);

  const evaluations = mockEvaluations;

  const filteredEvaluations = evaluations.filter((e) => {
    if (filter === "all") return true;
    if (filter === "pending") return e.status === "pending" || e.status === "in_progress";
    if (filter === "completed") return e.status === "completed";
    if (filter === "exploitable") return e.exploitable === true;
    if (filter === "safe") return e.exploitable === false;
    return true;
  });

  const stats = {
    total: evaluations.length,
    active: evaluations.filter((e) => e.status === "pending" || e.status === "in_progress").length,
    exploitable: evaluations.filter((e) => e.exploitable).length,
    safe: evaluations.filter((e) => e.exploitable === false).length,
    avgConfidence: Math.round(
      evaluations.filter(e => e.confidence).reduce((sum, e) => sum + (e.confidence || 0), 0) / 
      evaluations.filter(e => e.confidence).length * 100
    ) || 0,
  };

  const filterOptions = [
    { value: "all", label: "All", count: evaluations.length },
    { value: "pending", label: "Active", count: stats.active },
    { value: "completed", label: "Completed", count: evaluations.filter(e => e.status === "completed").length },
    { value: "exploitable", label: "Exploitable", count: stats.exploitable },
    { value: "safe", label: "Safe", count: stats.safe },
  ];

  const handleNewEvaluation = (data: EvaluationFormData) => {
    console.log("Starting evaluation:", data);
    setShowNewModal(false);
    setActiveEvaluation({ assetId: data.assetId, id: `aev-${Date.now()}` });
    setShowProgressModal(true);
  };

  const handleViewDetails = (evaluation: Evaluation) => {
    console.log("Viewing details:", evaluation.id);
    setSelectedEvaluation(mockDetailEvaluation);
  };

  const handleRunEvaluation = (evaluation: Evaluation) => {
    console.log("Re-running evaluation:", evaluation.id);
    setActiveEvaluation({ assetId: evaluation.assetId, id: evaluation.id });
    setShowProgressModal(true);
  };

  if (selectedEvaluation) {
    return (
      <EvaluationDetail 
        evaluation={selectedEvaluation} 
        onBack={() => setSelectedEvaluation(null)} 
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-xl font-bold text-foreground flex items-center gap-2 flex-wrap">
            AEV Dashboard
            <span className="text-xs font-medium px-2 py-0.5 rounded bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 border border-cyan-500/30">
              AUTONOMOUS VALIDATION
            </span>
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            AI-powered adversarial exposure validation with autonomous exploit chaining
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="outline" size="sm" data-testid="button-refresh">
            <RefreshCw className="h-3.5 w-3.5 mr-2" />
            Refresh
          </Button>
          <Button 
            size="sm"
            className="bg-gradient-to-r from-cyan-600 to-blue-600"
            onClick={() => setShowNewModal(true)}
            data-testid="button-new-evaluation"
          >
            <Plus className="h-3.5 w-3.5 mr-2" />
            New Evaluation
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <StatCard 
          label="Total Evaluations" 
          value={stats.total} 
          icon={Target}
          trend={{ value: 12, isPositive: true }}
        />
        <StatCard 
          label="Active" 
          value={stats.active} 
          icon={Activity}
          colorClass="text-amber-400"
        />
        <StatCard 
          label="Exploitable" 
          value={stats.exploitable} 
          icon={AlertTriangle}
          colorClass="text-red-400"
          trend={{ value: 5, isPositive: false }}
        />
        <StatCard 
          label="Safe" 
          value={stats.safe} 
          icon={ShieldCheck}
          colorClass="text-emerald-400"
        />
        <StatCard 
          label="Avg Confidence" 
          value={`${stats.avgConfidence}%`} 
          icon={Zap}
          colorClass="text-cyan-400"
        />
      </div>

      <FilterBar 
        options={filterOptions} 
        activeFilter={filter} 
        onFilterChange={setFilter} 
      />

      <EvaluationTable 
        evaluations={filteredEvaluations}
        onViewDetails={handleViewDetails}
        onRunEvaluation={handleRunEvaluation}
      />

      <NewEvaluationModal 
        isOpen={showNewModal}
        onClose={() => setShowNewModal(false)}
        onSubmit={handleNewEvaluation}
      />

      <ProgressModal 
        isOpen={showProgressModal}
        onClose={() => setShowProgressModal(false)}
        assetId={activeEvaluation?.assetId || ""}
        evaluationId={activeEvaluation?.id || ""}
      />
    </div>
  );
}
