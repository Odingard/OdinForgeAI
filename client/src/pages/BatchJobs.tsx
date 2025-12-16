import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { 
  Layers, 
  Plus, 
  Trash2, 
  Loader2, 
  CheckCircle2, 
  XCircle, 
  Clock,
  Server,
  AlertTriangle,
  Play,
} from "lucide-react";
import { format } from "date-fns";
import type { BatchJob } from "@shared/schema";

const exposureTypes = [
  { value: "cve", label: "CVE Vulnerability" },
  { value: "misconfiguration", label: "Misconfiguration" },
  { value: "behavioral_anomaly", label: "Behavioral Anomaly" },
  { value: "network_vulnerability", label: "Network Vulnerability" },
  { value: "cloud_misconfiguration", label: "Cloud Misconfiguration" },
  { value: "iam_abuse", label: "IAM Abuse" },
  { value: "saas_permission", label: "SaaS Permission Abuse" },
  { value: "api_sequence_abuse", label: "API Sequence Abuse" },
  { value: "payment_flow", label: "Payment Flow" },
  { value: "subscription_bypass", label: "Subscription Bypass" },
  { value: "state_machine", label: "State Machine Violation" },
];

const priorities = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

interface AssetConfig {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
}

export default function BatchJobs() {
  const { toast } = useToast();
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [jobName, setJobName] = useState("");
  const [jobDescription, setJobDescription] = useState("");
  const [assets, setAssets] = useState<AssetConfig[]>([
    { assetId: "", exposureType: "cve", priority: "medium", description: "" }
  ]);

  const { data: jobs = [], isLoading } = useQuery<BatchJob[]>({
    queryKey: ["/api/batch-jobs"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await apiRequest("POST", "/api/batch-jobs", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/batch-jobs"] });
      setIsCreateOpen(false);
      setJobName("");
      setJobDescription("");
      setAssets([{ assetId: "", exposureType: "cve", priority: "medium", description: "" }]);
      toast({
        title: "Batch job started",
        description: "Your batch evaluation has been queued",
      });
    },
    onError: (error) => {
      toast({
        title: "Failed to create batch job",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/batch-jobs/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/batch-jobs"] });
      toast({
        title: "Batch job deleted",
        description: "Batch job has been removed",
      });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("PATCH", `/api/batch-jobs/${id}`, { status: "failed" });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/batch-jobs"] });
      toast({
        title: "Batch job stopped",
        description: "Batch job has been cancelled",
      });
    },
  });

  const addAsset = () => {
    setAssets([...assets, { assetId: "", exposureType: "cve", priority: "medium", description: "" }]);
  };

  const removeAsset = (index: number) => {
    if (assets.length > 1) {
      setAssets(assets.filter((_, i) => i !== index));
    }
  };

  const updateAsset = (index: number, field: keyof AssetConfig, value: string) => {
    const newAssets = [...assets];
    newAssets[index] = { ...newAssets[index], [field]: value };
    setAssets(newAssets);
  };

  const handleCreate = () => {
    const validAssets = assets.filter(a => a.assetId && a.description);
    if (!jobName || validAssets.length === 0) {
      toast({
        title: "Validation error",
        description: "Please provide a job name and at least one valid asset configuration",
        variant: "destructive",
      });
      return;
    }
    createMutation.mutate({
      name: jobName,
      description: jobDescription,
      assets: validAssets,
    });
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "completed":
        return <Badge variant="default" className="bg-green-500/20 text-green-400 border-green-500/30"><CheckCircle2 className="w-3 h-3 mr-1" />Completed</Badge>;
      case "running":
        return <Badge variant="secondary" className="bg-blue-500/20 text-blue-400 border-blue-500/30"><Loader2 className="w-3 h-3 mr-1 animate-spin" />Running</Badge>;
      case "pending":
        return <Badge variant="outline"><Clock className="w-3 h-3 mr-1" />Pending</Badge>;
      case "failed":
        return <Badge variant="destructive"><XCircle className="w-3 h-3 mr-1" />Failed</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold" data-testid="text-batch-title">Batch Evaluations</h1>
          <p className="text-muted-foreground">Run multiple security assessments in parallel</p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button data-testid="btn-create-batch">
              <Plus className="w-4 h-4 mr-2" />
              New Batch Job
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Batch Evaluation</DialogTitle>
              <DialogDescription>Configure multiple assets for parallel security assessment</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Job Name</Label>
                  <Input
                    value={jobName}
                    onChange={(e) => setJobName(e.target.value)}
                    placeholder="Weekly infrastructure scan"
                    data-testid="input-job-name"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Description (Optional)</Label>
                  <Input
                    value={jobDescription}
                    onChange={(e) => setJobDescription(e.target.value)}
                    placeholder="Regular security assessment"
                    data-testid="input-job-description"
                  />
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label>Assets to Evaluate</Label>
                  <Button variant="outline" size="sm" onClick={addAsset} data-testid="btn-add-asset">
                    <Plus className="w-3 h-3 mr-1" />
                    Add Asset
                  </Button>
                </div>
                
                {assets.map((asset, index) => (
                  <Card key={index} className="relative" data-testid={`card-asset-${index}`}>
                    <CardContent className="p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">Asset {index + 1}</span>
                        {assets.length > 1 && (
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => removeAsset(index)}
                            data-testid={`btn-remove-asset-${index}`}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-1">
                          <Label className="text-xs">Asset ID</Label>
                          <Input
                            value={asset.assetId}
                            onChange={(e) => updateAsset(index, "assetId", e.target.value)}
                            placeholder="server-001, api.example.com"
                            data-testid={`input-asset-id-${index}`}
                          />
                        </div>
                        <div className="space-y-1">
                          <Label className="text-xs">Exposure Type</Label>
                          <Select 
                            value={asset.exposureType} 
                            onValueChange={(v) => updateAsset(index, "exposureType", v)}
                          >
                            <SelectTrigger data-testid={`select-exposure-${index}`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {exposureTypes.map((et) => (
                                <SelectItem key={et.value} value={et.value}>{et.label}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-1">
                          <Label className="text-xs">Priority</Label>
                          <Select 
                            value={asset.priority} 
                            onValueChange={(v) => updateAsset(index, "priority", v)}
                          >
                            <SelectTrigger data-testid={`select-priority-${index}`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {priorities.map((p) => (
                                <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-1">
                          <Label className="text-xs">Description</Label>
                          <Input
                            value={asset.description}
                            onChange={(e) => updateAsset(index, "description", e.target.value)}
                            placeholder="Brief description..."
                            data-testid={`input-asset-desc-${index}`}
                          />
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreateOpen(false)}>Cancel</Button>
              <Button 
                onClick={handleCreate} 
                disabled={createMutation.isPending}
                data-testid="btn-confirm-create"
              >
                {createMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                <Play className="w-4 h-4 mr-2" />
                Start Batch Job
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </CardContent>
        </Card>
      ) : jobs.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Layers className="w-12 h-12 text-muted-foreground mb-4" />
            <h3 className="font-medium mb-2">No batch jobs yet</h3>
            <p className="text-muted-foreground text-sm mb-4">
              Create a batch job to evaluate multiple assets in parallel
            </p>
            <Button onClick={() => setIsCreateOpen(true)} data-testid="btn-create-first">
              <Plus className="w-4 h-4 mr-2" />
              Create Batch Job
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {jobs.map((job) => (
            <Card key={job.id} data-testid={`card-batch-${job.id}`}>
              <CardContent className="p-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-4 flex-wrap">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-primary/10 rounded-md">
                        <Server className="w-4 h-4" />
                      </div>
                      <div>
                        <h3 className="font-medium">{job.name}</h3>
                        <p className="text-sm text-muted-foreground">
                          {job.description || `${job.totalEvaluations} asset${job.totalEvaluations !== 1 ? "s" : ""} queued`}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {getStatusBadge(job.status)}
                      {job.status === "running" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => cancelMutation.mutate(job.id)}
                          disabled={cancelMutation.isPending}
                          data-testid={`btn-cancel-batch-${job.id}`}
                        >
                          <XCircle className="w-3 h-3 mr-1" />
                          Stop
                        </Button>
                      )}
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => deleteMutation.mutate(job.id)}
                        disabled={deleteMutation.isPending}
                        data-testid={`btn-delete-batch-${job.id}`}
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                  
                  {(job.status === "running" || job.status === "completed") && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">Progress</span>
                        <span>
                          {job.completedEvaluations || 0} / {job.totalEvaluations} completed
                          {(job.failedEvaluations ?? 0) > 0 && (
                            <span className="text-destructive ml-2">
                              ({job.failedEvaluations} failed)
                            </span>
                          )}
                        </span>
                      </div>
                      <Progress value={job.progress || 0} className="h-2" />
                    </div>
                  )}
                  
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span>Created: {job.createdAt ? format(new Date(job.createdAt), "MMM d, yyyy HH:mm") : "Unknown"}</span>
                    {job.completedAt && (
                      <span>Completed: {format(new Date(job.completedAt), "MMM d, yyyy HH:mm")}</span>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
