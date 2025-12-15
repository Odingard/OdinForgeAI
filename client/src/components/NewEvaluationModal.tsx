import { useState } from "react";
import { X, Zap, Target, Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface NewEvaluationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: EvaluationFormData) => void;
}

export interface EvaluationFormData {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
}

export function NewEvaluationModal({ isOpen, onClose, onSubmit }: NewEvaluationModalProps) {
  const [formData, setFormData] = useState<EvaluationFormData>({
    assetId: "",
    exposureType: "cve",
    priority: "medium",
    description: "",
  });

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
    setFormData({ assetId: "", exposureType: "cve", priority: "medium", description: "" });
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div 
        className="bg-card border border-border rounded-xl w-full max-w-md shadow-2xl"
        data-testid="new-evaluation-modal"
      >
        <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 border-b border-border px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg">
                <Target className="h-5 w-5 text-white" />
              </div>
              <div>
                <h3 className="font-semibold text-foreground">New Evaluation</h3>
                <p className="text-xs text-muted-foreground">Start an autonomous exploit validation</p>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={onClose} data-testid="button-close-modal">
              <X className="h-4 w-4" />
            </Button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="space-y-2">
            <Label htmlFor="assetId" className="text-xs uppercase tracking-wider">
              Target Asset ID
            </Label>
            <Input
              id="assetId"
              placeholder="e.g., web-server-01, api-gateway"
              value={formData.assetId}
              onChange={(e) => setFormData({ ...formData, assetId: e.target.value })}
              className="font-mono"
              required
              data-testid="input-asset-id"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider">Exposure Type</Label>
              <Select
                value={formData.exposureType}
                onValueChange={(value) => setFormData({ ...formData, exposureType: value })}
              >
                <SelectTrigger data-testid="select-exposure-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="cve">CVE</SelectItem>
                  <SelectItem value="misconfiguration">Misconfiguration</SelectItem>
                  <SelectItem value="behavior">Behavioral</SelectItem>
                  <SelectItem value="network">Network</SelectItem>
                  <SelectItem value="business_logic">Business Logic</SelectItem>
                  <SelectItem value="api_abuse">API Abuse</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider">Priority</Label>
              <Select
                value={formData.priority}
                onValueChange={(value) => setFormData({ ...formData, priority: value })}
              >
                <SelectTrigger data-testid="select-priority">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="description" className="text-xs uppercase tracking-wider">
              Description
            </Label>
            <Textarea
              id="description"
              placeholder="Describe the exposure to be validated..."
              rows={3}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              required
              data-testid="input-description"
            />
          </div>

          <div className="flex items-start gap-2 p-3 bg-muted/30 rounded-lg border border-border">
            <Info className="h-4 w-4 text-cyan-400 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-muted-foreground">
              The AI will autonomously discover attack paths and chain exploits without predefined patterns.
            </p>
          </div>

          <Button
            type="submit"
            className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500"
            data-testid="button-start-evaluation"
          >
            <Zap className="h-4 w-4 mr-2" />
            Start Autonomous Evaluation
          </Button>
        </form>
      </div>
    </div>
  );
}
