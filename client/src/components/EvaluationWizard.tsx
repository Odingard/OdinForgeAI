import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  evaluationTemplates,
  generateDescription,
  getExposureType,
  getPriorityFromAnswers,
  type TemplateCategory,
  type InfrastructureType,
} from "@/lib/evaluation-templates";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { AdversaryProfile } from "@shared/schema";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Globe,
  Database,
  Cloud,
  Box,
  Network,
  Users,
  Mail,
  Code,
  Server,
  Shield,
  Loader2,
  Sparkles,
  FileText,
  AlertTriangle,
  UserRound,
} from "lucide-react";

const adversaryProfileLabels: Record<AdversaryProfile, { label: string; description: string }> = {
  script_kiddie: { label: "Script Kiddie", description: "Low sophistication, uses public tools" },
  opportunistic_criminal: { label: "Opportunistic Criminal", description: "Moderate skill, seeks easy financial gains" },
  organized_crime: { label: "Organized Crime", description: "Well-funded criminal organization" },
  insider_threat: { label: "Insider Threat", description: "Trusted insider with legitimate access" },
  nation_state: { label: "Nation State", description: "State-sponsored with unlimited resources" },
  apt_group: { label: "APT Group", description: "Advanced Persistent Threat group" },
  hacktivist: { label: "Hacktivist", description: "Ideologically motivated attacker" },
  competitor: { label: "Competitor", description: "Corporate espionage actor" },
};

const categoryIcons: Record<string, typeof Globe> = {
  web_servers: Globe,
  databases: Database,
  cloud_storage: Cloud,
  containers: Box,
  network: Network,
  identity: Users,
  email: Mail,
  applications: Code,
};

const priorityColors: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
};

interface EvaluationWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type WizardStep = "category" | "type" | "version" | "questions" | "review";

export function EvaluationWizard({ open, onOpenChange }: EvaluationWizardProps) {
  const { toast } = useToast();
  const [step, setStep] = useState<WizardStep>("category");
  const [selectedCategory, setSelectedCategory] = useState<TemplateCategory | null>(null);
  const [selectedType, setSelectedType] = useState<InfrastructureType | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<string>("");
  const [answers, setAnswers] = useState<Record<string, string | string[]>>({});
  const [additionalContext, setAdditionalContext] = useState("");
  const [assetName, setAssetName] = useState("");
  const [adversaryProfile, setAdversaryProfile] = useState<string>("");

  const resetWizard = () => {
    setStep("category");
    setSelectedCategory(null);
    setSelectedType(null);
    setSelectedVersion("");
    setAnswers({});
    setAdditionalContext("");
    setAssetName("");
    setAdversaryProfile("");
  };

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      resetWizard();
    }
    onOpenChange(open);
  };

  const createEvaluationMutation = useMutation({
    mutationFn: async (data: {
      assetId: string;
      exposureType: string;
      priority: string;
      description: string;
      adversaryProfile?: string;
    }) => {
      const response = await apiRequest("POST", "/api/aev/evaluate", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
      toast({
        title: "Evaluation Started",
        description: "AI analysis is now running on your infrastructure component.",
      });
      handleOpenChange(false);
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleCategorySelect = (category: TemplateCategory) => {
    setSelectedCategory(category);
    setStep("type");
  };

  const handleTypeSelect = (type: InfrastructureType) => {
    setSelectedType(type);
    setStep("version");
  };

  const handleVersionSelect = (version: string) => {
    setSelectedVersion(version);
    setStep("questions");
  };

  const handleAnswerChange = (questionId: string, value: string | string[]) => {
    setAnswers(prev => ({ ...prev, [questionId]: value }));
  };

  const handleCheckboxChange = (questionId: string, value: string, checked: boolean) => {
    setAnswers(prev => {
      const current = (prev[questionId] as string[]) || [];
      if (checked) {
        return { ...prev, [questionId]: [...current, value] };
      } else {
        return { ...prev, [questionId]: current.filter(v => v !== value) };
      }
    });
  };

  const isQuestionsComplete = () => {
    if (!selectedType) return false;
    const requiredQuestions = selectedType.questions.filter(q => q.required);
    return requiredQuestions.every(q => {
      const answer = answers[q.id];
      if (Array.isArray(answer)) return answer.length > 0;
      return !!answer;
    });
  };

  const handleSubmit = () => {
    if (!selectedCategory || !selectedType) return;

    let description = generateDescription(
      selectedCategory,
      selectedType,
      selectedVersion,
      answers
    );

    if (additionalContext.trim()) {
      description += `\n\nAdditional Context:\n${additionalContext}`;
    }

    const assetId = assetName.trim() || `${selectedType.id}-${Date.now()}`;
    const exposureType = getExposureType(selectedCategory.id, selectedType.id);
    const priority = getPriorityFromAnswers(answers);

    createEvaluationMutation.mutate({
      assetId,
      exposureType,
      priority,
      description,
      adversaryProfile: adversaryProfile || undefined,
    });
  };

  const getStepProgress = (): number => {
    switch (step) {
      case "category": return 20;
      case "type": return 40;
      case "version": return 60;
      case "questions": return 80;
      case "review": return 100;
      default: return 0;
    }
  };

  const renderCategoryStep = () => (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Select the type of infrastructure you want to evaluate
      </p>
      <div className="grid grid-cols-2 gap-3">
        {evaluationTemplates.map((category) => {
          const Icon = categoryIcons[category.id] || Server;
          return (
            <Card
              key={category.id}
              className="cursor-pointer hover-elevate active-elevate-2 transition-colors"
              onClick={() => handleCategorySelect(category)}
              data-testid={`card-category-${category.id}`}
            >
              <CardHeader className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-md bg-primary/10">
                    <Icon className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-sm">{category.name}</CardTitle>
                    <CardDescription className="text-xs line-clamp-1">
                      {category.description}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
            </Card>
          );
        })}
      </div>
    </div>
  );

  const renderTypeStep = () => (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Select the specific {selectedCategory?.name.toLowerCase()} type
      </p>
      <ScrollArea className="h-[300px] pr-4">
        <div className="space-y-2">
          {selectedCategory?.types.map((type) => (
            <Card
              key={type.id}
              className="cursor-pointer hover-elevate active-elevate-2 transition-colors"
              onClick={() => handleTypeSelect(type)}
              data-testid={`card-type-${type.id}`}
            >
              <CardHeader className="p-4">
                <div className="flex items-center gap-3">
                  <Server className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <CardTitle className="text-sm">{type.name}</CardTitle>
                    <CardDescription className="text-xs">
                      {type.description}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
            </Card>
          ))}
        </div>
      </ScrollArea>
    </div>
  );

  const renderVersionStep = () => (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        What version of {selectedType?.name} is running?
      </p>
      <ScrollArea className="h-[300px] pr-4">
        <div className="space-y-2">
          {selectedType?.versions.map((version) => (
            <Card
              key={version.value}
              className="cursor-pointer hover-elevate active-elevate-2 transition-colors"
              onClick={() => handleVersionSelect(version.value)}
              data-testid={`card-version-${version.value}`}
            >
              <CardContent className="p-4 flex items-center justify-between">
                <span className="text-sm font-medium">{version.label}</span>
                {version.value.includes("EOL") && (
                  <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30">
                    End of Life
                  </Badge>
                )}
                {version.value.includes("CVE") && (
                  <Badge variant="outline" className="bg-orange-500/10 text-orange-400 border-orange-500/30">
                    Known CVEs
                  </Badge>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      </ScrollArea>
    </div>
  );

  const renderQuestionsStep = () => (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        Answer these questions to help analyze your {selectedType?.name}
      </p>
      <ScrollArea className="h-[350px] pr-4">
        <div className="space-y-6">
          {selectedType?.questions.map((question) => (
            <div key={question.id} className="space-y-3">
              <Label className="text-sm font-medium flex items-center gap-1">
                {question.label}
                {question.required && <span className="text-red-400">*</span>}
              </Label>
              
              {question.type === "radio" && question.options && (
                <RadioGroup
                  value={answers[question.id] as string || ""}
                  onValueChange={(value) => handleAnswerChange(question.id, value)}
                  className="space-y-2"
                >
                  {question.options.map((option) => (
                    <div key={option.value} className="flex items-center space-x-2">
                      <RadioGroupItem
                        value={option.value}
                        id={`${question.id}-${option.value}`}
                        data-testid={`radio-${question.id}-${option.value}`}
                      />
                      <Label
                        htmlFor={`${question.id}-${option.value}`}
                        className="text-sm font-normal cursor-pointer"
                      >
                        {option.label}
                      </Label>
                    </div>
                  ))}
                </RadioGroup>
              )}
              
              {question.type === "select" && question.options && (
                <Select
                  value={answers[question.id] as string || ""}
                  onValueChange={(value) => handleAnswerChange(question.id, value)}
                >
                  <SelectTrigger data-testid={`select-${question.id}`}>
                    <SelectValue placeholder="Select an option" />
                  </SelectTrigger>
                  <SelectContent>
                    {question.options.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
              
              {question.type === "checkbox" && question.options && (
                <div className="space-y-2">
                  {question.options.map((option) => (
                    <div key={option.value} className="flex items-center space-x-2">
                      <Checkbox
                        id={`${question.id}-${option.value}`}
                        checked={((answers[question.id] as string[]) || []).includes(option.value)}
                        onCheckedChange={(checked) =>
                          handleCheckboxChange(question.id, option.value, checked as boolean)
                        }
                        data-testid={`checkbox-${question.id}-${option.value}`}
                      />
                      <Label
                        htmlFor={`${question.id}-${option.value}`}
                        className="text-sm font-normal cursor-pointer"
                      >
                        {option.label}
                      </Label>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          
          <div className="space-y-3 pt-4 border-t">
            <Label className="text-sm font-medium">
              Asset Name (optional)
            </Label>
            <input
              type="text"
              value={assetName}
              onChange={(e) => setAssetName(e.target.value)}
              placeholder="e.g., prod-web-server-01"
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="input-asset-name"
            />
          </div>
          
          <div className="space-y-3">
            <Label className="text-sm font-medium">
              Additional Context (optional)
            </Label>
            <Textarea
              value={additionalContext}
              onChange={(e) => setAdditionalContext(e.target.value)}
              placeholder="Any additional details about this system, recent changes, or specific concerns..."
              className="min-h-[80px]"
              data-testid="textarea-additional-context"
            />
          </div>
          
          <div className="space-y-3 pt-4 border-t">
            <div className="flex items-center gap-2">
              <Label className="text-sm font-medium">Threat Actor Profile (optional)</Label>
              <Tooltip>
                <TooltipTrigger>
                  <UserRound className="h-3 w-3 text-muted-foreground" />
                </TooltipTrigger>
                <TooltipContent>
                  <p className="max-w-xs text-xs">Simulates attack from a specific threat actor type. The AI will adjust its tactics and techniques accordingly.</p>
                </TooltipContent>
              </Tooltip>
            </div>
            <Select
              value={adversaryProfile || "__none__"}
              onValueChange={(value) => setAdversaryProfile(value === "__none__" ? "" : value)}
            >
              <SelectTrigger data-testid="select-adversary-profile">
                <SelectValue placeholder="Default (balanced analysis)" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__none__">Default (balanced analysis)</SelectItem>
                {(Object.keys(adversaryProfileLabels) as AdversaryProfile[]).map((profile) => (
                  <SelectItem key={profile} value={profile} data-testid={`option-${profile}`}>
                    {adversaryProfileLabels[profile].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {adversaryProfile && (
              <p className="text-xs text-muted-foreground">
                {adversaryProfileLabels[adversaryProfile as AdversaryProfile]?.description}
              </p>
            )}
          </div>
        </div>
      </ScrollArea>
      
      <div className="flex justify-end">
        <Button
          onClick={() => setStep("review")}
          disabled={!isQuestionsComplete()}
          data-testid="btn-continue-to-review"
        >
          Continue to Review
          <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </div>
    </div>
  );

  const renderReviewStep = () => {
    if (!selectedCategory || !selectedType) return null;
    
    const description = generateDescription(
      selectedCategory,
      selectedType,
      selectedVersion,
      answers
    );
    const priority = getPriorityFromAnswers(answers);
    const exposureType = getExposureType(selectedCategory.id, selectedType.id);
    
    return (
      <div className="space-y-6">
        <div className="p-4 rounded-lg bg-muted/50 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-xs text-muted-foreground">Asset</p>
              <p className="font-medium">{assetName || `${selectedType.id}-${Date.now()}`}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Type</p>
              <p className="font-medium">{selectedType.name}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Version</p>
              <p className="font-medium">{selectedVersion}</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4 flex-wrap">
            <div>
              <p className="text-xs text-muted-foreground">Exposure Type</p>
              <Badge variant="outline">{exposureType}</Badge>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Auto-detected Priority</p>
              <Badge variant="outline" className={priorityColors[priority]}>
                {priority.charAt(0).toUpperCase() + priority.slice(1)}
              </Badge>
            </div>
            {adversaryProfile && (
              <div>
                <p className="text-xs text-muted-foreground">Threat Actor</p>
                <Badge variant="outline" className="bg-violet-500/10 text-violet-400 border-violet-500/30">
                  {adversaryProfileLabels[adversaryProfile as AdversaryProfile]?.label}
                </Badge>
              </div>
            )}
          </div>
        </div>
        
        <div className="space-y-2">
          <Label className="text-sm font-medium flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Generated Analysis Request
          </Label>
          <div className="p-3 rounded-lg bg-muted/30 border text-sm font-mono whitespace-pre-wrap max-h-[200px] overflow-auto">
            {description}
            {additionalContext && (
              <>
                {"\n\nAdditional Context:\n"}
                {additionalContext}
              </>
            )}
          </div>
        </div>
        
        <div className="flex items-center gap-2 p-3 rounded-lg bg-primary/5 border border-primary/20">
          <Sparkles className="h-5 w-5 text-primary" />
          <p className="text-sm">
            AI will analyze this configuration for vulnerabilities, attack vectors, and provide remediation recommendations.
          </p>
        </div>
      </div>
    );
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            {step === "category" && "New Security Evaluation"}
            {step === "type" && selectedCategory?.name}
            {step === "version" && selectedType?.name}
            {step === "questions" && `Configure ${selectedType?.name}`}
            {step === "review" && "Review & Start Evaluation"}
          </DialogTitle>
          <DialogDescription>
            {step === "category" && "Select an infrastructure category to begin"}
            {step === "type" && "Choose the specific component type"}
            {step === "version" && "Select the version running in your environment"}
            {step === "questions" && "Answer a few questions about your configuration"}
            {step === "review" && "Review the details and start the AI analysis"}
          </DialogDescription>
        </DialogHeader>
        
        <div className="py-2">
          <Progress value={getStepProgress()} className="h-1" />
        </div>
        
        <div className="flex-1 overflow-hidden">
          {step === "category" && renderCategoryStep()}
          {step === "type" && renderTypeStep()}
          {step === "version" && renderVersionStep()}
          {step === "questions" && renderQuestionsStep()}
          {step === "review" && renderReviewStep()}
        </div>
        
        <div className="flex items-center justify-between pt-4 border-t mt-4">
          <Button
            variant="ghost"
            onClick={() => {
              if (step === "type") setStep("category");
              else if (step === "version") setStep("type");
              else if (step === "questions") setStep("version");
              else if (step === "review") setStep("questions");
            }}
            disabled={step === "category" || createEvaluationMutation.isPending}
            data-testid="btn-wizard-back"
          >
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Button>
          
          {step === "review" && (
            <Button
              onClick={handleSubmit}
              disabled={createEvaluationMutation.isPending}
              data-testid="btn-start-evaluation"
            >
              {createEvaluationMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Starting...
                </>
              ) : (
                <>
                  <Sparkles className="mr-2 h-4 w-4" />
                  Start AI Evaluation
                </>
              )}
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
