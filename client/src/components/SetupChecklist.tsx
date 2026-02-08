import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { CheckCircle2, Circle, ChevronDown, ChevronUp, ExternalLink } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { useDemoDataStatus, useLoadDemoData } from "@/hooks/useDemoData";
import { useQuery } from "@tanstack/react-query";

interface ChecklistItem {
  id: string;
  title: string;
  description: string;
  completed: boolean;
  action?: {
    label: string;
    href?: string;
    onClick?: () => void;
  };
}

export function SetupChecklist() {
  const [isOpen, setIsOpen] = useState(true);
  const { data: demoStatus } = useDemoDataStatus();
  const loadDemoData = useLoadDemoData();

  // Check various setup states
  const { data: agents } = useQuery({ queryKey: ["/api/agents"] });
  const { data: cloudConnections } = useQuery({ queryKey: ["/api/cloud-connections"] });
  const { data: evaluations } = useQuery({ queryKey: ["/api/aev/evaluations"] });

  const checklistItems: ChecklistItem[] = [
    {
      id: "demo",
      title: "Load Demo Data",
      description: "Explore features with sample data",
      completed: demoStatus?.hasDemoData || false,
      action: {
        label: "Load Demo Data",
        onClick: () => loadDemoData.mutate(),
      },
    },
    {
      id: "cloud",
      title: "Connect Cloud Provider",
      description: "Link AWS, Azure, or GCP for asset discovery",
      completed: (cloudConnections as any[])?.length > 0,
      action: {
        label: "Add Connection",
        href: "/infrastructure",
      },
    },
    {
      id: "agents",
      title: "Deploy Agents",
      description: "Install agents on servers for monitoring",
      completed: (agents as any[])?.length > 0,
      action: {
        label: "Deploy Agents",
        href: "/agents",
      },
    },
    {
      id: "evaluation",
      title: "Run First Evaluation",
      description: "Start automated security testing",
      completed: (evaluations as any[])?.length > 0,
      action: {
        label: "Run Evaluation",
        href: "/full-assessment",
      },
    },
    {
      id: "compliance",
      title: "Configure Compliance",
      description: "Set up compliance framework monitoring",
      completed: false,
      action: {
        label: "Configure",
        href: "/compliance",
      },
    },
  ];

  const completedCount = checklistItems.filter(item => item.completed).length;
  const progress = (completedCount / checklistItems.length) * 100;
  const allComplete = completedCount === checklistItems.length;

  if (allComplete) {
    return null; // Hide when everything is complete
  }

  return (
    <Card className="border-primary/20 bg-card/50">
      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <CardTitle className="text-lg flex items-center gap-2">
                Getting Started
                {!allComplete && (
                  <span className="text-xs font-normal text-muted-foreground">
                    ({completedCount}/{checklistItems.length})
                  </span>
                )}
              </CardTitle>
              <CardDescription>
                Complete these steps to get the most out of OdinForge-AI
              </CardDescription>
            </div>
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="sm">
                {isOpen ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </Button>
            </CollapsibleTrigger>
          </div>
          <Progress value={progress} className="mt-3" />
        </CardHeader>

        <CollapsibleContent>
          <CardContent className="space-y-3 pt-0">
            {checklistItems.map((item) => (
              <div
                key={item.id}
                className="flex items-start gap-3 p-3 rounded-lg border border-border hover:bg-muted/30 transition-colors"
              >
                <div className="shrink-0 mt-0.5">
                  {item.completed ? (
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                  ) : (
                    <Circle className="h-5 w-5 text-muted-foreground" />
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="font-medium text-sm">{item.title}</div>
                  <div className="text-xs text-muted-foreground">{item.description}</div>
                </div>

                {!item.completed && item.action && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="shrink-0"
                    onClick={item.action.onClick}
                    asChild={!!item.action.href}
                  >
                    {item.action.href ? (
                      <a href={item.action.href}>
                        {item.action.label}
                        <ExternalLink className="h-3 w-3 ml-1" />
                      </a>
                    ) : (
                      <span>{item.action.label}</span>
                    )}
                  </Button>
                )}
              </div>
            ))}
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}
