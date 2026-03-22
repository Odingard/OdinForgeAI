import { useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useLoadDemoData } from "@/hooks/useDemoData";
import {
  Cloud,
  Shield,
  FileText,
  FlaskConical,
  CheckCircle2,
  ArrowRight,
  Sparkles,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

interface OnboardingWizardProps {
  open: boolean;
  onClose: () => void;
}

const steps = [
  {
    id: "welcome",
    title: "Welcome to OdinForge-AI",
    description: "Your complete security automation platform",
    icon: Sparkles,
  },
  {
    id: "demo-data",
    title: "Explore with Demo Data",
    description: "Load sample data to explore all features",
    icon: FlaskConical,
  },
  {
    id: "setup",
    title: "Or Set Up Your Environment",
    description: "Connect your infrastructure and start securing",
    icon: Cloud,
  },
];

export function OnboardingWizard({ open, onClose }: OnboardingWizardProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const loadDemoData = useLoadDemoData();

  const progress = ((currentStep + 1) / steps.length) * 100;
  const step = steps[currentStep];
  const Icon = step.icon;

  const handleLoadDemo = async () => {
    await loadDemoData.mutateAsync();
    onClose();
  };

  const handleSkipToSetup = () => {
    onClose();
    // Could navigate to settings page or show setup wizard
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="text-2xl flex items-center gap-2">
            <Icon className="h-6 w-6 text-primary" />
            {step.title}
          </DialogTitle>
          <DialogDescription>{step.description}</DialogDescription>
        </DialogHeader>

        <Progress value={progress} className="mb-6" />

        <div className="space-y-6">
          {currentStep === 0 && (
            <div className="space-y-4">
              <p className="text-muted-foreground">
                OdinForge-AI helps you automate security testing, vulnerability assessments, and compliance monitoring across your entire infrastructure.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                <Card className="bg-muted/30">
                  <CardContent className="pt-6 text-center">
                    <Shield className="h-8 w-8 mx-auto mb-3 text-cyan-400" />
                    <h4 className="font-medium mb-2">Security Testing</h4>
                    <p className="text-xs text-muted-foreground">
                      Automated penetration testing and vulnerability scanning
                    </p>
                  </CardContent>
                </Card>

                <Card className="bg-muted/30">
                  <CardContent className="pt-6 text-center">
                    <FileText className="h-8 w-8 mx-auto mb-3 text-green-400" />
                    <h4 className="font-medium mb-2">Compliance</h4>
                    <p className="text-xs text-muted-foreground">
                      SOC2, ISO27001, NIST, and more compliance frameworks
                    </p>
                  </CardContent>
                </Card>

                <Card className="bg-muted/30">
                  <CardContent className="pt-6 text-center">
                    <Cloud className="h-8 w-8 mx-auto mb-3 text-purple-400" />
                    <h4 className="font-medium mb-2">Cloud Security</h4>
                    <p className="text-xs text-muted-foreground">
                      AWS, Azure, GCP asset discovery and protection
                    </p>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}

          {currentStep === 1 && (
            <div className="space-y-4">
              <p className="text-muted-foreground">
                Not ready to connect your infrastructure yet? Try OdinForge-AI with demo data to:
              </p>

              <ul className="space-y-3">
                {[
                  "Explore all features with realistic sample data",
                  "See security evaluations, agent monitoring, and compliance dashboards",
                  "Test workflows without connecting real systems",
                  "Clear demo data anytime with one click",
                ].map((item, index) => (
                  <li key={index} className="flex items-start gap-3">
                    <CheckCircle2 className="h-5 w-5 text-green-500 shrink-0 mt-0.5" />
                    <span className="text-sm">{item}</span>
                  </li>
                ))}
              </ul>

              <Button
                onClick={handleLoadDemo}
                disabled={loadDemoData.isPending}
                size="lg"
                className="w-full mt-6"
              >
                <FlaskConical className="h-4 w-4 mr-2" />
                {loadDemoData.isPending ? "Loading..." : "Load Demo Data"}
              </Button>
            </div>
          )}

          {currentStep === 2 && (
            <div className="space-y-4">
              <p className="text-muted-foreground">
                Ready to secure your actual infrastructure? Here's how to get started:
              </p>

              <ol className="space-y-4">
                {[
                  {
                    title: "Connect Cloud Providers",
                    description: "Link your AWS, Azure, or GCP accounts for asset discovery",
                  },
                  {
                    title: "Deploy Agents",
                    description: "Install lightweight agents on servers for continuous monitoring",
                  },
                  {
                    title: "Run First Evaluation",
                    description: "Start automated security testing on your infrastructure",
                  },
                  {
                    title: "Review Findings",
                    description: "Analyze results and prioritize remediation efforts",
                  },
                ].map((step, index) => (
                  <li key={index} className="flex items-start gap-3">
                    <div className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/20 text-primary text-sm font-medium shrink-0">
                      {index + 1}
                    </div>
                    <div>
                      <div className="font-medium text-sm">{step.title}</div>
                      <div className="text-xs text-muted-foreground">{step.description}</div>
                    </div>
                  </li>
                ))}
              </ol>

              <Button onClick={handleSkipToSetup} size="lg" className="w-full mt-6">
                Go to Setup
                <ArrowRight className="h-4 w-4 ml-2" />
              </Button>
            </div>
          )}
        </div>

        <div className="flex items-center justify-between mt-6 pt-6 border-t">
          <Button
            variant="outline"
            onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
            disabled={currentStep === 0}
          >
            Previous
          </Button>

          <div className="flex items-center gap-2">
            {steps.map((_, index) => (
              <div
                key={index}
                className={`w-2 h-2 rounded-full ${
                  index === currentStep
                    ? "bg-primary"
                    : index < currentStep
                    ? "bg-primary/50"
                    : "bg-muted"
                }`}
              />
            ))}
          </div>

          {currentStep < steps.length - 1 ? (
            <Button onClick={() => setCurrentStep(currentStep + 1)}>
              Next
              <ArrowRight className="h-4 w-4 ml-2" />
            </Button>
          ) : (
            <Button onClick={onClose} variant="outline">
              Close
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
