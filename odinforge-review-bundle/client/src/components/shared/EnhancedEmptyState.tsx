import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useLoadDemoData } from "@/hooks/useDemoData";
import { FlaskConical, LucideIcon } from "lucide-react";
import { ReactNode } from "react";

export interface EnhancedEmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  primaryAction?: {
    label: string;
    onClick: () => void;
    icon?: LucideIcon;
  };
  showDemoButton?: boolean;
  steps?: string[];
  previewImage?: string;
  children?: ReactNode;
}

/**
 * Enhanced empty state component with demo data loading capability
 * Provides better UX for pages with no data
 */
export function EnhancedEmptyState({
  icon: Icon,
  title,
  description,
  primaryAction,
  showDemoButton = true,
  steps,
  previewImage,
  children,
}: EnhancedEmptyStateProps) {
  const loadDemoData = useLoadDemoData();

  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-12 text-center">
        {/* Icon */}
        <div className="mb-4 rounded-full bg-muted/30 p-3">
          <Icon className="h-12 w-12 text-muted-foreground opacity-50" />
        </div>

        {/* Title & Description */}
        <h3 className="text-lg font-semibold mb-2">{title}</h3>
        <p className="text-sm text-muted-foreground mb-6 max-w-md">
          {description}
        </p>

        {/* Preview Image */}
        {previewImage && (
          <div className="mb-6 rounded-lg border border-border overflow-hidden max-w-2xl w-full">
            <img
              src={previewImage}
              alt="Feature preview"
              className="w-full h-auto"
            />
          </div>
        )}

        {/* Getting Started Steps */}
        {steps && steps.length > 0 && (
          <Card className="bg-muted/30 mb-6 max-w-md w-full">
            <CardContent className="pt-4">
              <div className="text-xs font-semibold text-muted-foreground mb-3 uppercase tracking-wider">
                Getting Started
              </div>
              <ol className="space-y-2 text-sm text-left">
                {steps.map((step, index) => (
                  <li key={index} className="flex items-start gap-2">
                    <span className="flex items-center justify-center w-5 h-5 rounded-full bg-primary/10 text-primary text-xs font-medium shrink-0 mt-0.5">
                      {index + 1}
                    </span>
                    <span className="text-muted-foreground">{step}</span>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        )}

        {/* Custom Content */}
        {children}

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row items-center gap-3 mt-4">
          {primaryAction && (
            <Button onClick={primaryAction.onClick} size="lg">
              {primaryAction.icon && <primaryAction.icon className="h-4 w-4 mr-2" />}
              {primaryAction.label}
            </Button>
          )}

          {showDemoButton && (
            <Button
              variant="outline"
              size="lg"
              onClick={() => loadDemoData.mutate()}
              disabled={loadDemoData.isPending}
            >
              <FlaskConical className="h-4 w-4 mr-2" />
              {loadDemoData.isPending ? "Loading..." : "Try with Demo Data"}
            </Button>
          )}
        </div>

        {showDemoButton && (
          <p className="text-xs text-muted-foreground mt-3">
            Demo data is perfect for exploring features and testing workflows
          </p>
        )}
      </CardContent>
    </Card>
  );
}
