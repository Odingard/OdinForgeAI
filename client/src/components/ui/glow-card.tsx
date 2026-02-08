import * as React from "react";
import { cn } from "@/lib/utils";

export interface GlowCardProps extends React.HTMLAttributes<HTMLDivElement> {
  glowColor?: "red" | "cyan" | "green" | "purple" | "none";
  glowIntensity?: "sm" | "md" | "lg";
  glass?: boolean;
  animated?: boolean;
  scanLine?: boolean;
}

const GlowCard = React.forwardRef<HTMLDivElement, GlowCardProps>(
  (
    {
      className,
      glowColor = "red",
      glowIntensity = "md",
      glass = false,
      animated = false,
      scanLine = false,
      children,
      ...props
    },
    ref
  ) => {
    const glowClass = React.useMemo(() => {
      if (glowColor === "none") return "";
      const intensity = glowIntensity === "sm" ? "-sm" : "";
      return `glow-${glowColor}${intensity}`;
    }, [glowColor, glowIntensity]);

    return (
      <div
        ref={ref}
        className={cn(
          "rounded-lg border transition-all duration-300",
          glass && "glass",
          glowClass,
          animated && "border-glow-animated",
          scanLine && "scan-line",
          className
        )}
        {...props}
      >
        {children}
      </div>
    );
  }
);
GlowCard.displayName = "GlowCard";

const GlowCardHeader = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex flex-col space-y-1.5 p-6", className)}
    {...props}
  />
));
GlowCardHeader.displayName = "GlowCardHeader";

const GlowCardTitle = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLHeadingElement>
>(({ className, children, ...props }, ref) => (
  <h3
    ref={ref}
    className={cn(
      "text-2xl font-semibold leading-none tracking-tight",
      className
    )}
    {...props}
  >
    {children}
  </h3>
));
GlowCardTitle.displayName = "GlowCardTitle";

const GlowCardDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn("text-sm text-muted-foreground", className)}
    {...props}
  />
));
GlowCardDescription.displayName = "GlowCardDescription";

const GlowCardContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn("p-6 pt-0", className)} {...props} />
));
GlowCardContent.displayName = "GlowCardContent";

const GlowCardFooter = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-center p-6 pt-0", className)}
    {...props}
  />
));
GlowCardFooter.displayName = "GlowCardFooter";

export {
  GlowCard,
  GlowCardHeader,
  GlowCardFooter,
  GlowCardTitle,
  GlowCardDescription,
  GlowCardContent,
};
