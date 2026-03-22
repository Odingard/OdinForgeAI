import * as React from "react";
import { cn } from "@/lib/utils";

export interface HolographicCardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "intense" | "subtle";
  animated?: boolean;
  scanLine?: boolean;
  borderGlow?: boolean;
}

const HolographicCard = React.forwardRef<HTMLDivElement, HolographicCardProps>(
  (
    {
      className,
      variant = "default",
      animated = true,
      scanLine = true,
      borderGlow = true,
      children,
      ...props
    },
    ref
  ) => {
    return (
      <div
        ref={ref}
        className={cn(
          "relative rounded-lg border transition-all duration-300",
          "glass border-border/50",
          animated && "holographic",
          scanLine && "scan-line",
          borderGlow && "hover:border-cyan-500/50",
          className
        )}
        {...props}
      >
        {/* Holographic shimmer overlay */}
        {animated && (
          <div className="absolute inset-0 rounded-lg pointer-events-none overflow-hidden">
            <div
              className="absolute inset-0 opacity-30"
              style={{
                background: `
                  linear-gradient(
                    135deg,
                    transparent 0%,
                    rgba(239, 68, 68, 0.1) 10%,
                    rgba(6, 182, 212, 0.15) 25%,
                    rgba(139, 92, 246, 0.15) 50%,
                    rgba(6, 182, 212, 0.1) 75%,
                    rgba(239, 68, 68, 0.1) 90%,
                    transparent 100%
                  )
                `,
                backgroundSize: "200% 200%",
                animation: "holographic-shift 10s ease infinite",
              }}
            />
          </div>
        )}

        {/* Border glow effect */}
        {borderGlow && (
          <div className="absolute -inset-[1px] rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none">
            <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-red-500/20 via-cyan-500/30 to-purple-500/20 blur-sm" />
          </div>
        )}

        {/* Content */}
        <div className="relative z-10">{children}</div>
      </div>
    );
  }
);
HolographicCard.displayName = "HolographicCard";

const HolographicCardHeader = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex flex-col space-y-1.5 p-6", className)}
    {...props}
  />
));
HolographicCardHeader.displayName = "HolographicCardHeader";

const HolographicCardTitle = React.forwardRef<
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
HolographicCardTitle.displayName = "HolographicCardTitle";

const HolographicCardDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn("text-sm text-muted-foreground", className)}
    {...props}
  />
));
HolographicCardDescription.displayName = "HolographicCardDescription";

const HolographicCardContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn("p-6 pt-0", className)} {...props} />
));
HolographicCardContent.displayName = "HolographicCardContent";

const HolographicCardFooter = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-center p-6 pt-0", className)}
    {...props}
  />
));
HolographicCardFooter.displayName = "HolographicCardFooter";

export {
  HolographicCard,
  HolographicCardHeader,
  HolographicCardFooter,
  HolographicCardTitle,
  HolographicCardDescription,
  HolographicCardContent,
};
