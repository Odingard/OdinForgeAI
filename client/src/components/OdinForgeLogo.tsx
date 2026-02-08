import { Shield } from "lucide-react";
import { cn } from "@/lib/utils";

interface OdinForgeLogoProps {
  size?: "sm" | "md" | "lg" | "xl";
  animated?: boolean;
  showIcon?: boolean;
  className?: string;
}

export function OdinForgeLogo({
  size = "md",
  animated = true,
  showIcon = true,
  className
}: OdinForgeLogoProps) {
  const sizeConfig = {
    sm: { text: "text-lg", icon: "h-5 w-5", iconPadding: "p-1.5" },
    md: { text: "text-xl", icon: "h-6 w-6", iconPadding: "p-2" },
    lg: { text: "text-2xl", icon: "h-7 w-7", iconPadding: "p-2.5" },
    xl: { text: "text-3xl", icon: "h-8 w-8", iconPadding: "p-3" },
  };

  const config = sizeConfig[size];

  return (
    <div className={cn("flex items-center gap-3", className)}>
      {showIcon && (
        <div className="relative">
          {/* Outer glow ring */}
          <div className={cn(
            "absolute inset-0 rounded-lg",
            animated && "glow-red-sm animate-pulse"
          )} />

          {/* Icon container */}
          <div className={cn(
            "relative rounded-lg bg-gradient-to-br from-red-600 to-red-500 border border-red-400/30",
            config.iconPadding,
            animated && "hover:scale-110 transition-transform duration-300"
          )}>
            <Shield className={cn(config.icon, "text-white relative z-10")} />
          </div>
        </div>
      )}

      <div className={cn("flex items-center gap-2 font-bold", config.text)}>
        <span className={cn(
          "relative",
          animated ? "text-neon-red" : "text-red-500"
        )}>
          Odin
        </span>
        <span className={cn(
          "relative",
          animated ? "text-neon-cyan" : "text-cyan-500"
        )}>
          Forge
        </span>
        {animated && (
          <div className="relative ml-1">
            <span className="absolute -inset-1 bg-gradient-to-r from-red-500/20 via-cyan-500/20 to-red-500/20 blur-sm animate-pulse rounded" />
            <span className="relative text-xs px-2 py-0.5 rounded glass border border-cyan-500/30 text-cyan-400 font-medium uppercase tracking-wider">
              AI
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
