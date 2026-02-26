import { cn } from "@/lib/utils";

interface OdinForgeLogoProps {
  size?: "sm" | "md" | "lg" | "xl";
  animated?: boolean;
  showIcon?: boolean;
  className?: string;
}

/**
 * Shield + Valknut SVG icon matching the OdinGard brand mark.
 * Rendered inline so it scales with text and supports CSS color inheritance.
 */
function ShieldValknut({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 40 46"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {/* Shield outline */}
      <path
        d="M20 2L4 10V22C4 32.5 11 40 20 44C29 40 36 32.5 36 22V10L20 2Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      {/* Valknut — three interlocking triangles */}
      <path
        d="M20 12L14.5 22H25.5L20 12Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
        fill="none"
      />
      <path
        d="M15 27L20 18L25 27H15Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
        fill="none"
      />
      <path
        d="M12.5 22L20 32L27.5 22H12.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  );
}

export { ShieldValknut };

export function OdinForgeLogo({
  size = "md",
  animated = true,
  showIcon = true,
  className,
}: OdinForgeLogoProps) {
  const sizeConfig = {
    sm: { text: "text-lg", icon: "h-7 w-7", container: "h-8 w-8" },
    md: { text: "text-xl", icon: "h-8 w-8", container: "h-9 w-9" },
    lg: { text: "text-2xl", icon: "h-10 w-10", container: "h-11 w-11" },
    xl: { text: "text-3xl", icon: "h-12 w-12", container: "h-14 w-14" },
  };

  const config = sizeConfig[size];

  return (
    <div className={cn("flex items-center gap-3", className)}>
      {showIcon && (
        <div className="relative">
          {animated && (
            <div className="absolute inset-0 rounded-lg glow-red-sm animate-pulse" />
          )}
          <div
            className={cn(
              "relative rounded-lg bg-gradient-to-br from-red-600 to-red-500 border border-red-400/30 flex items-center justify-center",
              config.container,
              animated && "hover:scale-110 transition-transform duration-300",
            )}
          >
            <ShieldValknut className={cn(config.icon, "text-white")} />
          </div>
        </div>
      )}

      <div className={cn("flex items-center gap-1 font-bold tracking-tight", config.text)}>
        <span className={animated ? "text-neon-red" : "text-red-500"}>
          Odin
        </span>
        <span className={animated ? "text-neon-cyan" : "text-cyan-500"}>
          Forge
        </span>
      </div>
    </div>
  );
}
