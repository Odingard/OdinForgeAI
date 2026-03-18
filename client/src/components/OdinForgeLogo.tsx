import { cn } from "@/lib/utils";

interface OdinForgeLogoProps {
  size?: "sm" | "md" | "lg" | "xl";
  animated?: boolean;
  showIcon?: boolean;
  className?: string;
}

/**
 * Shield + Valknut SVG icon matching the OdinGard Security brand mark.
 * Three interlocking triangles inside a pointed shield.
 * Rendered inline so it scales with text and supports CSS color inheritance.
 */
function ShieldValknut({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 40 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {/* Shield — pointed bottom, flat top */}
      <path
        d="M20 2L3 10V24C3 34 10.5 41.5 20 46C29.5 41.5 37 34 37 24V10L20 2Z"
        fill="currentColor"
        fillOpacity="0.1"
        stroke="currentColor"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      {/* Valknut — three interlocking triangles */}
      {/* Top triangle */}
      <path
        d="M20 11L14 21H26L20 11Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
        fill="none"
      />
      {/* Bottom-left triangle */}
      <path
        d="M14 28L20 18L26 28H14Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
        fill="none"
      />
      {/* Bottom-right triangle */}
      <path
        d="M11 22L20 34L29 22H11Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  );
}

export { ShieldValknut };

/**
 * OdinGard Security parent brand wordmark.
 * Shield icon + "ODINGARD" text — used in login/signup and footer contexts.
 */
export function OdinGardBrand({
  size = "md",
  className,
}: {
  size?: "sm" | "md" | "lg";
  className?: string;
}) {
  const sizeConfig = {
    sm: { icon: "h-5 w-5", text: "text-sm", gap: "gap-1.5" },
    md: { icon: "h-7 w-7", text: "text-lg", gap: "gap-2" },
    lg: { icon: "h-9 w-9", text: "text-2xl", gap: "gap-2.5" },
  };
  const config = sizeConfig[size];

  return (
    <div className={cn("flex items-center", config.gap, className)}>
      <ShieldValknut className={cn(config.icon, "text-slate-300")} />
      <span className={cn(config.text, "font-bold tracking-widest text-slate-300")} style={{ letterSpacing: "0.15em" }}>
        ODINGARD
      </span>
    </div>
  );
}

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
