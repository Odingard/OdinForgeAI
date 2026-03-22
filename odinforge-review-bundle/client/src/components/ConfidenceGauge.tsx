import { motion } from "framer-motion";

interface ConfidenceGaugeProps {
  confidence: number;
  label?: string;
  size?: "sm" | "md" | "lg";
}

export function ConfidenceGauge({ 
  confidence, 
  label = "Confidence", 
  size = "md" 
}: ConfidenceGaugeProps) {
  const sizeClasses = {
    sm: { container: "w-24 h-12", text: "text-lg", label: "text-[10px]" },
    md: { container: "w-32 h-16", text: "text-2xl", label: "text-xs" },
    lg: { container: "w-40 h-20", text: "text-3xl", label: "text-sm" },
  };

  const classes = sizeClasses[size];

  const getColor = () => {
    if (confidence >= 90) return { stroke: "stroke-red-500", text: "text-red-400", glow: "drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]" };
    if (confidence >= 75) return { stroke: "stroke-orange-500", text: "text-orange-400", glow: "drop-shadow-[0_0_8px_rgba(249,115,22,0.5)]" };
    if (confidence >= 50) return { stroke: "stroke-amber-500", text: "text-amber-400", glow: "drop-shadow-[0_0_8px_rgba(245,158,11,0.5)]" };
    if (confidence >= 25) return { stroke: "stroke-emerald-500", text: "text-emerald-400", glow: "drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]" };
    return { stroke: "stroke-blue-500", text: "text-blue-400", glow: "drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]" };
  };

  const colors = getColor();
  
  const radius = 45;
  const strokeWidth = 8;
  const normalizedRadius = radius - strokeWidth / 2;
  const circumference = normalizedRadius * Math.PI;
  const strokeDashoffset = circumference - (confidence / 100) * circumference;

  return (
    <div className="flex flex-col items-center" data-testid="confidence-gauge">
      <div className={`${classes.container} relative`}>
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 50">
          <path
            d={`M 5,50 A ${normalizedRadius},${normalizedRadius} 0 0,1 95,50`}
            fill="none"
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-muted/30"
          />
          <motion.path
            d={`M 5,50 A ${normalizedRadius},${normalizedRadius} 0 0,1 95,50`}
            fill="none"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            className={`${colors.stroke} ${colors.glow}`}
            initial={{ strokeDasharray: circumference, strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1, ease: "easeOut" }}
          />
        </svg>
        <div className="absolute inset-0 flex items-end justify-center pb-1">
          <motion.span
            className={`${classes.text} font-bold ${colors.text}`}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {confidence}%
          </motion.span>
        </div>
      </div>
      <span className={`${classes.label} text-muted-foreground mt-1`}>{label}</span>
    </div>
  );
}
