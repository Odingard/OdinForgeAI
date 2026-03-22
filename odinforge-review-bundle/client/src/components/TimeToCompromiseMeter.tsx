import { motion } from "framer-motion";
import { Clock, Zap, AlertTriangle, Shield } from "lucide-react";

interface TimeToCompromiseMeterProps {
  expected: number;
  minimum: number;
  maximum: number;
  unit: "minutes" | "hours" | "days";
}

export function TimeToCompromiseMeter({ 
  expected, 
  minimum, 
  maximum, 
  unit 
}: TimeToCompromiseMeterProps) {
  const normalizedHours = unit === "minutes" ? expected / 60 : unit === "days" ? expected * 24 : expected;
  
  const getUrgencyLevel = () => {
    if (normalizedHours < 1) return { level: "critical", color: "red", label: "Immediate" };
    if (normalizedHours < 4) return { level: "high", color: "orange", label: "Urgent" };
    if (normalizedHours < 24) return { level: "medium", color: "amber", label: "Moderate" };
    return { level: "low", color: "emerald", label: "Extended" };
  };

  const urgency = getUrgencyLevel();
  
  const maxDisplay = Math.max(maximum, expected * 1.5);
  const expectedPercent = Math.min((expected / maxDisplay) * 100, 100);
  const minPercent = (minimum / maxDisplay) * 100;
  const maxPercent = (maximum / maxDisplay) * 100;

  const colorClasses = {
    red: {
      bg: "bg-red-500",
      bgFaded: "bg-red-500/20",
      text: "text-red-400",
      border: "border-red-500/30",
      glow: "shadow-red-500/20",
    },
    orange: {
      bg: "bg-orange-500",
      bgFaded: "bg-orange-500/20",
      text: "text-orange-400",
      border: "border-orange-500/30",
      glow: "shadow-orange-500/20",
    },
    amber: {
      bg: "bg-amber-500",
      bgFaded: "bg-amber-500/20",
      text: "text-amber-400",
      border: "border-amber-500/30",
      glow: "shadow-amber-500/20",
    },
    emerald: {
      bg: "bg-emerald-500",
      bgFaded: "bg-emerald-500/20",
      text: "text-emerald-400",
      border: "border-emerald-500/30",
      glow: "shadow-emerald-500/20",
    },
  };

  const colors = colorClasses[urgency.color as keyof typeof colorClasses];

  const getIcon = () => {
    switch (urgency.level) {
      case "critical": return <Zap className="h-5 w-5" />;
      case "high": return <AlertTriangle className="h-5 w-5" />;
      case "medium": return <Clock className="h-5 w-5" />;
      default: return <Shield className="h-5 w-5" />;
    }
  };

  return (
    <div className="space-y-4" data-testid="time-to-compromise-meter">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${colors.bgFaded} ${colors.text}`}>
            {getIcon()}
          </div>
          <div>
            <h4 className="font-medium text-foreground">Time to Compromise</h4>
            <p className="text-xs text-muted-foreground">Estimated exploitation timeframe</p>
          </div>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-bold ${colors.text}`}>
            {expected} <span className="text-sm font-normal">{unit}</span>
          </div>
          <div className={`text-xs ${colors.text} flex items-center gap-1 justify-end`}>
            {getIcon()}
            {urgency.label}
          </div>
        </div>
      </div>

      <div className="relative h-8">
        <div className="absolute inset-0 rounded-full bg-muted/50 overflow-hidden">
          <div
            className={`absolute left-0 top-0 h-full ${colors.bgFaded} transition-all duration-300`}
            style={{ width: `${maxPercent}%` }}
          />
          <div
            className="absolute left-0 top-0 h-full bg-muted/30 transition-all duration-300"
            style={{ left: `${minPercent}%`, width: `${maxPercent - minPercent}%` }}
          />
        </div>
        
        <motion.div
          className="absolute top-1/2 -translate-y-1/2 w-4 h-4"
          style={{ left: `${expectedPercent}%`, marginLeft: -8 }}
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ delay: 0.5, type: "spring" }}
        >
          <div className={`w-full h-full rounded-full ${colors.bg} shadow-lg ${colors.glow} ring-2 ring-background`} />
        </motion.div>

        <div className="absolute bottom-[-20px] left-0 text-[10px] text-muted-foreground">
          {minimum}{unit.charAt(0)}
        </div>
        <div 
          className="absolute bottom-[-20px] text-[10px] text-muted-foreground"
          style={{ left: `${expectedPercent}%`, transform: "translateX(-50%)" }}
        >
          <span className={colors.text}>{expected}{unit.charAt(0)}</span>
        </div>
        <div className="absolute bottom-[-20px] right-0 text-[10px] text-muted-foreground">
          {maximum}{unit.charAt(0)}
        </div>
      </div>

      <div className="pt-4 grid grid-cols-4 gap-2 text-center text-xs">
        <div className={`p-2 rounded-md ${urgency.level === "critical" ? colors.bgFaded + " " + colors.border + " border" : "bg-muted/30"}`}>
          <span className={urgency.level === "critical" ? colors.text : "text-muted-foreground"}>Immediate</span>
          <div className="text-[10px] text-muted-foreground mt-0.5">&lt;1h</div>
        </div>
        <div className={`p-2 rounded-md ${urgency.level === "high" ? colors.bgFaded + " " + colors.border + " border" : "bg-muted/30"}`}>
          <span className={urgency.level === "high" ? colors.text : "text-muted-foreground"}>Urgent</span>
          <div className="text-[10px] text-muted-foreground mt-0.5">1-4h</div>
        </div>
        <div className={`p-2 rounded-md ${urgency.level === "medium" ? colors.bgFaded + " " + colors.border + " border" : "bg-muted/30"}`}>
          <span className={urgency.level === "medium" ? colors.text : "text-muted-foreground"}>Moderate</span>
          <div className="text-[10px] text-muted-foreground mt-0.5">4-24h</div>
        </div>
        <div className={`p-2 rounded-md ${urgency.level === "low" ? colors.bgFaded + " " + colors.border + " border" : "bg-muted/30"}`}>
          <span className={urgency.level === "low" ? colors.text : "text-muted-foreground"}>Extended</span>
          <div className="text-[10px] text-muted-foreground mt-0.5">&gt;24h</div>
        </div>
      </div>
    </div>
  );
}
