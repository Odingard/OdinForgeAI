import * as React from "react";
import { X, CheckCircle2, AlertTriangle, AlertCircle, Info, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import { useSound } from "@/lib/sounds";

type ToastType = "success" | "error" | "warning" | "info" | "scan";

interface CyberToastProps {
  id: string;
  type: ToastType;
  title: string;
  description?: string;
  duration?: number;
  onClose: () => void;
}

const toastConfig = {
  success: {
    icon: CheckCircle2,
    color: "text-green-400",
    bg: "from-green-500/10 to-emerald-500/10",
    border: "border-green-500/30",
    glow: "glow-green-sm",
    sound: "success" as const,
  },
  error: {
    icon: AlertCircle,
    color: "text-red-400",
    bg: "from-red-500/10 to-orange-500/10",
    border: "border-red-500/30",
    glow: "glow-red-sm pulse-glow",
    sound: "error" as const,
  },
  warning: {
    icon: AlertTriangle,
    color: "text-amber-400",
    bg: "from-amber-500/10 to-yellow-500/10",
    border: "border-amber-500/30",
    glow: "glow-purple-sm",
    sound: "warning" as const,
  },
  info: {
    icon: Info,
    color: "text-cyan-400",
    bg: "from-cyan-500/10 to-blue-500/10",
    border: "border-cyan-500/30",
    glow: "glow-cyan-sm",
    sound: "notification" as const,
  },
  scan: {
    icon: Zap,
    color: "text-purple-400",
    bg: "from-purple-500/10 to-pink-500/10",
    border: "border-purple-500/30",
    glow: "glow-purple-sm",
    sound: "scan" as const,
  },
};

export function CyberToast({ id, type, title, description, duration = 5000, onClose }: CyberToastProps) {
  const config = toastConfig[type];
  const Icon = config.icon;
  const sound = useSound();
  const [isExiting, setIsExiting] = React.useState(false);

  React.useEffect(() => {
    // Play sound when toast appears
    sound.play(config.sound);

    // Auto-dismiss after duration
    if (duration > 0) {
      const timer = setTimeout(() => {
        setIsExiting(true);
        setTimeout(onClose, 300); // Wait for exit animation
      }, duration);
      return () => clearTimeout(timer);
    }
  }, [duration, onClose, sound, config.sound]);

  const handleClose = () => {
    setIsExiting(true);
    setTimeout(onClose, 300);
  };

  return (
    <div
      className={cn(
        "glass border rounded-lg p-4 min-w-[300px] max-w-[400px]",
        "transition-all duration-300 scan-line",
        config.border,
        config.glow,
        isExiting ? "opacity-0 translate-x-full" : "opacity-100 translate-x-0",
        "animate-in slide-in-from-right"
      )}
    >
      <div className="flex gap-3">
        {/* Icon */}
        <div className={cn(
          "p-2 rounded-lg bg-gradient-to-br shrink-0",
          config.bg,
          config.border,
          "border"
        )}>
          <Icon className={cn("h-5 w-5", config.color)} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <p className={cn("font-semibold text-sm", config.color)}>{title}</p>
          {description && (
            <p className="text-xs text-muted-foreground mt-1">{description}</p>
          )}
        </div>

        {/* Close button */}
        <button
          onClick={handleClose}
          className="shrink-0 p-1 rounded hover:bg-muted/50 transition-colors"
        >
          <X className="h-4 w-4 text-muted-foreground" />
        </button>
      </div>

      {/* Progress bar */}
      {duration > 0 && (
        <div className="mt-3 h-1 bg-muted/30 rounded-full overflow-hidden">
          <div
            className={cn(
              "h-full bg-gradient-to-r",
              type === "success" && "from-green-500 to-emerald-500",
              type === "error" && "from-red-500 to-orange-500",
              type === "warning" && "from-amber-500 to-yellow-500",
              type === "info" && "from-cyan-500 to-blue-500",
              type === "scan" && "from-purple-500 to-pink-500"
            )}
            style={{
              animation: `shrink ${duration}ms linear forwards`,
            }}
          />
        </div>
      )}
    </div>
  );
}

// Toast container component
export function CyberToastContainer() {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      <div className="pointer-events-auto">
        {/* Toasts will be rendered here */}
      </div>
    </div>
  );
}

// Toast context and hooks
interface Toast {
  id: string;
  type: ToastType;
  title: string;
  description?: string;
  duration?: number;
}

const ToastContext = React.createContext<{
  toasts: Toast[];
  showToast: (toast: Omit<Toast, "id">) => void;
  removeToast: (id: string) => void;
} | null>(null);

export function CyberToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([]);

  const showToast = React.useCallback((toast: Omit<Toast, "id">) => {
    const id = Math.random().toString(36).substring(7);
    setToasts((prev) => [...prev, { ...toast, id }]);
  }, []);

  const removeToast = React.useCallback((id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, showToast, removeToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map((toast) => (
          <div key={toast.id} className="pointer-events-auto">
            <CyberToast {...toast} onClose={() => removeToast(toast.id)} />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useCyberToast() {
  const context = React.useContext(ToastContext);
  if (!context) {
    throw new Error("useCyberToast must be used within CyberToastProvider");
  }
  return context;
}

// Add keyframe animation to global CSS
const style = document.createElement("style");
style.textContent = `
  @keyframes shrink {
    from { width: 100%; }
    to { width: 0%; }
  }
`;
document.head.appendChild(style);
