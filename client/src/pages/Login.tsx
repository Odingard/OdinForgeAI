import { useState, useEffect, useRef } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { Lock, Mail, AlertCircle, Shield, Target, GitBranch, Activity } from "lucide-react";
import { ShieldValknut, OdinGardBrand } from "@/components/OdinForgeLogo";
import { useUIAuth } from "@/contexts/UIAuthContext";

const loginSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

type LoginFormData = z.infer<typeof loginSchema>;

interface LoginProps {
  onLoginSuccess: () => void;
}

// ── Animated background with floating threat indicators ──────────────────

function ThreatCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    let w = canvas.parentElement?.clientWidth || 800;
    let h = canvas.parentElement?.clientHeight || 900;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);

    // Nodes — simulated network topology
    interface TNode { x: number; y: number; vx: number; vy: number; r: number; color: string; pulse: number }
    const nodes: TNode[] = [];
    for (let i = 0; i < 18; i++) {
      nodes.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r: 2 + Math.random() * 2,
        color: ["#ef4444", "#38bdf8", "#a855f7", "#22c55e"][Math.floor(Math.random() * 4)],
        pulse: Math.random() * Math.PI * 2,
      });
    }

    let t = 0;
    let animId: number;

    function draw() {
      t += 0.008;
      ctx!.clearRect(0, 0, w, h);

      // Update nodes
      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < 0 || n.x > w) n.vx *= -1;
        if (n.y < 0 || n.y > h) n.vy *= -1;
        n.pulse += 0.02;
      }

      // Draw connections
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 200) {
            const alpha = (1 - dist / 200) * 0.08;
            ctx!.beginPath();
            ctx!.moveTo(nodes[i].x, nodes[i].y);
            ctx!.lineTo(nodes[j].x, nodes[j].y);
            ctx!.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
            ctx!.lineWidth = 0.5;
            ctx!.stroke();
          }
        }
      }

      // Draw nodes
      for (const n of nodes) {
        const pulseR = n.r + Math.sin(n.pulse) * 1;
        // Outer glow
        const grad = ctx!.createRadialGradient(n.x, n.y, 0, n.x, n.y, pulseR * 6);
        grad.addColorStop(0, n.color + "18");
        grad.addColorStop(1, "transparent");
        ctx!.fillStyle = grad;
        ctx!.beginPath();
        ctx!.arc(n.x, n.y, pulseR * 6, 0, Math.PI * 2);
        ctx!.fill();
        // Core
        ctx!.beginPath();
        ctx!.arc(n.x, n.y, pulseR, 0, Math.PI * 2);
        ctx!.fillStyle = n.color + "60";
        ctx!.fill();
      }

      // Scan line
      const scanY = (t * 80) % h;
      const scanGrad = ctx!.createLinearGradient(0, scanY - 40, 0, scanY + 40);
      scanGrad.addColorStop(0, "transparent");
      scanGrad.addColorStop(0.5, "rgba(56, 189, 248, 0.03)");
      scanGrad.addColorStop(1, "transparent");
      ctx!.fillStyle = scanGrad;
      ctx!.fillRect(0, scanY - 40, w, 80);

      animId = requestAnimationFrame(draw);
    }

    draw();

    const onResize = () => {
      w = canvas.parentElement?.clientWidth || 800;
      h = canvas.parentElement?.clientHeight || 900;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 pointer-events-none"
      style={{ width: "100%", height: "100%" }}
    />
  );
}

// ── Stat counter with rolling animation ──────────────────────────────────

function StatCounter({ label, value, suffix = "" }: { label: string; value: string; suffix?: string }) {
  return (
    <div className="text-center">
      <div className="text-2xl xl:text-3xl font-bold tracking-tight text-foreground">
        {value}<span className="text-cyan-400">{suffix}</span>
      </div>
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-1">{label}</div>
    </div>
  );
}

// ── Main Login Component ─────────────────────────────────────────────────

export default function Login({ onLoginSuccess }: LoginProps) {
  const { toast } = useToast();
  const { login } = useUIAuth();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const form = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  async function onSubmit(data: LoginFormData) {
    setIsSubmitting(true);
    setError(null);
    try {
      await login(data.email, data.password);
      toast({ title: "Welcome back", description: "You have successfully signed in." });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Login failed";
      setError(message);
      toast({ title: "Authentication failed", description: message, variant: "destructive" });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex bg-[#060910] relative overflow-hidden">
      {/* Left Panel — Hero */}
      <div className="hidden lg:flex lg:w-1/2 xl:w-[55%] relative flex-col justify-between p-12 xl:p-16">
        <ThreatCanvas />

        {/* Subtle grid overlay */}
        <div
          className="absolute inset-0 pointer-events-none opacity-[0.03]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(56,189,248,1) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,1) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />

        <div className="relative z-10">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-20">
            <div className="relative">
              <div className="absolute inset-0 rounded-xl blur-md" style={{ background: "rgba(239,68,68,0.2)" }} />
              <div className="relative rounded-xl bg-gradient-to-br from-red-600 to-red-700 border border-red-500/30 p-2.5 flex items-center justify-center">
                <ShieldValknut className="h-9 w-9 text-white" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-1.5 text-2xl font-bold tracking-tight">
                <span className="text-red-500">Odin</span>
                <span className="text-cyan-400">Forge</span>
              </div>
              <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500 font-medium">
                Adversarial Exposure Validation
              </div>
            </div>
          </div>

          {/* Hero copy */}
          <div className="max-w-xl">
            <h1 className="text-4xl xl:text-[3.25rem] font-extrabold tracking-tight leading-[1.08] mb-5">
              <span className="text-slate-100">Breach simulations</span>
              <br />
              <span className="text-slate-100">that prove </span>
              <span className="text-cyan-400">real risk.</span>
            </h1>
            <p className="text-base xl:text-lg text-slate-400 leading-relaxed max-w-md">
              Autonomous exploit agents chain vulnerabilities into full attack paths.
              Every finding ships with the HTTP evidence that confirms it.
            </p>
          </div>

          {/* Stats strip */}
          <div className="mt-14 flex items-center gap-8 xl:gap-12">
            <StatCounter value="6" suffix="-phase" label="Breach Chains" />
            <div className="h-8 w-px bg-slate-700/50" />
            <StatCounter value="12" suffix="-turn" label="Exploit Agent" />
            <div className="h-8 w-px bg-slate-700/50" />
            <StatCounter value="10" suffix="+" label="Vuln Classes" />
            <div className="h-8 w-px bg-slate-700/50" />
            <StatCounter value="100" suffix="%" label="Evidence-Backed" />
          </div>
        </div>

        {/* Capabilities strip */}
        <div className="relative z-10 mt-auto pt-16">
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            {[
              { icon: Target, label: "Exploit Verification", desc: "Proven payloads, not theory" },
              { icon: GitBranch, label: "Attack Path Mapping", desc: "Multi-phase breach chains" },
              { icon: Shield, label: "Defense Gap Analysis", desc: "See what your SOC missed" },
              { icon: Activity, label: "Live Breach Replay", desc: "Watch attacks unfold" },
            ].map((cap) => (
              <div key={cap.label} className="group">
                <div className="flex items-center gap-2 mb-1.5">
                  <cap.icon className="h-3.5 w-3.5 text-cyan-400/70" />
                  <span className="text-xs font-semibold text-slate-300">{cap.label}</span>
                </div>
                <span className="text-[11px] text-slate-500 leading-relaxed">{cap.desc}</span>
              </div>
            ))}
          </div>

          <div className="mt-8 pt-6 border-t border-slate-800/60 flex items-center gap-6">
            <OdinGardBrand size="sm" className="opacity-40" />
            <span className="h-3 w-px bg-slate-800" />
            <span className="text-[11px] text-slate-600">BSL 1.1 Licensed</span>
          </div>
        </div>
      </div>

      {/* Right Panel — Login Form */}
      <div className="flex-1 flex items-center justify-center relative z-10 p-6"
        style={{ background: "linear-gradient(135deg, rgba(6,9,16,0.97) 0%, rgba(10,15,25,0.98) 100%)" }}
      >
        {/* Subtle accent border on left edge */}
        <div className="hidden lg:block absolute left-0 top-0 bottom-0 w-px bg-gradient-to-b from-transparent via-cyan-500/20 to-transparent" />

        <div className="w-full max-w-[400px]">
          {/* Mobile logo */}
          <div className="lg:hidden text-center mb-10">
            <div className="inline-flex items-center gap-3 mb-3">
              <div className="rounded-xl bg-gradient-to-br from-red-600 to-red-700 border border-red-500/30 p-2 flex items-center justify-center">
                <ShieldValknut className="h-7 w-7 text-white" />
              </div>
              <div className="flex items-center gap-1.5 text-xl font-bold">
                <span className="text-red-500">Odin</span>
                <span className="text-cyan-400">Forge</span>
              </div>
            </div>
            <p className="text-sm text-slate-500">Adversarial Exposure Validation</p>
          </div>

          {/* Form card */}
          <div className="rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-xl p-8 shadow-2xl shadow-black/30">
            <div className="mb-7">
              <h2 className="text-xl font-bold tracking-tight text-slate-100">Sign in</h2>
              <p className="text-sm text-slate-500 mt-1">Access the control plane</p>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 mb-5 bg-red-500/8 border border-red-500/20 rounded-lg text-sm text-red-400">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
                <FormField control={form.control} name="email" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs font-medium text-slate-400 uppercase tracking-wider">Email</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-600" />
                        <Input
                          type="email"
                          placeholder="operator@company.com"
                          className="pl-10 h-11 bg-slate-800/40 border-slate-700/50 text-slate-200 placeholder:text-slate-600 focus:border-cyan-500/50 focus:ring-cyan-500/20 rounded-lg"
                          autoComplete="email"
                          data-testid="input-email"
                          {...field}
                        />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )} />

                <FormField control={form.control} name="password" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-xs font-medium text-slate-400 uppercase tracking-wider">Password</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-600" />
                        <Input
                          type="password"
                          placeholder="Enter your password"
                          className="pl-10 h-11 bg-slate-800/40 border-slate-700/50 text-slate-200 placeholder:text-slate-600 focus:border-cyan-500/50 focus:ring-cyan-500/20 rounded-lg"
                          autoComplete="current-password"
                          data-testid="input-password"
                          {...field}
                        />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )} />

                <Button
                  type="submit"
                  className="w-full h-11 text-sm font-semibold bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 border-0 shadow-lg shadow-red-900/20 rounded-lg"
                  disabled={isSubmitting}
                  data-testid="button-login"
                >
                  {isSubmitting ? (
                    <><div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />Signing in...</>
                  ) : "Sign in"}
                </Button>
              </form>
            </Form>

            <div className="mt-6 pt-5 border-t border-slate-800/60 text-center text-sm text-slate-500">
              Don't have an account?{" "}
              <a href="/signup" className="text-cyan-400 font-medium hover:text-cyan-300 transition-colors" data-testid="link-signup">Create one</a>
            </div>
          </div>

          <p className="text-center text-[11px] text-slate-600 mt-5">
            Multi-factor authentication &middot; Role-based access control
          </p>
        </div>
      </div>
    </div>
  );
}
