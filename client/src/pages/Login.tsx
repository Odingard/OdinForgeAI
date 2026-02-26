import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { Lock, Mail, AlertCircle, Crosshair, Network, Zap, BarChart3 } from "lucide-react";
import { ShieldValknut } from "@/components/OdinForgeLogo";
import { useUIAuth } from "@/contexts/UIAuthContext";

const loginSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

type LoginFormData = z.infer<typeof loginSchema>;

interface LoginProps {
  onLoginSuccess: () => void;
}

function AnimatedGrid() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <div
        className="absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(56,189,248,1) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,1) 1px, transparent 1px)",
          backgroundSize: "60px 60px",
        }}
      />
      <div
        className="absolute rounded-full animate-pulse"
        style={{
          width: 500, height: 500, top: "-10%", left: "-10%",
          background: "radial-gradient(circle, rgba(239,68,68,0.08) 0%, transparent 70%)",
          filter: "blur(80px)",
        }}
      />
      <div
        className="absolute rounded-full animate-pulse"
        style={{
          width: 600, height: 600, bottom: "-15%", right: "-10%",
          background: "radial-gradient(circle, rgba(56,189,248,0.06) 0%, transparent 70%)",
          filter: "blur(80px)", animationDelay: "1s",
        }}
      />
      <div
        className="absolute rounded-full animate-pulse"
        style={{
          width: 300, height: 300, top: "40%", left: "30%",
          background: "radial-gradient(circle, rgba(139,92,246,0.04) 0%, transparent 70%)",
          filter: "blur(60px)", animationDelay: "2s",
        }}
      />
      <div className="scan-line absolute inset-0 opacity-20" />
    </div>
  );
}

function FeatureItem({ icon: Icon, title, description }: { icon: React.ComponentType<{ className?: string }>; title: string; description: string }) {
  return (
    <div className="flex items-start gap-3">
      <div className="mt-0.5 rounded-md bg-cyan-500/10 border border-cyan-500/20 p-2 shrink-0">
        <Icon className="h-4 w-4 text-cyan-400" />
      </div>
      <div>
        <div className="text-sm font-medium text-foreground">{title}</div>
        <div className="text-xs text-muted-foreground leading-relaxed">{description}</div>
      </div>
    </div>
  );
}

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
    <div className="min-h-screen flex bg-background relative">
      <AnimatedGrid />

      {/* Left Panel — Branding */}
      <div className="hidden lg:flex lg:w-1/2 xl:w-[55%] relative z-10 flex-col justify-between p-12">
        <div>
          <div className="flex items-center gap-3 mb-16">
            <div className="relative">
              <div className="absolute inset-0 rounded-lg glow-red-sm animate-pulse" />
              <div className="relative rounded-lg bg-gradient-to-br from-red-600 to-red-500 border border-red-400/30 p-2 flex items-center justify-center">
                <ShieldValknut className="h-8 w-8 text-white" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-1.5 text-2xl font-bold tracking-tight">
                <span className="text-red-500">Odin</span>
                <span className="text-cyan-400">Forge</span>
                <span className="ml-1.5 text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-semibold uppercase tracking-widest">AI</span>
              </div>
              <div className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-medium mt-0.5">
                Adversarial Exposure Validation
              </div>
            </div>
          </div>

          <div className="max-w-lg">
            <h1 className="text-4xl xl:text-5xl font-bold tracking-tight leading-[1.1] mb-4">
              Prove your defenses
              <br />
              <span className="text-cyan-400">before attackers do.</span>
            </h1>
            <p className="text-lg text-muted-foreground leading-relaxed mb-10">
              OdinForge finds vulnerabilities and proves they're exploitable.
              Every finding includes the HTTP request and response that confirm it.
            </p>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 max-w-xl">
            <FeatureItem icon={Crosshair} title="Exploit Agent" description="12-turn agentic loop with 7 tools. SQLi, XSS, SSRF, auth bypass — proven with payloads." />
            <FeatureItem icon={Network} title="Breach Chains" description="Multi-phase attack paths from app compromise to domain admin, with real-time graphs." />
            <FeatureItem icon={Zap} title="Recon Engine" description="8 scanning modules feed 6 verification agents that confirm what's actually exploitable." />
            <FeatureItem icon={BarChart3} title="Deterministic Scoring" description="EPSS + CVSS + exploitability. No LLM in the scoring loop — just real threat intel." />
          </div>
        </div>

        <div className="flex items-center gap-6 text-xs text-muted-foreground">
          <span>BSL 1.1 Licensed</span>
          <span className="h-3 w-px bg-border" />
          <span>Six Sense Enterprise Services LLC</span>
        </div>
      </div>

      {/* Right Panel — Login Form */}
      <div className="flex-1 flex items-center justify-center relative z-10 p-6">
        <div className="w-full max-w-[420px]">
          <div className="lg:hidden text-center mb-10">
            <div className="inline-flex items-center gap-3 mb-3">
              <div className="rounded-lg bg-gradient-to-br from-red-600 to-red-500 border border-red-400/30 p-1.5 flex items-center justify-center">
                <ShieldValknut className="h-7 w-7 text-white" />
              </div>
              <div className="flex items-center gap-1.5 text-xl font-bold">
                <span className="text-red-500">Odin</span>
                <span className="text-cyan-400">Forge</span>
                <span className="ml-1 text-[9px] px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-semibold uppercase tracking-widest">AI</span>
              </div>
            </div>
            <p className="text-sm text-muted-foreground">Adversarial Exposure Validation</p>
          </div>

          <div className="rounded-xl border border-border bg-card/80 backdrop-blur-sm p-8">
            <div className="mb-6">
              <h2 className="text-xl font-semibold tracking-tight">Sign in</h2>
              <p className="text-sm text-muted-foreground mt-1">Enter your credentials to access the control plane</p>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 mb-5 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
                <FormField control={form.control} name="email" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-sm font-medium">Email</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input type="email" placeholder="admin@example.com" className="pl-10 h-11 bg-background/50" autoComplete="email" data-testid="input-email" {...field} />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )} />

                <FormField control={form.control} name="password" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-sm font-medium">Password</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input type="password" placeholder="Enter your password" className="pl-10 h-11 bg-background/50" autoComplete="current-password" data-testid="input-password" {...field} />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )} />

                <Button type="submit" className="w-full h-11 text-sm font-medium" disabled={isSubmitting} data-testid="button-login">
                  {isSubmitting ? (
                    <><div className="h-4 w-4 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin mr-2" />Signing in...</>
                  ) : "Sign in"}
                </Button>
              </form>
            </Form>

            <div className="mt-6 pt-6 border-t border-border text-center text-sm text-muted-foreground">
              Don't have an account?{" "}
              <a href="/signup" className="text-primary font-medium hover:underline" data-testid="link-signup">Create one</a>
            </div>
          </div>

          <p className="text-center text-[11px] text-muted-foreground mt-6">
            Protected by multi-factor authentication and role-based access control
          </p>
        </div>
      </div>
    </div>
  );
}
