import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { Lock, Mail, User, AlertCircle, Crosshair, Network, Zap, BarChart3 } from "lucide-react";
import { ShieldValknut, OdinGardBrand } from "@/components/OdinForgeLogo";
import { useUIAuth } from "@/contexts/UIAuthContext";
import { Link } from "wouter";

const signupSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  displayName: z.string().min(2, "Display name must be at least 2 characters").max(128),
  password: z.string().min(8, "Password must be at least 8 characters"),
  confirmPassword: z.string().min(8, "Please confirm your password"),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

type SignupFormData = z.infer<typeof signupSchema>;

interface SignupProps {
  onSignupSuccess: () => void;
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

export default function Signup({ onSignupSuccess }: SignupProps) {
  const { toast } = useToast();
  const { register } = useUIAuth();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const form = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: { email: "", displayName: "", password: "", confirmPassword: "" },
  });

  async function onSubmit(data: SignupFormData) {
    setIsSubmitting(true);
    setError(null);
    try {
      await register(data.email, data.password, data.displayName);
      toast({ title: "Account created", description: "Welcome to OdinForge AEV!" });
      onSignupSuccess();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Registration failed";
      setError(message);
      toast({ title: "Registration failed", description: message, variant: "destructive" });
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
          <div className="mb-16">
            <img src="/odinforge-lockup-horizontal.png" alt="OdinForge — Adversarial Exposure Validation" className="h-14" />
          </div>

          <div className="max-w-lg">
            <h1 className="text-4xl xl:text-5xl font-bold tracking-tight leading-[1.1] mb-4">
              Start validating
              <br />
              <span className="text-cyan-400">your attack surface.</span>
            </h1>
            <p className="text-lg text-muted-foreground leading-relaxed mb-10">
              Create your account to access the full AEV platform.
              Scan, exploit, and chain vulnerabilities with real evidence.
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
          <OdinGardBrand size="sm" className="opacity-60" />
          <span className="h-3 w-px bg-border" />
          <span>BSL 1.1 Licensed</span>
        </div>
      </div>

      {/* Right Panel — Signup Form */}
      <div className="flex-1 flex items-center justify-center relative z-10 p-6">
        <div className="w-full max-w-[420px]">
          <div className="lg:hidden text-center mb-10">
            <img src="/odinforge-lockup-stacked.png" alt="OdinForge" className="h-28 mx-auto" />
          </div>

          <div className="rounded-xl border border-border bg-card/80 backdrop-blur-sm p-8">
            <div className="mb-6">
              <h2 className="text-xl font-semibold tracking-tight">Create an account</h2>
              <p className="text-sm text-muted-foreground mt-1">Register to access the control plane</p>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 mb-5 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField control={form.control} name="email" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-sm font-medium">Email</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input type="email" placeholder="you@example.com" className="pl-10 h-11 bg-background/50" autoComplete="email" data-testid="input-email" {...field} />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )} />

                <FormField control={form.control} name="displayName" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-sm font-medium">Display Name</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input type="text" placeholder="Your name" className="pl-10 h-11 bg-background/50" autoComplete="name" data-testid="input-display-name" {...field} />
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
                        <Input type="password" placeholder="Create a password" className="pl-10 h-11 bg-background/50" autoComplete="new-password" data-testid="input-password" {...field} />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )} />

                <FormField control={form.control} name="confirmPassword" render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-sm font-medium">Confirm Password</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                        <Input type="password" placeholder="Confirm your password" className="pl-10 h-11 bg-background/50" autoComplete="new-password" data-testid="input-confirm-password" {...field} />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )} />

                <Button type="submit" className="w-full h-11 text-sm font-medium" disabled={isSubmitting} data-testid="button-signup">
                  {isSubmitting ? (
                    <><div className="h-4 w-4 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin mr-2" />Creating account...</>
                  ) : "Create account"}
                </Button>
              </form>
            </Form>

            <div className="mt-6 pt-6 border-t border-border text-center text-sm text-muted-foreground">
              Already have an account?{" "}
              <Link href="/login" className="text-primary font-medium hover:underline" data-testid="link-login">Sign in</Link>
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
