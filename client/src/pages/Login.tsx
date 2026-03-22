import { useState, useEffect, useRef } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useUIAuth } from "@/contexts/UIAuthContext";
import { useToast } from "@/hooks/use-toast";

const loginSchema = z.object({
  email: z.string().email("Valid email required"),
  password: z.string().min(8, "Minimum 8 characters"),
});
type LoginFormData = z.infer<typeof loginSchema>;

interface LoginProps { onLoginSuccess: () => void; }

const BOOT_LINES = [
  { cls: "hi",  text: "OdinForge AEV  //  Mjolnir Engine v4.2",            delay: 0    },
  { cls: "",    text: "Build 2026.03.17-prod  //  Odingard Security",       delay: 200  },
  { cls: "",    text: "",                                                    delay: 420  },
  { cls: "hi",  text: "BOOT SEQUENCE",                                      delay: 600  },
  { cls: "ok",  text: "  [OK]  kernel integrity verified",                  delay: 720  },
  { cls: "ok",  text: "  [OK]  evidence contract runtime loaded",           delay: 920  },
  { cls: "ok",  text: "  [OK]  exploit engine calibrated (50+ payloads)",   delay: 1100 },
  { cls: "ok",  text: "  [OK]  agent mesh online  (300 concurrent slots)",  delay: 1280 },
  { cls: "ok",  text: "  [OK]  EvidenceContract v2.0 enforced",             delay: 1460 },
  { cls: "ok",  text: "  [OK]  phase executors 1-6 ready",                  delay: 1640 },
  { cls: "ok",  text: "  [OK]  defender mirror — sigma engine ready",       delay: 1820 },
  { cls: "ok",  text: "  [OK]  breach chain replay recorder ready",         delay: 2000 },
  { cls: "ok",  text: "  [OK]  PostgreSQL 15 — connected",                  delay: 2180 },
  { cls: "ok",  text: "  [OK]  Redis 7 — connected",                        delay: 2360 },
  { cls: "ok",  text: "  [OK]  WebSocket mesh — listening on :5000/ws",     delay: 2540 },
  { cls: "",    text: "",                                                    delay: 2700 },
  { cls: "warn",text: "  [!!]  active engagements detected",                delay: 2860 },
  { cls: "warn",text: "  [!!]  critical findings pending review",           delay: 3020 },
  { cls: "",    text: "",                                                    delay: 3200 },
  { cls: "red", text: "AUTHENTICATION REQUIRED",                            delay: 3340 },
  { cls: "",    text: "",                                                    delay: 3420 },
];

export default function Login({ onLoginSuccess }: LoginProps) {
  const { login } = useUIAuth();
  const { toast } = useToast();
  const [bootDone, setBootDone] = useState(false);
  const [visibleLines, setVisibleLines] = useState<typeof BOOT_LINES>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bootRef = useRef<HTMLDivElement>(null);

  const form = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  useEffect(() => {
    BOOT_LINES.forEach((line, i) => {
      setTimeout(() => {
        setVisibleLines(prev => [...prev, line]);
        if (bootRef.current) bootRef.current.scrollTop = bootRef.current.scrollHeight;
      }, line.delay);
    });
    setTimeout(() => setBootDone(true), 3700);
  }, []);

  async function onSubmit(data: LoginFormData) {
    setIsSubmitting(true);
    setError(null);
    try {
      await login(data.email, data.password);
      toast({ title: "Access granted", description: "Welcome back, operator." });
      onLoginSuccess();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Authentication failed";
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  }

  const clsMap: Record<string, string> = {
    hi:   "text-[#7a93ad]",
    ok:   "text-[#22c55e]",
    warn: "text-[#f59e0b]",
    red:  "text-[#e8384f]",
    "":   "text-[#3a5166]",
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#07090f] relative overflow-hidden">
      {/* scanline overlay */}
      <div className="absolute inset-0 pointer-events-none z-0"
        style={{ background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px)" }} />

      <div className="w-full max-w-[520px] relative z-10 px-6">

        {/* Boot sequence */}
        {!bootDone && (
          <div ref={bootRef} className="font-mono text-[11px] leading-[1.8] max-h-[360px] overflow-hidden">
            {visibleLines.map((line, i) => (
              <div key={i} className={clsMap[line.cls] ?? "text-[#3a5166]"}>{line.text || "\u00a0"}</div>
            ))}
            <span className="inline-block w-[8px] h-[13px] bg-[#e8384f] align-middle animate-[blink_.8s_step-end_infinite]" />
          </div>
        )}

        {/* Login form */}
        {bootDone && (
          <div className="font-mono animate-[fadein_.3s_ease]">
            {/* Brand */}
            <div className="flex items-center gap-[14px] mb-8 pb-6 border-b border-[#1a2535]">
              <div className="w-[38px] h-[38px] bg-[#e8384f] flex items-center justify-center flex-shrink-0">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="1.5">
                  <path d="M12 2L4 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-8-4z"/>
                  <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
              <div>
                <div className="text-[18px] font-bold text-[#eaf0f8] font-sans tracking-[.01em]">
                  Odin<span className="text-[#e8384f]">Forge</span>
                </div>
                <div className="text-[9px] tracking-[.18em] text-[#1e3148] mt-[2px]">
                  adversarial exposure validation
                </div>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 text-[10px] text-[#e8384f] px-[10px] py-[8px] border border-[rgba(232,56,79,.22)] bg-[rgba(232,56,79,.09)] mb-4">
                <span className="text-[#e8384f]">✕</span> {error}
              </div>
            )}

            <form onSubmit={form.handleSubmit(onSubmit)} className="flex flex-col gap-4">
              <div>
                <div className="text-[9px] tracking-[.15em] uppercase text-[#3a5166] mb-[6px] flex items-center gap-[5px]">
                  <span className="text-[#e8384f]">›</span> operator identity
                </div>
                <input
                  type="email"
                  placeholder="operator@sixsenseenterprise.com"
                  className="w-full bg-[#0c1018] border border-[#243348] text-[#eaf0f8] font-mono text-[12px] px-[12px] py-[10px] outline-none transition-colors focus:border-[#e8384f] placeholder:text-[#1e3148]"
                  autoComplete="email"
                  data-testid="input-email"
                  {...form.register("email")}
                />
                {form.formState.errors.email && (
                  <div className="text-[9px] text-[#e8384f] mt-1">{form.formState.errors.email.message}</div>
                )}
              </div>

              <div>
                <div className="text-[9px] tracking-[.15em] uppercase text-[#3a5166] mb-[6px] flex items-center gap-[5px]">
                  <span className="text-[#e8384f]">›</span> access key
                </div>
                <input
                  type="password"
                  placeholder="••••••••••••••••"
                  className="w-full bg-[#0c1018] border border-[#243348] text-[#eaf0f8] font-mono text-[12px] px-[12px] py-[10px] outline-none transition-colors focus:border-[#e8384f] placeholder:text-[#1e3148]"
                  autoComplete="current-password"
                  data-testid="input-password"
                  {...form.register("password")}
                />
                {form.formState.errors.password && (
                  <div className="text-[9px] text-[#e8384f] mt-1">{form.formState.errors.password.message}</div>
                )}
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                data-testid="button-login"
                className="w-full mt-2 py-[11px] bg-[#e8384f] border-none text-white font-mono text-[11px] font-bold tracking-[.12em] uppercase cursor-pointer transition-colors hover:bg-[#d42e44] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? "Authenticating..." : "Authenticate →"}
              </button>
            </form>

            <div className="mt-5 pt-4 border-t border-[#1a2535] flex items-center justify-between">
              <div className="text-[9px] text-[#1e3148] tracking-[.06em]">MFA · RBAC · BSL 1.1</div>
              <a href="/signup" className="text-[10px] text-[#60a5fa] hover:underline" data-testid="link-signup">
                Request access
              </a>
            </div>
          </div>
        )}
      </div>

      {/* Status strip */}
      <div className="absolute bottom-0 left-0 right-0 flex items-center gap-4 px-6 py-2 border-t border-[#1a2535] bg-[#0c1018] font-mono text-[9px] tracking-[.07em] text-[#1e3148]">
        <div className="w-[5px] h-[5px] rounded-full bg-[#22c55e] animate-[pulse_2s_ease-in-out_infinite]" />
        <span className="text-[#3a5166]">engine nominal</span>
        <span className="text-[#1a2535]">·</span>
        <span className="text-[#3a5166]">mjolnir v4.2</span>
        <span className="text-[#1a2535]">·</span>
        <span className="text-[#3a5166]">build 2026.03.17</span>
        <span className="ml-auto text-[#1e3148]">odingard security // six sense enterprise services</span>
      </div>
    </div>
  );
}
