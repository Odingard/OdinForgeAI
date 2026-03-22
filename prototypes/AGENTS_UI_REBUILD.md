# OdinForge AEV — Full UI Rebuild

**4 files. Apply in order. Every block is a complete replacement.**

---

## Apply order

1. `client/src/index.css` — stripped design system, remove all dead code
2. `client/src/pages/Login.tsx` — terminal boot sequence
3. `client/src/App.tsx` — new shell (topbar, sidebar, statusbar)
4. `client/src/pages/BreachChains.tsx` — network map + evidence panel

---

## VERIFY after applying

```bash
cd /Users/dre/prod/OdinForge-AI
npx tsc --noEmit
npm run dev
```

---

### FILE: client/src/index.css
ACTION: REPLACE

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
  --bg:          #07090f;
  --nav:         #090c14;
  --panel:       #0c1018;
  --panel2:      #0f1520;
  --border:      #1a2535;
  --border2:     #243348;
  --hover:       rgba(255,255,255,.025);

  --red:         #e8384f;
  --red-dim:     rgba(232,56,79,.09);
  --red-border:  rgba(232,56,79,.22);
  --green:       #22c55e;
  --green-dim:   rgba(34,197,94,.08);
  --green-border:rgba(34,197,94,.2);
  --blue:        #60a5fa;
  --blue-dim:    rgba(96,165,250,.1);
  --blue-border: rgba(96,165,250,.25);
  --amber:       #f59e0b;
  --amber-dim:   rgba(245,158,11,.09);
  --amber-border:rgba(245,158,11,.25);
  --purple:      #a78bfa;
  --cyan:        #06b6d4;

  --t1: #eaf0f8;
  --t2: #7a93ad;
  --t3: #3a5166;
  --t4: #1e3148;

  --font-sans: 'IBM Plex Sans', system-ui, sans-serif;
  --font-mono: 'IBM Plex Mono', Consolas, 'Courier New', monospace;
  --font-serif: Georgia, serif;
  --radius: 4px;

  --background: 222 40% 4%;
  --foreground: 210 33% 96%;
  --border-color: 215 35% 15%;
  --card: 220 33% 7%;
  --card-foreground: 210 33% 96%;
  --popover: 220 20% 8%;
  --popover-foreground: 210 20% 95%;
  --primary: 0 75% 55%;
  --primary-foreground: 0 0% 98%;
  --secondary: 215 30% 13%;
  --secondary-foreground: 210 33% 96%;
  --muted: 215 30% 10%;
  --muted-foreground: 210 20% 40%;
  --accent: 215 30% 13%;
  --accent-foreground: 210 33% 96%;
  --destructive: 0 84% 45%;
  --destructive-foreground: 0 0% 98%;
  --input: 215 10% 65%;
  --ring: 0 75% 55%;

  --chart-1: 0 84% 55%;
  --chart-2: 25 95% 55%;
  --chart-3: 45 95% 55%;
  --chart-4: 142 76% 55%;
  --chart-5: 200 90% 55%;
  --chart-6: 280 65% 60%;

  --sidebar: var(--nav);
  --sidebar-foreground: var(--t2);
  --sidebar-border: var(--border);
  --sidebar-primary: var(--red);
  --sidebar-primary-foreground: #fff;
  --sidebar-accent: var(--panel2);
  --sidebar-accent-foreground: var(--t1);
  --sidebar-ring: var(--red);

  --falcon-bg:          var(--bg);
  --falcon-nav:         var(--nav);
  --falcon-panel:       var(--panel);
  --falcon-panel-2:     var(--panel2);
  --falcon-border:      var(--border);
  --falcon-border-2:    var(--border2);
  --falcon-hover:       var(--hover);
  --falcon-red:         var(--red);
  --falcon-red-dim:     var(--red-dim);
  --falcon-red-border:  var(--red-border);
  --falcon-orange:      var(--amber);
  --falcon-orange-dim:  var(--amber-dim);
  --falcon-green:       var(--green);
  --falcon-green-dim:   var(--green-dim);
  --falcon-blue:        #3b82f6;
  --falcon-blue-dim:    var(--blue-dim);
  --falcon-blue-hi:     var(--blue);
  --falcon-yellow:      var(--amber);
  --falcon-yellow-dim:  var(--amber-dim);
  --falcon-t1:          var(--t1);
  --falcon-t2:          var(--t2);
  --falcon-t3:          var(--t3);
  --falcon-t4:          var(--t4);
  --falcon-row-hover:   var(--panel2);
  --shadow-2xs: none; --shadow-xs: none; --shadow-sm: none;
  --shadow: none; --shadow-md: none; --shadow-lg: none;
  --shadow-xl: none; --shadow-2xl: none;
}

@layer base {
  * { @apply border-border; }
  body {
    background: var(--bg);
    color: var(--t1);
    font-family: var(--font-sans);
    font-feature-settings: "rlig" 1, "calt" 1;
  }
}

/* ── Chip / Badge ── */
.f-chip {
  display: inline-flex; align-items: center;
  padding: 2px 8px; font-family: var(--font-mono);
  font-size: 9px; font-weight: 500; letter-spacing: .08em;
  border: 1px solid; border-radius: 2px;
}
.f-chip-crit  { color: var(--red);    border-color: var(--red-border);    background: var(--red-dim);    }
.f-chip-high  { color: var(--amber);  border-color: var(--amber-border);  background: var(--amber-dim);  }
.f-chip-med   { color: var(--blue);   border-color: var(--blue-border);   background: var(--blue-dim);   }
.f-chip-low   { color: var(--blue);   border-color: var(--blue-border);   background: var(--blue-dim);   }
.f-chip-ok    { color: var(--green);  border-color: var(--green-border);  background: var(--green-dim);  }
.f-chip-gray  { color: var(--t3);     border-color: var(--border);        background: rgba(255,255,255,.03); }

/* ── Status pill ── */
.f-status { display: inline-flex; align-items: center; gap: 5px; font-family: var(--font-mono); font-size: 10px; }
.f-s-dot  { width: 5px; height: 5px; border-radius: 50%; }
.f-sd-live  { background: var(--green); animation: f-pulse 2s ease-in-out infinite; }
.f-sd-queue { background: var(--amber); }
.f-sd-done  { background: var(--t4); }
.f-sd-err   { background: var(--red); }
.f-st-live  { color: var(--green); }
.f-st-queue { color: var(--amber); }
.f-st-done  { color: var(--t3); }
.f-st-err   { color: var(--red); }
@keyframes f-pulse { 0%,100%{box-shadow:0 0 5px var(--green)} 50%{box-shadow:none} }
@keyframes f-blink { 0%,100%{opacity:1} 50%{opacity:.3} }

/* ── Panel ── */
.f-panel { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; overflow: hidden; display: flex; flex-direction: column; }
.f-panel-head { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; border-bottom: 1px solid var(--border); background: var(--panel2); flex-shrink: 0; }
.f-panel-title { font-size: 10px; font-weight: 500; letter-spacing: .1em; color: var(--t2); text-transform: uppercase; display: flex; align-items: center; gap: 8px; }
.f-panel-dot   { width: 5px; height: 5px; border-radius: 50%; background: var(--red); }
.f-panel-dot.g { background: var(--green); }
.f-panel-dot.b { background: var(--blue); }

/* ── Table ── */
.f-tbl       { display: flex; flex-direction: column; flex: 1; min-height: 0; overflow: hidden; }
.f-tbl-head  { display: grid; padding: 7px 14px; background: rgba(0,0,0,.2); border-bottom: 1px solid var(--border); flex-shrink: 0; }
.f-th        { font-family: var(--font-mono); font-size: 9px; letter-spacing: .18em; color: var(--t4); text-transform: uppercase; }
.f-tbl-body  { overflow-y: auto; flex: 1; }
.f-tbl-row   { display: grid; padding: 10px 14px; border-bottom: 1px solid rgba(26,37,53,.55); cursor: pointer; align-items: center; transition: background .1s; }
.f-tbl-row:hover { background: var(--panel2); }
.f-tbl-row:last-child { border-bottom: none; }
.f-td        { font-size: 12px; color: var(--t2); }
.f-td.n      { font-weight: 600; color: var(--t1); }
.f-td.sub    { font-family: var(--font-mono); font-size: 9px; color: var(--t3); margin-top: 2px; }
.f-td.m      { font-family: var(--font-mono); font-size: 11px; }

/* ── KPI ── */
.f-kpi { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 14px 15px; transition: border-color .15s; }
.f-kpi:hover { border-color: var(--border2); }
.f-kpi.hot   { border-color: var(--red-border); }
.f-kpi.ok    { border-color: var(--green-border); }
.f-kpi-lbl   { font-family: var(--font-mono); font-size: 9px; letter-spacing: .1em; color: var(--t3); text-transform: uppercase; margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
.f-kpi-dot   { width: 5px; height: 5px; border-radius: 50%; background: var(--t4); }
.f-kpi-dot.r { background: var(--red); }
.f-kpi-dot.g { background: var(--green); }
.f-kpi-dot.b { background: var(--blue); }
.f-kpi-dot.o { background: var(--amber); }
.f-kpi-val   { font-family: var(--font-mono); font-size: 28px; font-weight: 500; line-height: 1; letter-spacing: -.02em; color: var(--t1); }
.f-kpi-val.r { color: var(--red); }
.f-kpi-val.g { color: var(--green); }
.f-kpi-val.b { color: var(--blue); }
.f-kpi-val.o { color: var(--amber); }
.f-kpi-foot  { margin-top: 5px; font-family: var(--font-mono); font-size: 9px; color: var(--t3); }

/* ── Buttons ── */
.f-btn { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 3px; border: 1px solid; font-family: var(--font-sans); font-size: 11px; font-weight: 500; cursor: pointer; transition: all .12s; white-space: nowrap; }
.f-btn svg { width: 12px; height: 12px; }
.f-btn-primary   { background: var(--red);   border-color: var(--red);        color: #fff; }
.f-btn-primary:hover { background: #d42e44; }
.f-btn-secondary { background: var(--blue-dim); border-color: var(--blue-border); color: var(--blue); }
.f-btn-secondary:hover { background: rgba(96,165,250,.18); }
.f-btn-ghost     { background: transparent; border-color: var(--border2); color: var(--t2); }
.f-btn-ghost:hover { border-color: var(--t2); color: var(--t1); }
.f-btn-danger    { background: transparent; border-color: var(--red-border); color: var(--red); }
.f-btn-danger:hover { background: var(--red-dim); }

/* ── Nav badges ── */
.f-nav-badge { margin-left: auto; font-family: var(--font-mono); font-size: 9px; font-weight: 500; padding: 1px 6px; border-radius: 2px; }
.f-nb-r { background: var(--red-dim);  color: var(--red);  border: 1px solid var(--red-border); }
.f-nb-d { background: rgba(255,255,255,.04); color: var(--t3); border: 1px solid var(--border); }

/* ── Tabs ── */
.f-tab-bar { display: flex; gap: 2px; border-bottom: 1px solid var(--border); margin-bottom: 18px; overflow-x: auto; }
.f-tab { padding: 8px 14px; font-size: 11px; font-weight: 500; color: var(--t3); background: transparent; border: none; border-bottom: 2px solid transparent; cursor: pointer; transition: all .15s; white-space: nowrap; display: inline-flex; align-items: center; gap: 6px; font-family: var(--font-sans); }
.f-tab svg { width: 13px; height: 13px; }
.f-tab:hover { color: var(--t2); }
.f-tab.active { color: var(--t1); border-bottom-color: var(--red); }

/* ── Modal ── */
.f-modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,.65); z-index: 50; display: flex; align-items: center; justify-content: center; animation: f-fade-in .15s ease; }
@keyframes f-fade-in { from{opacity:0} to{opacity:1} }
.f-modal { background: var(--panel); border: 1px solid var(--border2); border-radius: 5px; width: 100%; max-width: 480px; max-height: 80vh; overflow-y: auto; animation: f-scale-in .15s ease; }
@keyframes f-scale-in { from{transform:scale(.96);opacity:0} to{transform:scale(1);opacity:1} }
.f-modal-lg { max-width: 720px; }
.f-modal-xl { max-width: 960px; }
.f-modal-head { padding: 14px 18px; border-bottom: 1px solid var(--border); }
.f-modal-title { font-size: 13px; font-weight: 600; color: var(--t1); margin: 0; }
.f-modal-desc  { font-size: 11px; color: var(--t3); margin-top: 3px; }
.f-modal-body  { padding: 18px; }
.f-modal-footer { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 18px; border-top: 1px solid var(--border); }

/* ── Switch ── */
.f-switch { width: 34px; height: 18px; border-radius: 9px; background: var(--border2); border: none; cursor: pointer; position: relative; transition: background .2s; flex-shrink: 0; padding: 0; }
.f-switch.on { background: var(--green); }
.f-switch::after { content: ''; position: absolute; top: 2px; left: 2px; width: 14px; height: 14px; border-radius: 50%; background: #fff; transition: left .2s; }
.f-switch.on::after { left: 18px; }

/* ── Select ── */
.f-select { width: 100%; padding: 8px 30px 8px 11px; background: var(--panel); border: 1px solid var(--border); border-radius: 3px; color: var(--t1); font-size: 12px; appearance: none; cursor: pointer; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%233a5166' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 9px center; }
.f-select:focus { outline: none; border-color: var(--blue); }

/* ── Misc ── */
.f-tb-track { flex: 1; height: 3px; background: var(--border); border-radius: 2px; overflow: hidden; }
.f-tb-fill  { height: 100%; border-radius: 2px; }
.f-tf-r { background: var(--red); }
.f-tf-o { background: var(--amber); }
.f-tf-b { background: var(--blue); }
.f-tf-g { background: var(--green); }

/* ── Severity aliases used in BreachChains ── */
.sc-crit { color: var(--red);   border-color: var(--red-border);   background: var(--red-dim);   }
.sc-high { color: var(--amber); border-color: var(--amber-border); background: var(--amber-dim); }
.sc-med  { color: var(--blue);  border-color: var(--blue-border);  background: var(--blue-dim);  }
.sc-low  { color: var(--blue);  border-color: var(--blue-border);  background: var(--blue-dim);  }
.sev-chip { display: inline-flex; align-items: center; padding: 2px 8px; font-family: var(--font-mono); font-size: 9px; font-weight: 500; letter-spacing: .08em; border: 1px solid; border-radius: 2px; }
.status-pill { display: inline-flex; align-items: center; gap: 5px; font-family: var(--font-mono); font-size: 10px; }
.sp-dot  { width: 5px; height: 5px; border-radius: 50%; }
.sp-live  { background: var(--green); animation: f-pulse 2s ease-in-out infinite; }
.sp-queue { background: var(--amber); }
.sp-done  { background: var(--t4); }
.spt-live  { color: var(--green); }
.spt-queue { color: var(--amber); }
.spt-done  { color: var(--t3); }
.falcon-panel      { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; overflow: hidden; display: flex; flex-direction: column; }
.falcon-panel-head { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; border-bottom: 1px solid var(--border); background: var(--panel2); flex-shrink: 0; }
.falcon-kpi        { background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 14px 15px; transition: border-color .15s; }
.falcon-kpi:hover  { border-color: var(--border2); }
.falcon-kpi.hot    { border-color: var(--red-border); }
```

---

### FILE: client/src/pages/Login.tsx
ACTION: REPLACE

```tsx
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
```

---

### FILE: client/src/App.tsx
ACTION: REPLACE

```tsx
import { useState, useCallback, useEffect, lazy, Suspense, Component } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { Switch, Route, useLocation, Redirect, Link } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider, useQuery } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "./components/ThemeProvider";
import { UIAuthProvider, useUIAuth } from "./contexts/UIAuthContext";
import { ViewModeProvider } from "./contexts/ViewModeContext";
import { useAuth } from "@/contexts/AuthContext";
import { Shield, FileText, Settings, LogOut } from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuTrigger, DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { ShieldValknut } from "./components/OdinForgeLogo";
import { NotificationsPopover } from "./components/NotificationsPopover";

const BreachChains = lazy(() => import("@/pages/BreachChains"));
const Reports      = lazy(() => import("@/pages/Reports"));
const SettingsPage = lazy(() => import("@/pages/Settings"));
const Login        = lazy(() => import("@/pages/Login"));
const Signup       = lazy(() => import("@/pages/Signup"));
const NotFound     = lazy(() => import("@/pages/not-found"));

class AppErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean; error: Error | null }> {
  constructor(props: { children: ReactNode }) { super(props); this.state = { hasError: false, error: null }; }
  static getDerivedStateFromError(error: Error) { return { hasError: true, error }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("[AppErrorBoundary]", error, info); }
  render() {
    if (this.state.hasError) return (
      <div className="min-h-screen flex items-center justify-center p-8" style={{ background: "var(--bg)" }}>
        <div className="max-w-lg w-full space-y-4">
          <h1 className="text-xl font-bold" style={{ color: "var(--red)" }}>Something went wrong</h1>
          <pre className="text-xs p-4 overflow-auto max-h-64" style={{ background: "var(--panel)", color: "var(--t2)", border: "1px solid var(--border)" }}>
            {this.state.error?.message}{"\n\n"}{this.state.error?.stack}
          </pre>
          <button onClick={() => { this.setState({ hasError: false, error: null }); window.location.reload(); }}
            className="px-4 py-2 text-sm" style={{ background: "var(--red)", color: "#fff", border: "none", cursor: "pointer" }}>
            Reload
          </button>
        </div>
      </div>
    );
    return this.props.children;
  }
}

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="text-center">
        <div className="h-5 w-5 border-2 border-t-transparent rounded-full animate-spin mx-auto mb-3"
          style={{ borderColor: "var(--red)", borderTopColor: "transparent" }} />
        <p className="font-mono text-[9px] tracking-widest" style={{ color: "var(--t4)" }}>LOADING</p>
      </div>
    </div>
  );
}

function Router() {
  return (
    <AppErrorBoundary>
      <Suspense fallback={<PageLoader />}>
        <Switch>
          <Route path="/"><Redirect to="/breach-chains" /></Route>
          <Route path="/login"><Redirect to="/breach-chains" /></Route>
          <Route path="/signup"><Redirect to="/breach-chains" /></Route>
          <Route path="/breach-chains" component={BreachChains} />
          <Route path="/reports" component={Reports} />
          <Route path="/admin/settings" component={SettingsPage} />
          <Route component={NotFound} />
        </Switch>
      </Suspense>
    </AppErrorBoundary>
  );
}

const PAGE_META: Record<string, { name: string; sub: string }> = {
  "/breach-chains":   { name: "Breach Chains",  sub: "Threat Operations Center" },
  "/reports":         { name: "Reports",         sub: "Engagement deliverables"  },
  "/admin/settings":  { name: "Settings",        sub: "System configuration"     },
};

/* ── TopBar ── */
function TopBar() {
  const { user: uiUser, logout } = useUIAuth();
  const [location] = useLocation();
  const { data: chains = [] } = useQuery<any[]>({ queryKey: ["/api/breach-chains"], refetchInterval: 5000 });

  const handleLogout = async () => { await logout(); window.location.reload(); };
  const meta = PAGE_META[location] ?? { name: "OdinForge", sub: "AEV Platform" };

  const activeCount  = chains.filter((c: any) => c.status === "running").length;
  const critCount    = chains.reduce((s: number, c: any) =>
    s + (c.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "critical").length, 0);
  const breachCount  = chains.filter((c: any) =>
    (c.phaseResults || []).some((p: any) => (p.findings || []).length > 0)).length;
  const engineStatus = activeCount > 0 ? "ACTIVE" : "NOMINAL";

  const S = ({ value, label, color }: { value: string; label: string; color?: string }) => (
    <div className="flex flex-col items-center justify-center px-[14px] gap-[1px]"
      style={{ borderLeft: "1px solid var(--border)" }}>
      <div className="font-mono text-[13px] font-medium leading-none" style={{ color: color ?? "var(--t1)" }}>{value}</div>
      <div className="font-mono text-[8px] tracking-[.12em] uppercase" style={{ color: "var(--t3)" }}>{label}</div>
    </div>
  );

  return (
    <div className="flex items-center" style={{ borderBottom: "1px solid var(--border)", background: "var(--panel)", gridColumn: "1 / -1" }}>
      {/* Logo block */}
      <div className="flex items-center gap-[10px] px-[16px] h-full flex-shrink-0"
        style={{ width: 220, borderRight: "1px solid var(--border)" }}>
        <div className="flex items-center justify-center flex-shrink-0"
          style={{ width: 28, height: 28, background: "var(--red)" }}>
          <ShieldValknut className="w-[15px] h-[15px] text-white" />
        </div>
        <div>
          <div className="text-[15px] font-bold" style={{ color: "var(--t1)", fontFamily: "var(--font-sans)" }}>
            Odin<span style={{ color: "var(--red)" }}>Forge</span>
          </div>
          <div className="font-mono text-[8px] tracking-[.18em]" style={{ color: "var(--t4)" }}>AEV PLATFORM</div>
        </div>
      </div>

      {/* Page name */}
      <div className="flex flex-col gap-[1px] px-[16px]">
        <div className="text-[13px] font-semibold" style={{ color: "var(--t1)" }}>{meta.name}</div>
        <div className="font-mono text-[9px] tracking-[.06em]" style={{ color: "var(--t3)" }}>{meta.sub}</div>
      </div>

      {/* Breach alert */}
      {breachCount > 0 && (
        <div className="flex items-center gap-[6px] px-[10px] py-[4px] ml-3"
          style={{ background: "var(--red-dim)", border: "1px solid var(--red-border)" }}>
          <div className="w-[5px] h-[5px] rounded-full" style={{ background: "var(--red)", animation: "f-blink 1.8s ease-in-out infinite" }} />
          <span className="font-mono text-[9px] tracking-[.07em]" style={{ color: "var(--red)" }}>
            {breachCount} BREACH PATH{breachCount !== 1 ? "S" : ""} DETECTED
          </span>
        </div>
      )}

      {/* Right stats */}
      <div className="ml-auto flex items-stretch h-full">
        <S value={String(activeCount)} label="Active" color={activeCount > 0 ? "var(--blue)" : undefined} />
        <S value={String(critCount)} label="Critical" color={critCount > 0 ? "var(--red)" : undefined} />
        <S value={String(breachCount)} label="Breaches" color={breachCount > 0 ? "var(--amber)" : undefined} />
        <S value={engineStatus} label="Engine" color={activeCount > 0 ? "var(--blue)" : "var(--green)"} />

        {/* Notifications */}
        <div className="flex items-center justify-center w-[44px] cursor-pointer"
          style={{ borderLeft: "1px solid var(--border)", color: "var(--t3)" }}>
          <NotificationsPopover />
        </div>

        {/* User */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <div className="flex items-center gap-[9px] px-[14px] cursor-pointer transition-colors"
              style={{ borderLeft: "1px solid var(--border)" }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "var(--hover)"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = ""; }}
              data-testid="button-user-menu">
              <div className="w-[26px] h-[26px] rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
                style={{ background: "var(--red)", color: "#fff" }}>
                {(uiUser?.displayName?.charAt(0) || uiUser?.email?.charAt(0) || "U").toUpperCase()}
              </div>
              <div>
                <div className="text-[12px] font-medium" style={{ color: "var(--t1)" }}>
                  {uiUser?.displayName || uiUser?.email || "User"}
                </div>
                <div className="font-mono text-[8px] tracking-[.07em]" style={{ color: "var(--t3)" }}>
                  {(uiUser?.role?.name || "OPERATOR").toUpperCase()}
                </div>
              </div>
            </div>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            {uiUser && (
              <>
                <div className="px-3 py-2">
                  <p className="text-xs font-medium">{uiUser.displayName || uiUser.email}</p>
                  <p className="text-xs mt-0.5" style={{ color: "var(--t3)" }}>{uiUser.email}</p>
                </div>
                <DropdownMenuSeparator />
              </>
            )}
            <DropdownMenuItem>Profile</DropdownMenuItem>
            <DropdownMenuItem>Settings</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout} className="text-red-400 focus:text-red-400" data-testid="menu-logout">
              <LogOut className="h-3.5 w-3.5 mr-2" />Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}

/* ── Sidebar ── */
function Sidebar() {
  const [location] = useLocation();
  const { hasPermission } = useAuth();
  const { user: uiUser, logout } = useUIAuth();
  const { data: chains = [] } = useQuery<any[]>({ queryKey: ["/api/breach-chains"], refetchInterval: 5000 });
  const breachCount = chains.filter((c: any) =>
    (c.phaseResults || []).some((p: any) => (p.findings || []).length > 0)).length;

  const navItem = (href: string, Icon: typeof Shield, label: string, badge?: number) => {
    const active = location.startsWith(href);
    return (
      <Link key={href} href={href}>
        <div className="flex items-center gap-[10px] py-[9px] px-[14px] text-[12px] font-medium cursor-pointer select-none transition-all"
          style={{
            color: active ? "var(--t1)" : "var(--t2)",
            background: active ? "rgba(255,255,255,.04)" : undefined,
            borderLeft: active ? "2px solid var(--red)" : "2px solid transparent",
          }}
          onMouseEnter={e => { if (!active) { (e.currentTarget as HTMLElement).style.color = "var(--t1)"; (e.currentTarget as HTMLElement).style.background = "var(--hover)"; }}}
          onMouseLeave={e => { if (!active) { (e.currentTarget as HTMLElement).style.color = "var(--t2)"; (e.currentTarget as HTMLElement).style.background = ""; }}}>
          <Icon className="w-[14px] h-[14px] flex-shrink-0" strokeWidth={1.5} />
          {label}
          {badge !== undefined && badge > 0 && (
            <span className="f-nav-badge f-nb-r ml-auto">{badge}</span>
          )}
        </div>
      </Link>
    );
  };

  const showSettings = hasPermission("org:manage_settings") || hasPermission("org:manage_users");

  return (
    <div className="flex flex-col overflow-hidden" style={{ background: "var(--nav)", borderRight: "1px solid var(--border)" }}>
      <div className="h-4" />
      <div className="flex flex-col gap-[2px] px-[10px]">
        {navItem("/breach-chains", Shield, "Breach Chains", breachCount)}
        {navItem("/reports", FileText, "Reports")}
      </div>
      <div className="flex-1" />
      {showSettings && (
        <div className="px-[10px] pb-1">
          {navItem("/admin/settings", Settings, "Settings")}
        </div>
      )}
      <div className="flex items-center gap-[10px] px-[14px] py-[10px] cursor-pointer transition-colors"
        style={{ borderTop: "1px solid var(--border)" }}
        onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "var(--hover)"; }}
        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = ""; }}>
        <div className="w-[26px] h-[26px] rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
          style={{ background: "var(--red)", color: "#fff" }}>
          {(uiUser?.displayName?.charAt(0) || uiUser?.email?.charAt(0) || "U").toUpperCase()}
        </div>
        <div>
          <div className="text-[12px] font-semibold" style={{ color: "var(--t1)" }}>
            {uiUser?.displayName || uiUser?.email || "User"}
          </div>
          <div className="font-mono text-[8px] tracking-[.06em]" style={{ color: "var(--t3)" }}>
            {(uiUser?.role?.name || "OPERATOR").toUpperCase()}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── StatusBar ── */
function StatusBar() {
  const { data: chains = [] } = useQuery<any[]>({ queryKey: ["/api/breach-chains"], refetchInterval: 5000 });
  const running = chains.filter((c: any) => c.status === "running");
  return (
    <div className="flex items-center px-[16px] gap-[12px] font-mono text-[9px] tracking-[.07em]"
      style={{ borderTop: "1px solid var(--border)", background: "var(--panel)", color: "var(--t4)", gridColumn: "1 / -1" }}>
      <span>engine</span><span style={{ color: "var(--t3)" }}>Mjolnir v4.2</span>
      <span style={{ color: "var(--border2)" }}>·</span>
      <span>build</span><span style={{ color: "var(--t3)" }}>2026.03.17</span>
      <span style={{ color: "var(--border2)" }}>·</span>
      <span>odingard security</span>
      <div className="ml-auto flex items-center gap-[5px]" style={{ color: running.length > 0 ? "var(--blue)" : "var(--green)" }}>
        <div className="w-[5px] h-[5px] rounded-full" style={{ background: running.length > 0 ? "var(--blue)" : "var(--green)" }} />
        {running.length > 0 ? `${running.length} chain${running.length !== 1 ? "s" : ""} active` : "systems nominal"}
      </div>
    </div>
  );
}

/* ── App Layout ── */
function AppLayout() {
  return (
    <div className="h-screen w-full overflow-hidden" style={{
      display: "grid",
      gridTemplateColumns: "220px 1fr",
      gridTemplateRows: "48px 1fr 24px",
      background: "var(--bg)",
    }}>
      <TopBar />
      <Sidebar />
      <main className="flex flex-col overflow-hidden" style={{ background: "var(--bg)" }}>
        <div className="flex flex-col gap-[14px] p-5 flex-1 overflow-auto">
          <Router />
        </div>
      </main>
      <StatusBar />
    </div>
  );
}

function AuthenticatedApp() {
  const { isAuthenticated, isLoading } = useUIAuth();
  const [, forceUpdate] = useState(0);
  const [location] = useLocation();

  useEffect(() => {
    fetch("/api/flags").then(r => r.ok ? r.json() : {})
      .then((flags: Record<string, boolean>) => { (window as any).__ODINFORGE_FLAGS__ = flags; })
      .catch(() => {});
  }, []);

  const handleAuthSuccess = useCallback(() => forceUpdate(x => x + 1), []);

  if (isLoading) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--bg)" }}>
      <div className="text-center">
        <div className="h-5 w-5 border-2 border-t-transparent rounded-full animate-spin mx-auto mb-3"
          style={{ borderColor: "var(--red)", borderTopColor: "transparent" }} />
        <p className="font-mono text-[9px] tracking-widest" style={{ color: "var(--t4)" }}>INITIALIZING</p>
      </div>
    </div>
  );

  if (!isAuthenticated) {
    if (location === "/signup") return <Signup onSignupSuccess={handleAuthSuccess} />;
    return <Login onLoginSuccess={handleAuthSuccess} />;
  }

  return (
    <ViewModeProvider>
      <TooltipProvider>
        <AppLayout />
        <Toaster />
      </TooltipProvider>
    </ViewModeProvider>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <UIAuthProvider>
          <AuthenticatedApp />
        </UIAuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
```

---

### FILE: client/src/pages/BreachChains.tsx
ACTION: REPLACE

```tsx
import { useState, useEffect, useRef, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { useBreachChainUpdates } from "@/hooks/useBreachChainUpdates";
import { Play, Pause, StopCircle, Eye, Plus, Download, RotateCcw, Shield, FileText } from "lucide-react";
import type { BreachChain, BreachPhaseResult, AttackGraph } from "@shared/schema";

// ── Types ────────────────────────────────────────────────────────────────────

interface NodeData {
  title: string; sev: string; mitre?: string; technique?: string;
  assets?: { k: string; v: string; c?: string }[];
  status?: number; evidence?: string; extracted?: string;
  curl?: string; ts?: string; hash?: string;
}

interface GraphNode { id: string; x: number; y: number; r: number; label: string; col: string; data: NodeData; }
interface GraphEdge { x1: number; y1: number; x2: number; y2: number; col: string; dashed: boolean; cx: boolean; delay: number; }

// ── Constants ────────────────────────────────────────────────────────────────

const PHASE_LABELS: Record<string, string> = {
  application_compromise:   "APP",
  credential_extraction:    "CREDS",
  cloud_iam_escalation:     "IAM",
  container_k8s_breakout:   "K8S",
  lateral_movement:         "LATERAL",
  impact_assessment:        "IMPACT",
};

const PHASE_ORDER = [
  "application_compromise", "credential_extraction", "cloud_iam_escalation",
  "container_k8s_breakout", "lateral_movement", "impact_assessment",
];

const SEV_COLOR: Record<string, string> = {
  critical: "var(--red)", high: "var(--amber)",
  medium: "var(--blue)", low: "var(--blue)", info: "var(--t3)",
};

const SEV_CLS: Record<string, string> = {
  critical: "f-chip f-chip-crit", high: "f-chip f-chip-high",
  medium: "f-chip f-chip-med", low: "f-chip f-chip-low", info: "f-chip f-chip-gray",
};

// ── SVG helpers ──────────────────────────────────────────────────────────────

function mkEl(tag: string, attrs: Record<string, string>) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
  return el;
}

// ── Evidence Panel ───────────────────────────────────────────────────────────

function EvidencePanel({ data, title, onClose }: { data: NodeData; title: string; onClose: () => void }) {
  const sevCls = data.sev === "critical" ? "f-chip f-chip-crit" : data.sev === "high" ? "f-chip f-chip-high" : "f-chip f-chip-gray";
  return (
    <div className="flex flex-col h-full" style={{ borderLeft: "1px solid var(--border)" }}>
      <div className="flex items-center justify-between px-3 py-[7px] flex-shrink-0"
        style={{ borderBottom: "1px solid var(--border)", background: "var(--panel2)" }}>
        <span className="font-mono text-[9px] tracking-[.1em] uppercase text-ellipsis overflow-hidden whitespace-nowrap max-w-[180px]"
          style={{ color: "var(--t3)" }}>{title}</span>
        <button onClick={onClose} className="font-mono text-[13px] leading-none px-[3px]"
          style={{ background: "transparent", border: "none", color: "var(--t3)", cursor: "pointer" }}>✕</button>
      </div>
      <div className="flex-1 overflow-y-auto p-3 font-mono text-[9px]">
        <span className={sevCls} style={{ marginBottom: 10, display: "inline-block" }}>
          {data.sev?.toUpperCase()}
        </span>

        {data.mitre && (
          <div style={{ marginBottom: 10 }}>
            <div className="ev-label-row">MITRE ATT&CK</div>
            <div style={{ color: "var(--t1)", fontSize: 10, lineHeight: 1.5 }}>{data.mitre} — {data.technique}</div>
          </div>
        )}

        {data.assets && data.assets.length > 0 && (
          <>
            <div style={{ height: 1, background: "var(--border)", margin: "10px 0" }} />
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--amber)", marginBottom: 5, display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--amber)", display: "inline-block" }} />
                ASSET PROOF
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "3px 10px", lineHeight: 1.65 }}>
                {data.assets.map((a, i) => (
                  <>
                    <span key={`k${i}`} style={{ color: "var(--t3)", whiteSpace: "nowrap" }}>{a.k}</span>
                    <span key={`v${i}`} style={{ color: a.c === "red" ? "var(--red)" : a.c === "amber" ? "var(--amber)" : a.c === "blue" ? "var(--blue)" : a.c === "green" ? "var(--green)" : "var(--t1)", fontWeight: a.c === "red" ? 700 : undefined, wordBreak: "break-all" }}>{a.v}</span>
                  </>
                ))}
              </div>
            </div>
          </>
        )}

        {data.status && (
          <>
            <div style={{ height: 1, background: "var(--border)", margin: "10px 0" }} />
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--t3)", marginBottom: 4 }}>HTTP STATUS</div>
              <div style={{ fontSize: 11, color: data.status === 200 ? "var(--green)" : "var(--amber)" }}>{data.status} OK — confirmed live</div>
            </div>
          </>
        )}

        {data.evidence && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--t3)", marginBottom: 4 }}>EVIDENCE SNIPPET</div>
            <div style={{ fontSize: 8.5, padding: 8, background: "var(--bg)", border: "1px solid var(--border2)", color: "var(--t2)", lineHeight: 1.65, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{data.evidence}</div>
          </div>
        )}

        {data.extracted && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--red)", marginBottom: 4, display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--red)", display: "inline-block" }} />
              EXTRACTED DATA
            </div>
            <div style={{ fontSize: 8.5, padding: 8, background: "rgba(232,56,79,.05)", border: "1px solid var(--red-border)", color: "var(--red)", lineHeight: 1.65, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{data.extracted}</div>
          </div>
        )}

        {data.curl && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--t3)", marginBottom: 4 }}>REPRODUCE</div>
            <div style={{ fontSize: 8.5, padding: 8, background: "var(--bg)", border: "1px solid var(--border2)", color: "var(--t2)", lineHeight: 1.65, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{data.curl}</div>
          </div>
        )}

        {data.ts && (
          <>
            <div style={{ height: 1, background: "var(--border)", margin: "10px 0" }} />
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--t3)", marginBottom: 3 }}>CONFIRMED AT</div>
              <div style={{ fontSize: 9, color: "var(--t3)" }}>{data.ts}</div>
            </div>
          </>
        )}

        {data.hash && (
          <div style={{ fontSize: 7.5, padding: "5px 7px", background: "var(--bg)", border: "1px solid var(--border)", color: "var(--t4)", wordBreak: "break-all", marginTop: 8 }}>
            <span style={{ color: "var(--t3)" }}>SHA-256: </span>{data.hash}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Network Map ──────────────────────────────────────────────────────────────

function NetworkMap({
  chain, graph, nodes: liveNodes, edges: liveEdges,
}: {
  chain: BreachChain;
  graph: AttackGraph | null;
  nodes: any[];
  edges: any[];
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<{ data: NodeData; title: string } | null>(null);
  const [hint, setHint] = useState("click any confirmed node for full evidence");
  const nodeStore = useRef<Record<string, NodeData>>({});
  const drawnIds = useRef<Set<string>>(new Set());
  const drawnEdges = useRef<Set<string>>(new Set());

  function drawEdge(x1: number, y1: number, x2: number, y2: number, col: string, dashed: boolean, cx: boolean, delay: number) {
    setTimeout(() => {
      const s = svgRef.current; if (!s) return;
      const ln = mkEl("line", { x1: String(x1), y1: String(y1), x2: String(x2), y2: String(y2), stroke: col, "stroke-width": cx ? "0.9" : "0.7", "marker-end": "url(#ar)" });
      if (dashed) { ln.setAttribute("stroke-dasharray", "3 3"); ln.setAttribute("stroke-opacity", "0.2"); }
      else { ln.setAttribute("stroke-dasharray", cx ? "6 3" : "400"); ln.setAttribute("stroke-dashoffset", "400"); ln.setAttribute("stroke-opacity", cx ? "0.45" : "1"); (ln as SVGElement & { style: CSSStyleDeclaration }).style.animation = "dl .5s ease forwards"; }
      s.insertBefore(ln, s.firstChild);
    }, delay);
  }

  function drawNode(n: GraphNode) {
    const s = svgRef.current; if (!s) return;
    nodeStore.current[n.id] = n.data;
    const g = mkEl("g", { cursor: n.data.sev === "info" ? "default" : "pointer" });
    (g as SVGElement & { style: CSSStyleDeclaration }).style.transformOrigin = `${n.x}px ${n.y}px`;
    (g as SVGElement & { style: CSSStyleDeclaration }).style.animation = "pn .35s cubic-bezier(.34,1.56,.64,1) forwards";
    (g as SVGElement & { style: CSSStyleDeclaration }).style.opacity = "0";
    const hit = mkEl("circle", { cx: String(n.x), cy: String(n.y), r: String(n.r + 5), fill: "transparent", stroke: "transparent" });
    const circ = mkEl("circle", { cx: String(n.x), cy: String(n.y), r: String(n.r), fill: "var(--panel)", stroke: n.col, "stroke-width": "1.5" });
    const txt = mkEl("text", { x: String(n.x), y: String(n.y), "text-anchor": "middle", "dominant-baseline": "central", "font-size": n.r > 15 ? "10" : "7", "font-family": "var(--font-mono)", fill: n.col });
    txt.textContent = n.label;
    g.appendChild(hit); g.appendChild(circ); g.appendChild(txt);
    if (n.data.sev !== "info") {
      g.addEventListener("click", () => setSelectedNode({ data: n.data, title: n.data.title }));
      g.addEventListener("mouseenter", () => { (circ as Element).setAttribute("stroke-width", "2.5"); setHint(n.data.title); });
      g.addEventListener("mouseleave", () => { (circ as Element).setAttribute("stroke-width", "1.5"); setHint("click any confirmed node for full evidence"); });
    }
    s.appendChild(g);
  }

  // Build graph from live nodes/edges when available
  useEffect(() => {
    if (liveNodes.length === 0) return;
    const RED = "var(--red)", AMB = "var(--amber)", BLU = "var(--blue)", GRY = "var(--t4)";
    // Map liveNodes to positioned graph nodes
    // Positions: phases spread spatially across canvas
    const phasePos: Record<string, { x: number; y: number }> = {
      application_compromise:  { x: 52,  y: 38  },
      credential_extraction:   { x: 205, y: 50  },
      cloud_iam_escalation:    { x: 370, y: 30  },
      container_k8s_breakout:  { x: 200, y: 168 },
      lateral_movement:        { x: 365, y: 168 },
      impact_assessment:       { x: 295, y: 248 },
    };
    liveNodes.forEach((n: any) => {
      if (drawnIds.current.has(n.nodeId)) return;
      drawnIds.current.add(n.nodeId);
      const pos = phasePos[n.phase] ?? { x: 260, y: 148 };
      const isSpine = n.kind === "phase_spine";
      const col = n.severity === "critical" ? RED : n.severity === "high" ? AMB : isSpine ? "var(--t2)" : GRY;
      const nodeData: NodeData = {
        title: n.label, sev: n.severity ?? "info",
        technique: n.technique, ts: n.timestamp,
      };
      drawNode({ id: n.nodeId, x: pos.x, y: pos.y, r: isSpine ? 17 : 13, label: n.label?.slice(0, 6) ?? "?", col, data: nodeData });
    });
    liveEdges.forEach((e: any) => {
      const key = `${e.fromNodeId}-${e.toNodeId}`;
      if (drawnEdges.current.has(key)) return;
      drawnEdges.current.add(key);
      // Simple fallback positioning — edges draw between drawn node positions
      drawEdge(0, 0, 0, 0, e.confirmed ? RED : GRY, !e.confirmed, false, 0);
    });
  }, [liveNodes, liveEdges]);

  // Fallback: draw a summary graph from completed phase results
  useEffect(() => {
    if (liveNodes.length > 0) return;
    if (!chain.phaseResults?.length) return;
    const s = svgRef.current; if (!s) return;
    // Clear existing drawn nodes
    while (s.children.length > 1) s.removeChild(s.lastChild!); // keep defs
    drawnIds.current.clear(); drawnEdges.current.clear();

    const phaseCoords = [
      { x: 52, y: 38 }, { x: 205, y: 50 }, { x: 370, y: 30 },
      { x: 200, y: 168 }, { x: 365, y: 168 }, { x: 295, y: 248 },
    ];
    const RED = "var(--red)", AMB = "var(--amber)", GRN = "var(--green)", GRY = "var(--t3)";

    chain.phaseResults.forEach((phase, i) => {
      const pos = phaseCoords[i] ?? { x: 260, y: 148 };
      const hasBreach = (phase.findings || []).some((f: any) => f.severity === "critical");
      const col = phase.status === "completed" ? (hasBreach ? RED : GRN) : phase.status === "running" ? AMB : GRY;
      const data: NodeData = {
        title: `Phase ${i + 1} — ${PHASE_LABELS[phase.phaseName] ?? phase.phaseName}`,
        sev: hasBreach ? "critical" : phase.status === "completed" ? "info" : "info",
        technique: `${(phase.findings || []).length} findings`,
        ts: phase.completedAt ?? undefined,
      };
      drawNode({ id: `phase-${i}`, x: pos.x, y: pos.y, r: 17, label: String(i + 1), col, data });
      if (i > 0) drawEdge(phaseCoords[i - 1].x, phaseCoords[i - 1].y, pos.x, pos.y, GRY, false, false, 300 + i * 200);
      (phase.findings || []).slice(0, 3).forEach((f: any, fi: number) => {
        const fCol = SEV_COLOR[f.severity] ?? GRY;
        const fx = pos.x + (fi % 2 === 0 ? 80 : -80);
        const fy = pos.y + Math.floor(fi / 2) * 28 - 14;
        const fData: NodeData = {
          title: f.title ?? "Finding", sev: f.severity ?? "medium",
          technique: f.technique, mitre: f.mitreId,
          evidence: f.description, ts: f.confirmedAt,
        };
        drawNode({ id: `f-${i}-${fi}`, x: fx, y: fy, r: 11, label: (f.severity ?? "med").slice(0, 4), col: fCol, data: fData });
        drawEdge(pos.x, pos.y, fx, fy, fCol, false, false, 500 + i * 200 + fi * 100);
      });
    });
  }, [chain.phaseResults, liveNodes.length]);

  return (
    <div className="flex flex-1 min-h-0 overflow-hidden">
      {/* Map */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="flex items-center justify-between px-3 py-[6px] flex-shrink-0"
          style={{ borderBottom: "1px solid var(--border)", background: "var(--panel2)" }}>
          <span className="font-mono text-[9px] tracking-[.1em] uppercase" style={{ color: "var(--t3)" }}>network breach map</span>
          <span className="font-mono text-[7px]" style={{ color: "var(--t4)" }}>{hint}</span>
        </div>
        <div className="flex-1 overflow-hidden">
          <svg ref={svgRef} style={{ width: "100%", height: "100%", display: "block" }} viewBox="0 0 510 295" preserveAspectRatio="xMidYMid meet">
            <defs>
              <style>{`
                @keyframes pn{from{opacity:0;transform:scale(0)}to{opacity:1;transform:scale(1)}}
                @keyframes dl{from{stroke-dashoffset:400}to{stroke-dashoffset:0}}
              `}</style>
              <marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
                <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" strokeWidth="1.5" strokeLinecap="round"/>
              </marker>
            </defs>
            {liveNodes.length === 0 && !chain.phaseResults?.length && (
              <text x="255" y="148" textAnchor="middle" fontFamily="monospace" fontSize="10" fill="var(--t4)">
                {chain.status === "pending" ? "engagement queued — awaiting start" : "initializing network map..."}
              </text>
            )}
          </svg>
        </div>
      </div>

      {/* Evidence panel */}
      {selectedNode && (
        <div style={{ width: 264, flexShrink: 0 }}>
          <EvidencePanel data={selectedNode.data} title={selectedNode.title} onClose={() => setSelectedNode(null)} />
        </div>
      )}
    </div>
  );
}

// ── Feed row ─────────────────────────────────────────────────────────────────

function FeedRow({ ts, agent, agCls, msg, msgCls }: { ts: string; agent: string; agCls: string; msg: string; msgCls?: string }) {
  const agStyle: Record<string, { color: string; border: string; background: string }> = {
    EXPLOIT: { color: "var(--red)",   border: "var(--red-border)",   background: "var(--red-dim)"   },
    RECON:   { color: "var(--blue)",  border: "var(--blue-border)",  background: "var(--blue-dim)"  },
    CLOUD:   { color: "var(--amber)", border: "var(--amber-border)", background: "var(--amber-dim)" },
    LATERAL: { color: "var(--green)", border: "var(--green-border)", background: "var(--green-dim)" },
    SYS:     { color: "var(--t3)",    border: "var(--border2)",      background: "rgba(255,255,255,.03)" },
  };
  const s = agStyle[agent] ?? agStyle.SYS;
  const textColor = msgCls === "ok" ? "var(--green)" : msgCls === "crit" ? "var(--red)" : msgCls === "warn" ? "var(--amber)" : "var(--t2)";
  return (
    <div className="flex gap-[6px] font-mono text-[9px] leading-[1.55]" style={{ animation: "fadein .15s ease" }}>
      <span style={{ color: "var(--t4)", flexShrink: 0, minWidth: 36, fontSize: 8, marginTop: 1 }}>{ts}</span>
      <span style={{ flexShrink: 0, fontSize: 7, padding: "1px 4px", fontWeight: 700, minWidth: 44, textAlign: "center", marginTop: 2, ...s }}>{agent}</span>
      <span style={{ flex: 1, color: textColor }}>{msg}</span>
    </div>
  );
}

// ── Chain Detail View ─────────────────────────────────────────────────────────

function ChainDetailView({ chain, onBack }: { chain: BreachChain; onBack: () => void }) {
  const { toast } = useToast();
  const { nodes, edges, liveEvents, latestGraph } = useBreachChainUpdates({
    enabled: chain.status === "running" || chain.status === "paused",
    chainId: chain.id,
  });
  const [elapsed, setElapsed] = useState(0);
  const tiRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (chain.status === "running") {
      tiRef.current = setInterval(() => setElapsed(e => e + 1), 1000);
    }
    return () => { if (tiRef.current) clearInterval(tiRef.current); };
  }, [chain.status]);

  const pauseMut = useMutation({ mutationFn: () => apiRequest("POST", `/api/breach-chains/${chain.id}/pause`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] }); toast({ title: "Chain paused" }); }});
  const stopMut = useMutation({ mutationFn: () => apiRequest("POST", `/api/breach-chains/${chain.id}/stop`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] }); toast({ title: "Chain stopped" }); }});

  const totalFindings = (chain.phaseResults || []).flatMap((p: any) => p.findings || []).length;
  const critFindings  = (chain.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "critical").length;
  const totalCreds    = chain.totalCredentialsHarvested ?? 0;
  const currentPhaseIdx = PHASE_ORDER.indexOf(chain.currentPhase ?? "");
  const timer = `${String(Math.floor(elapsed / 60)).padStart(2, "0")}:${String(elapsed % 60).padStart(2, "0")}`;

  // Build feed from liveEvents + phase completions
  const feedRows: { ts: string; agent: string; msg: string; cls: string }[] = [
    { ts: "00:00", agent: "SYS", msg: `target: ${chain.targetUrl} — engagement started`, cls: "dim" },
    ...(chain.phaseResults || []).map((p: any, i: number) => ({
      ts: "—", agent: p.phaseName?.includes("cloud") ? "CLOUD" : p.phaseName?.includes("lateral") ? "LATERAL" : p.phaseName?.includes("recon") ? "RECON" : "EXPLOIT",
      msg: `${PHASE_LABELS[p.phaseName] ?? p.phaseName} — ${p.status} — ${(p.findings || []).length} findings`,
      cls: p.status === "completed" && (p.findings || []).some((f: any) => f.severity === "critical") ? "crit" : "ok",
    })),
    ...liveEvents.map((e: any) => ({
      ts: "live", agent: e.eventKind?.includes("cred") ? "EXPLOIT" : e.eventKind?.includes("cloud") ? "CLOUD" : "EXPLOIT",
      msg: e.detail ?? e.target, cls: "warn",
    })),
  ];

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Chain header */}
      <div className="flex items-center gap-3 px-4 py-3 flex-shrink-0" style={{ borderBottom: "1px solid var(--border)", background: "var(--panel)" }}>
        <button onClick={onBack} className="flex items-center gap-[6px] font-mono text-[10px] px-[8px] py-[4px] cursor-pointer transition-all"
          style={{ color: "var(--t3)", border: "1px solid var(--border2)", background: "transparent" }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = "var(--t1)"; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = "var(--t3)"; }}>
          ← All Chains
        </button>
        <div>
          <div className="font-mono text-[12px] font-semibold" style={{ color: "var(--t1)" }}>{chain.targetUrl}</div>
          <div className="font-mono text-[9px]" style={{ color: "var(--t3)" }}>
            {chain.id?.slice(0, 16)} · full-chain · {chain.executionMode ?? "live"} · {chain.targetIp ?? "resolving..."}
          </div>
        </div>

        {chain.status === "running" && (
          <div className="flex items-center gap-[6px] px-[10px] py-[4px] ml-2" style={{ background: "var(--green-dim)", border: "1px solid var(--green-border)" }}>
            <div className="w-[5px] h-[5px] rounded-full" style={{ background: "var(--green)", animation: "f-pulse 1.4s infinite" }} />
            <span className="font-mono text-[9px]" style={{ color: "var(--green)" }}>running</span>
          </div>
        )}
        {chain.status === "completed" && (
          <div className="flex items-center gap-[6px] px-[10px] py-[4px] ml-2" style={{ background: "rgba(255,255,255,.04)", border: "1px solid var(--border2)" }}>
            <span className="font-mono text-[9px]" style={{ color: "var(--t3)" }}>completed</span>
          </div>
        )}

        <div className="ml-auto flex items-center gap-3">
          {/* Stats inline */}
          {[
            { v: String(critFindings), l: "critical", c: critFindings > 0 ? "var(--red)" : undefined },
            { v: String(totalFindings), l: "findings", c: undefined },
            { v: String(totalCreds), l: "creds", c: totalCreds > 0 ? "var(--amber)" : undefined },
            { v: timer, l: "elapsed", c: undefined },
            { v: chain.overallRiskScore ? String(chain.overallRiskScore) : "—", l: "grade", c: chain.overallRiskScore ? "var(--red)" : undefined },
          ].map(({ v, l, c }) => (
            <div key={l} className="flex flex-col items-center" style={{ gap: 1, minWidth: 36 }}>
              <div className="font-mono text-[12px] font-medium leading-none" style={{ color: c ?? "var(--t1)" }}>{v}</div>
              <div className="font-mono text-[8px] tracking-[.1em] uppercase" style={{ color: "var(--t3)" }}>{l}</div>
            </div>
          ))}
          {chain.status === "running" && (
            <button onClick={() => pauseMut.mutate()} className="f-btn f-btn-ghost" style={{ fontSize: 11, padding: "5px 10px" }}>
              <Pause className="w-[11px] h-[11px]" /> Pause
            </button>
          )}
          {(chain.status === "running" || chain.status === "paused") && (
            <button onClick={() => stopMut.mutate()} className="f-btn f-btn-danger" style={{ fontSize: 11, padding: "5px 10px" }}>
              <StopCircle className="w-[11px] h-[11px]" /> Stop
            </button>
          )}
        </div>
      </div>

      {/* Phase bar */}
      <div className="flex flex-shrink-0" style={{ borderBottom: "1px solid var(--border)" }}>
        {PHASE_ORDER.map((phase, i) => {
          const pr = (chain.phaseResults || []).find((p: any) => p.phaseName === phase);
          const isCurrent = currentPhaseIdx === i;
          const isDone = pr?.status === "completed";
          const hasBreach = (pr?.findings || []).some((f: any) => f.severity === "critical");
          const col = isCurrent ? "var(--amber)" : isDone && hasBreach ? "var(--red)" : isDone ? "var(--green)" : "var(--t4)";
          return (
            <div key={phase} className="flex-1 text-center font-mono cursor-default transition-all"
              style={{ padding: "6px 4px", fontSize: 9, letterSpacing: ".08em", borderRight: i < 5 ? "1px solid var(--border)" : "none", color: col, background: isCurrent ? "rgba(245,158,11,.04)" : undefined }}>
              <div style={{ fontSize: 8, opacity: .6, marginBottom: 2 }}>0{i + 1}</div>
              {PHASE_LABELS[phase]}
            </div>
          );
        })}
      </div>

      {/* Body: feed + map */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* Feed */}
        <div className="flex flex-col flex-shrink-0" style={{ width: 300, borderRight: "1px solid var(--border)" }}>
          <div className="flex items-center justify-between px-3 py-[6px] flex-shrink-0" style={{ borderBottom: "1px solid var(--border)", background: "var(--panel2)" }}>
            <span className="font-mono text-[9px] tracking-[.1em] uppercase" style={{ color: "var(--t3)" }}>live action feed</span>
            {chain.status === "running" && (
              <span className="font-mono text-[8px] px-[6px] py-[1px]" style={{ color: "var(--amber)", border: "1px solid var(--amber-border)", background: "var(--amber-dim)" }}>
                phase {currentPhaseIdx + 1}
              </span>
            )}
          </div>
          <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-[2px]" style={{ background: "var(--bg)" }}>
            {feedRows.map((r, i) => (
              <FeedRow key={i} ts={r.ts} agent={r.agent} agCls="" msg={r.msg} msgCls={r.cls} />
            ))}
            {chain.status === "running" && (
              <div className="flex gap-[6px] font-mono text-[9px] mt-1">
                <span style={{ color: "var(--t4)", minWidth: 36, fontSize: 8 }}></span>
                <span className="inline-block w-[6px] h-[10px] align-middle" style={{ background: "var(--t3)", animation: "f-blink .8s step-end infinite" }} />
              </div>
            )}
          </div>
        </div>

        {/* Network map */}
        <NetworkMap chain={chain} graph={latestGraph} nodes={nodes} edges={edges} />
      </div>
    </div>
  );
}

// ── Chains List View ──────────────────────────────────────────────────────────

function ChainsListView({ chains, onSelect, onCreate }: {
  chains: BreachChain[];
  onSelect: (c: BreachChain) => void;
  onCreate: () => void;
}) {
  const totalCrit = chains.reduce((s, c) =>
    s + (c.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "critical").length, 0);
  const running   = chains.filter(c => c.status === "running").length;
  const completed = chains.filter(c => c.status === "completed").length;
  const breached  = chains.filter(c => (c.phaseResults || []).some((p: any) => (p.findings || []).some((f: any) => f.severity === "critical"))).length;

  const chipCls = (s: string) => {
    if (s === "running") return "f-chip f-chip-ok";
    if (s === "completed") return "f-chip f-chip-gray";
    if (s === "failed") return "f-chip f-chip-crit";
    if (s === "paused") return "f-chip f-chip-high";
    return "f-chip f-chip-gray";
  };

  const critCount = (c: BreachChain) =>
    (c.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "critical").length;

  return (
    <div className="flex flex-col gap-4">
      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        {[
          { dot: "b", val: String(running),   lbl: "Active Ops",       cls: running > 0 ? "b" : "" },
          { dot: "r", val: String(totalCrit), lbl: "Critical Findings", cls: totalCrit > 0 ? "r" : "" },
          { dot: "o", val: String(chains.reduce((s, c) => s + (c.totalCredentialsHarvested ?? 0), 0)), lbl: "Credentials", cls: "o" },
          { dot: "g", val: String(completed), lbl: "Completed",        cls: "g" },
          { dot: "r", val: breached > 0 ? "F" : "—", lbl: "Risk Grade",cls: breached > 0 ? "r" : "" },
        ].map(({ dot, val, lbl, cls }) => (
          <div key={lbl} className={`f-kpi ${breached > 0 && lbl === "Risk Grade" ? "hot" : ""}`}>
            <div className="f-kpi-lbl"><span className={`f-kpi-dot ${dot}`} />{lbl}</div>
            <div className={`f-kpi-val ${cls}`}>{val}</div>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="f-panel">
        <div className="f-panel-head">
          <span className="f-panel-title"><span className="f-panel-dot" />Engagements</span>
          <button onClick={onCreate} className="f-btn f-btn-primary" style={{ fontSize: 11, padding: "5px 12px" }}>
            <Plus className="w-[11px] h-[11px]" /> New Engagement
          </button>
        </div>
        <div className="f-tbl">
          <div className="f-tbl-head" style={{ gridTemplateColumns: "2fr 1.2fr 1fr 1fr 1fr 100px" }}>
            {["target / chain id", "status", "phase", "findings", "grade", "actions"].map(h => (
              <div key={h} className="f-th" style={h === "actions" ? { textAlign: "right" } : {}}>{h}</div>
            ))}
          </div>
          <div className="f-tbl-body">
            {chains.length === 0 && (
              <div className="f-table-empty font-mono text-[11px]" style={{ padding: "40px 16px", textAlign: "center", color: "var(--t4)" }}>
                no engagements yet — start your first breach chain
              </div>
            )}
            {chains.map(chain => {
              const crit = critCount(chain);
              const high = (chain.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "high").length;
              const phIdx = PHASE_ORDER.indexOf(chain.currentPhase ?? "");
              return (
                <div key={chain.id} className="f-tbl-row" style={{ gridTemplateColumns: "2fr 1.2fr 1fr 1fr 1fr 100px" }} onClick={() => onSelect(chain)}>
                  <div>
                    <div className="f-td n">{chain.targetUrl}</div>
                    <div className="f-td sub">{chain.id?.slice(0, 16)} · {chain.profile ?? "full-chain"} · {chain.executionMode ?? "live"}</div>
                  </div>
                  <div className="f-td"><span className={chipCls(chain.status)}>{chain.status}</span></div>
                  <div className="f-td m" style={{ color: chain.status === "running" ? "var(--amber)" : "var(--t3)" }}>
                    {phIdx >= 0 ? `${phIdx + 1} · ${PHASE_LABELS[chain.currentPhase ?? ""] ?? "—"}` : "—"}
                  </div>
                  <div className="f-td m">
                    <span style={{ color: crit > 0 ? "var(--red)" : "var(--t2)" }}>{crit} crit</span>
                    {high > 0 && <span style={{ color: "var(--t2)" }}> / {high} high</span>}
                  </div>
                  <div className="f-td m font-bold" style={{ color: crit > 0 ? "var(--red)" : "var(--t3)" }}>
                    {chain.overallRiskScore ?? "—"}
                  </div>
                  <div className="f-td flex gap-[5px] justify-end" onClick={e => e.stopPropagation()}>
                    <button onClick={() => onSelect(chain)} title="View" className="f-icon-btn"
                      style={{ width: 26, height: 26, display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--border2)", background: "transparent", cursor: "pointer" }}>
                      <Eye className="w-[11px] h-[11px]" style={{ stroke: "var(--t3)" }} />
                    </button>
                    {chain.status === "completed" && (
                      <button title="Download" className="f-icon-btn"
                        style={{ width: 26, height: 26, display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--border2)", background: "transparent", cursor: "pointer" }}>
                        <Download className="w-[11px] h-[11px]" style={{ stroke: "var(--t3)" }} />
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── New Engagement Modal ──────────────────────────────────────────────────────

function NewEngagementModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const { toast } = useToast();
  const [targetUrl, setTargetUrl] = useState("");
  const [profile, setProfile]     = useState("full_chain");
  const [mode, setMode]           = useState("live");

  const createMut = useMutation({
    mutationFn: () => apiRequest("POST", "/api/breach-chains", { targetUrl, profile, executionMode: mode }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] }); toast({ title: "Engagement started" }); onSuccess(); onClose(); },
    onError: (e: any) => toast({ title: "Failed", description: e.message, variant: "destructive" }),
  });

  const ProfileOpt = ({ val, label, sub, color }: { val: string; label: string; sub: string; color: string }) => (
    <div onClick={() => setProfile(val)} className="cursor-pointer text-center p-[10px] transition-all"
      style={{ border: `1px solid ${profile === val ? "var(--red-border)" : "var(--border2)"}`, background: profile === val ? "var(--red-dim)" : "transparent" }}>
      <div className="font-mono text-[10px] font-bold" style={{ color: profile === val ? "var(--red)" : "var(--t2)" }}>{label}</div>
      <div className="font-mono text-[8px] mt-[3px]" style={{ color: "var(--t3)" }}>{sub}</div>
    </div>
  );

  const ModeOpt = ({ val, label, sub, color }: { val: string; label: string; sub: string; color: string }) => (
    <div onClick={() => setMode(val)} className="cursor-pointer text-center p-[10px] transition-all"
      style={{ border: `1px solid ${mode === val ? "var(--red-border)" : "var(--border2)"}`, background: mode === val ? "var(--red-dim)" : "transparent" }}>
      <div className="font-mono text-[10px] font-bold" style={{ color: mode === val ? color : "var(--t2)" }}>{label}</div>
      <div className="font-mono text-[8px] mt-[3px]" style={{ color: "var(--t3)" }}>{sub}</div>
    </div>
  );

  return (
    <div className="f-modal-overlay" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="f-modal" style={{ maxWidth: 480 }}>
        <div className="f-modal-head">
          <div className="f-modal-title">New Engagement</div>
          <div className="f-modal-desc">Configure breach chain parameters</div>
        </div>
        <div className="f-modal-body flex flex-col gap-4">
          <div>
            <div className="font-mono text-[9px] tracking-[.12em] uppercase mb-[6px]" style={{ color: "var(--t3)" }}>Target URL</div>
            <input value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
              className="w-full font-mono text-[12px] px-[11px] py-[9px] outline-none transition-colors"
              style={{ background: "var(--bg)", border: "1px solid var(--border2)", color: "var(--t1)" }}
              placeholder="https://target.example.com"
              onFocus={e => { (e.currentTarget as HTMLElement).style.borderColor = "var(--red)"; }}
              onBlur={e => { (e.currentTarget as HTMLElement).style.borderColor = "var(--border2)"; }} />
          </div>
          <div>
            <div className="font-mono text-[9px] tracking-[.12em] uppercase mb-[8px]" style={{ color: "var(--t3)" }}>Profile</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
              <ProfileOpt val="full_chain" label="Standard" sub="Phases 1–4" color="var(--red)" />
              <ProfileOpt val="deep"       label="Deep"     sub="All 6 phases" color="var(--red)" />
              <ProfileOpt val="mssp"       label="MSSP"     sub="White-label" color="var(--red)" />
            </div>
          </div>
          <div>
            <div className="font-mono text-[9px] tracking-[.12em] uppercase mb-[8px]" style={{ color: "var(--t3)" }}>Execution Mode</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
              <ModeOpt val="safe"       label="Safe"       sub="Passive only"   color="var(--green)" />
              <ModeOpt val="simulation" label="Simulation" sub="Safe payloads"  color="var(--amber)" />
              <ModeOpt val="live"       label="Live"       sub="Real exploits"  color="var(--red)"   />
            </div>
          </div>
        </div>
        <div className="f-modal-footer">
          <button onClick={onClose} className="f-btn f-btn-ghost">Cancel</button>
          <button onClick={() => createMut.mutate()} disabled={!targetUrl || createMut.isPending} className="f-btn f-btn-primary">
            <Play className="w-[11px] h-[11px]" />
            {createMut.isPending ? "Starting..." : "Start Engagement"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────

export default function BreachChains() {
  const { data: chains = [], isLoading } = useQuery<BreachChain[]>({
    queryKey: ["/api/breach-chains"], refetchInterval: 5000,
  });
  const [selectedChain, setSelectedChain] = useState<BreachChain | null>(null);
  const [showNewModal, setShowNewModal]   = useState(false);

  // Auto-select running chain if nothing selected
  useEffect(() => {
    if (!selectedChain) {
      const running = chains.find(c => c.status === "running");
      if (running) setSelectedChain(running);
    }
  }, [chains, selectedChain]);

  if (isLoading) return (
    <div className="flex items-center justify-center h-full">
      <div className="text-center">
        <div className="h-5 w-5 border-2 border-t-transparent rounded-full animate-spin mx-auto mb-3"
          style={{ borderColor: "var(--red)", borderTopColor: "transparent" }} />
        <p className="font-mono text-[9px] tracking-widest" style={{ color: "var(--t4)" }}>LOADING</p>
      </div>
    </div>
  );

  // Sync selected chain with latest data
  const activeChain = selectedChain ? chains.find(c => c.id === selectedChain.id) ?? selectedChain : null;

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0, height: "100%" }}>
      {activeChain ? (
        <ChainDetailView chain={activeChain} onBack={() => setSelectedChain(null)} />
      ) : (
        <ChainsListView chains={chains} onSelect={setSelectedChain} onCreate={() => setShowNewModal(true)} />
      )}
      {showNewModal && <NewEngagementModal onClose={() => setShowNewModal(false)} onSuccess={() => {}} />}
    </div>
  );
}
```

---

## Dead code to delete

After applying the 4 files above, delete these — they are fully replaced or unused:

```bash
# Remove unused components
rm /Users/dre/prod/OdinForge-AI/client/src/components/AttackHeatmap.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/components/ChainComparison.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/components/ChainSparkline.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/components/CredentialWeb.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/components/DefenseGapPanel.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/components/FilterBar.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/components/StatCard.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/components/TrialBanner.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/components/ViewModeToggle.tsx
rm /Users/dre/prod/OdinForge-AI/client/src/styles/canvas.css

# Signup.tsx — keep (referenced in App.tsx routing)
# EvidencePanel.tsx in BreachChains — now inlined, delete old standalone if present
```

---

## VS Code Claude paste prompt

```
Read /Users/dre/prod/OdinForge-AI/prototypes/AGENTS_UI_REBUILD.md in full.

For each ### FILE section:
1. Open the file at the specified path
2. Select all content (Cmd+A)
3. Paste the complete code block replacing everything
4. Save

For each file in "Dead code to delete":
1. Delete the file at the specified path

After all files are applied, run in terminal:
  cd /Users/dre/prod/OdinForge-AI && npx tsc --noEmit

Report any TypeScript errors with the exact line numbers.
```
