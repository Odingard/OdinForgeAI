import { useEffect, useRef, memo, useMemo } from "react";
import { computeRiskScore, riskScoreColor, riskScoreLabel } from "@/lib/dashboard-transforms";
import { GlowCard } from "@/components/ui/glow-card";

export const RiskScoreGauge = memo(function RiskScoreGauge({ posture }: { posture: any }) {
  const score = computeRiskScore(posture);
  const color = riskScoreColor(score);
  const label = riskScoreLabel(score);

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const timeRef = useRef(0);
  const lastFrameRef = useRef(0);
  const TARGET_FPS = 20;
  const FRAME_INTERVAL = 1000 / TARGET_FPS;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const size = 120;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const outerR = 48;
    const ringW = 6;
    const sweepLen = 0.15;

    function draw(now: number = 0) {
      animRef.current = requestAnimationFrame(draw);
      if (document.hidden) return;
      const elapsed = now - lastFrameRef.current;
      if (elapsed < FRAME_INTERVAL) return;
      lastFrameRef.current = now;

      timeRef.current += 0.008;
      const t = timeRef.current;
      ctx!.clearRect(0, 0, size, size);

      // Grid dots
      ctx!.save();
      ctx!.fillStyle = "rgba(56,189,248,0.04)";
      for (let gx = 0; gx < size; gx += 14) {
        for (let gy = 0; gy < size; gy += 14) {
          ctx!.fillRect(gx, gy, 1, 1);
        }
      }
      ctx!.restore();

      // Background ring
      ctx!.save();
      ctx!.beginPath();
      ctx!.arc(cx, cy, outerR, 0, Math.PI * 2);
      ctx!.strokeStyle = "rgba(56,189,248,0.06)";
      ctx!.lineWidth = ringW;
      ctx!.stroke();
      ctx!.restore();

      // Inner ring
      ctx!.save();
      ctx!.beginPath();
      ctx!.arc(cx, cy, outerR - 12, 0, Math.PI * 2);
      ctx!.strokeStyle = "rgba(56,189,248,0.03)";
      ctx!.lineWidth = 1;
      ctx!.stroke();
      ctx!.restore();

      // Progress arc
      const startAngle = -Math.PI / 2;
      const progress = (score / 100) * Math.PI * 2;

      // Glow pass
      ctx!.save();
      ctx!.beginPath();
      ctx!.arc(cx, cy, outerR, startAngle, startAngle + progress);
      ctx!.strokeStyle = color;
      ctx!.lineWidth = ringW + 4;
      ctx!.lineCap = "round";
      ctx!.globalAlpha = 0.15;
      ctx!.stroke();
      ctx!.restore();

      // Sharp pass
      ctx!.save();
      ctx!.beginPath();
      ctx!.arc(cx, cy, outerR, startAngle, startAngle + progress);
      ctx!.strokeStyle = color;
      ctx!.lineWidth = ringW;
      ctx!.lineCap = "round";
      ctx!.globalAlpha = 0.85;
      ctx!.stroke();
      ctx!.restore();

      // Radar sweep
      const sweepAngle = (t * 1.05) % (Math.PI * 2);
      ctx!.save();
      const grad = ctx!.createConicGradient(sweepAngle - sweepLen, cx, cy);
      grad.addColorStop(0, "transparent");
      grad.addColorStop(0.7, `${color}15`);
      grad.addColorStop(1, `${color}30`);
      ctx!.beginPath();
      ctx!.moveTo(cx, cy);
      ctx!.arc(cx, cy, outerR - 2, sweepAngle - sweepLen, sweepAngle);
      ctx!.closePath();
      ctx!.fillStyle = grad;
      ctx!.fill();
      ctx!.restore();

      // Sweep line
      ctx!.save();
      ctx!.beginPath();
      ctx!.moveTo(cx, cy);
      ctx!.lineTo(
        cx + Math.cos(sweepAngle) * (outerR - 2),
        cy + Math.sin(sweepAngle) * (outerR - 2),
      );
      ctx!.strokeStyle = color;
      ctx!.globalAlpha = 0.4 + Math.sin(t * 3) * 0.1;
      ctx!.lineWidth = 1;
      ctx!.stroke();
      ctx!.restore();

      // Center score
      ctx!.save();
      ctx!.font = "bold 26px 'Inter', system-ui";
      ctx!.fillStyle = color;
      ctx!.textAlign = "center";
      ctx!.textBaseline = "middle";
      ctx!.shadowColor = color;
      ctx!.shadowBlur = 12;
      ctx!.fillText(String(score), cx, cy - 2);
      ctx!.restore();

      // Label
      ctx!.save();
      ctx!.font = "600 7px 'IBM Plex Mono', monospace";
      ctx!.fillStyle = color;
      ctx!.globalAlpha = 0.7;
      ctx!.textAlign = "center";
      ctx!.textBaseline = "middle";
      ctx!.letterSpacing = "1px";
      ctx!.fillText(label.toUpperCase(), cx, cy + 14);
      ctx!.restore();

      // Tick marks
      ctx!.save();
      for (let i = 0; i < 24; i++) {
        const angle = (i / 24) * Math.PI * 2 - Math.PI / 2;
        const isMajor = i % 6 === 0;
        const innerTick = outerR + (isMajor ? 2 : 4);
        const outerTick = outerR + (isMajor ? 7 : 6);
        ctx!.beginPath();
        ctx!.moveTo(cx + Math.cos(angle) * innerTick, cy + Math.sin(angle) * innerTick);
        ctx!.lineTo(cx + Math.cos(angle) * outerTick, cy + Math.sin(angle) * outerTick);
        ctx!.strokeStyle = isMajor ? "rgba(56,189,248,0.2)" : "rgba(56,189,248,0.07)";
        ctx!.lineWidth = isMajor ? 1 : 0.5;
        ctx!.stroke();
      }
      ctx!.restore();

    }

    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [score, color, label]);

  return (
    <GlowCard glowColor="cyan" glowIntensity="sm" glass scanLine className="p-2">
      <div className="flex items-center gap-2 mb-1">
        <span
          className="inline-block h-1.5 w-1.5 rounded-full"
          style={{ backgroundColor: color, boxShadow: `0 0 4px ${color}` }}
        />
        <span
          style={{
            fontSize: 8,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "#475569",
            letterSpacing: 1.5,
            textTransform: "uppercase",
          }}
        >
          Threat Level
        </span>
      </div>
      <div className="flex justify-center">
        <canvas ref={canvasRef} style={{ width: 120, height: 120 }} />
      </div>
    </GlowCard>
  );
});
