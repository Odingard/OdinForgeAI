import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

interface ParticleBackgroundProps {
  className?: string;
  particleCount?: number;
  particleColor?: string;
  particleSize?: number;
  speed?: number;
  opacity?: number;
}

export function ParticleBackground({
  className,
  particleCount = 50,
  particleColor = "#06b6d4",
  particleSize = 2,
  speed = 0.5,
  opacity = 0.3
}: ParticleBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Set canvas size
    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    // Particle class
    class Particle {
      x: number;
      y: number;
      vx: number;
      vy: number;
      size: number;

      constructor() {
        this.x = Math.random() * (canvas?.width || 800);
        this.y = Math.random() * (canvas?.height || 600);
        this.vx = (Math.random() - 0.5) * speed;
        this.vy = (Math.random() - 0.5) * speed;
        this.size = Math.random() * particleSize + 1;
      }

      update() {
        this.x += this.vx;
        this.y += this.vy;

        if (this.x < 0 || this.x > (canvas?.width || 800)) this.vx *= -1;
        if (this.y < 0 || this.y > (canvas?.height || 600)) this.vy *= -1;
      }

      draw() {
        if (!ctx) return;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fillStyle = particleColor;
        ctx.globalAlpha = opacity;
        ctx.fill();
        ctx.globalAlpha = 1;
      }
    }

    // Create particles
    const particles: Particle[] = [];
    for (let i = 0; i < particleCount; i++) {
      particles.push(new Particle());
    }

    // Animation loop
    let animationId: number;
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Update and draw particles
      particles.forEach((particle) => {
        particle.update();
        particle.draw();
      });

      // Draw connections
      ctx.globalAlpha = opacity * 0.5;
      particles.forEach((p1, i) => {
        particles.slice(i + 1).forEach((p2) => {
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < 150) {
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = particleColor;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        });
      });
      ctx.globalAlpha = 1;

      animationId = requestAnimationFrame(animate);
    };
    animate();

    return () => {
      window.removeEventListener("resize", resize);
      cancelAnimationFrame(animationId);
    };
  }, [particleCount, particleColor, particleSize, speed, opacity]);

  return (
    <canvas
      ref={canvasRef}
      className={cn("absolute inset-0 pointer-events-none", className)}
    />
  );
}

export function GridBackground({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "absolute inset-0 grid-bg opacity-20 pointer-events-none",
        className
      )}
      style={{
        maskImage: "linear-gradient(to bottom, black, transparent 50%)",
      }}
    />
  );
}

export function GradientOrb({
  className,
  color1 = "red",
  color2 = "cyan",
  size = "lg"
}: {
  className?: string;
  color1?: string;
  color2?: string;
  size?: "sm" | "md" | "lg" | "xl";
}) {
  const sizeClasses = {
    sm: "h-32 w-32",
    md: "h-48 w-48",
    lg: "h-64 w-64",
    xl: "h-96 w-96",
  };

  return (
    <div
      className={cn(
        "absolute rounded-full blur-3xl opacity-20 animate-pulse pointer-events-none",
        sizeClasses[size],
        className
      )}
      style={{
        background: `radial-gradient(circle, ${color1}, ${color2})`,
        animation: "pulse 8s ease-in-out infinite",
      }}
    />
  );
}

export function ScanLines({ className }: { className?: string }) {
  return (
    <div className={cn("absolute inset-0 pointer-events-none overflow-hidden", className)}>
      <div
        className="absolute inset-0 opacity-10"
        style={{
          backgroundImage: "linear-gradient(0deg, transparent 50%, rgba(0, 255, 255, 0.03) 50%)",
          backgroundSize: "100% 4px",
          animation: "scan 8s linear infinite",
        }}
      />
    </div>
  );
}

export function MatrixRain({ className }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    const columns = Math.floor(canvas.width / 20);
    const drops: number[] = Array(columns).fill(0);

    const matrix = "01";

    let animationId: number;
    const draw = () => {
      ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = "#0f0";
      ctx.font = "12px monospace";

      for (let i = 0; i < drops.length; i++) {
        const text = matrix[Math.floor(Math.random() * matrix.length)];
        ctx.fillText(text, i * 20, drops[i] * 20);

        if (drops[i] * 20 > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }

      animationId = requestAnimationFrame(draw);
    };
    draw();

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className={cn("absolute inset-0 pointer-events-none opacity-20", className)}
    />
  );
}
