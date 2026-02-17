import { useEffect, useRef, useState } from "react";

// Demo breach chain data — a realistic multi-phase attack scenario
const DEMO_NODES = [
  { id: "entry", label: "External Recon", tactic: "Reconnaissance", type: "entry", x: 0, y: 0, detail: "Port scan + service fingerprinting", asset: "perimeter-fw-01" },
  { id: "webapp", label: "Web App Exploit", tactic: "Initial Access", type: "exploit", x: 0, y: 0, detail: "CVE-2025-29810 — Auth bypass in login API", asset: "web-app-prod.example.com" },
  { id: "cred1", label: "Credential Harvest", tactic: "Credential Access", type: "harvest", x: 0, y: 0, detail: "Database connection string in env vars", asset: "postgres-primary" },
  { id: "db", label: "Database Access", tactic: "Collection", type: "pivot", x: 0, y: 0, detail: "Full read access to users table (42K records)", asset: "postgres-primary" },
  { id: "lateral1", label: "Lateral Movement", tactic: "Lateral Movement", type: "pivot", x: 0, y: 0, detail: "SSH with harvested service account key", asset: "k8s-worker-03" },
  { id: "k8s", label: "K8s Pod Escape", tactic: "Privilege Escalation", type: "exploit", x: 0, y: 0, detail: "hostPID: true + nsenter to node", asset: "k8s-worker-03" },
  { id: "cloud", label: "Cloud IAM Escalation", tactic: "Privilege Escalation", type: "exploit", x: 0, y: 0, detail: "Node role → AssumeRole to admin", asset: "AWS account 491720..." },
  { id: "cred2", label: "Secret Store Access", tactic: "Credential Access", type: "harvest", x: 0, y: 0, detail: "AWS Secrets Manager — 23 secrets exfiltrated", asset: "us-east-1 secrets" },
  { id: "impact", label: "Full Compromise", tactic: "Impact", type: "objective", x: 0, y: 0, detail: "Domain admin + cloud admin achieved", asset: "entire environment" },
];

const DEMO_EDGES = [
  { from: "entry", to: "webapp", technique: "T1190", prob: 0.92, label: "Exploit Public-Facing App" },
  { from: "webapp", to: "cred1", technique: "T1552", prob: 0.88, label: "Unsecured Credentials" },
  { from: "cred1", to: "db", technique: "T1078", prob: 0.95, label: "Valid Accounts" },
  { from: "webapp", to: "lateral1", technique: "T1021", prob: 0.74, label: "Remote Services (SSH)" },
  { from: "lateral1", to: "k8s", technique: "T1611", prob: 0.81, label: "Container Escape" },
  { from: "k8s", to: "cloud", technique: "T1548", prob: 0.67, label: "Abuse Elevation Control" },
  { from: "cloud", to: "cred2", technique: "T1528", prob: 0.91, label: "Steal App Access Token" },
  { from: "cred2", to: "impact", technique: "T1486", prob: 0.85, label: "Data Encrypted for Impact" },
  { from: "db", to: "lateral1", technique: "T1021", prob: 0.62, label: "Credential Reuse" },
];

const TACTICS_COLORS: Record<string, string> = {
  "Reconnaissance": "#64748b",
  "Initial Access": "#ef4444",
  "Credential Access": "#f59e0b",
  "Collection": "#8b5cf6",
  "Lateral Movement": "#3b82f6",
  "Privilege Escalation": "#ec4899",
  "Impact": "#dc2626",
};

const NODE_COLORS: Record<string, { bg: string; border: string; glow: string }> = {
  entry: { bg: "#0f172a", border: "#64748b", glow: "rgba(100,116,139,0.3)" },
  exploit: { bg: "#1a0a0a", border: "#ef4444", glow: "rgba(239,68,68,0.4)" },
  harvest: { bg: "#1a1400", border: "#f59e0b", glow: "rgba(245,158,11,0.4)" },
  pivot: { bg: "#0a0a1a", border: "#3b82f6", glow: "rgba(59,130,246,0.4)" },
  objective: { bg: "#1a0505", border: "#dc2626", glow: "rgba(220,38,38,0.5)" },
};

function layoutNodes(width: number, height: number) {
  const nodes = DEMO_NODES.map((n) => ({ ...n }));
  const cx = width / 2;
  const cy = height / 2;
  const radiusX = Math.min(width * 0.38, 420);
  const radiusY = Math.min(height * 0.38, 320);

  // Arrange in a flowing arc pattern
  const positions = [
    { ax: -0.85, ay: -0.6 },   // entry — top left
    { ax: -0.45, ay: -0.85 },  // webapp — top
    { ax: 0.15, ay: -0.7 },    // cred1 — top right
    { ax: 0.65, ay: -0.35 },   // db — right
    { ax: -0.1, ay: 0.0 },     // lateral1 — center
    { ax: 0.5, ay: 0.25 },     // k8s — center right
    { ax: -0.55, ay: 0.45 },   // cloud — bottom left
    { ax: 0.15, ay: 0.65 },    // cred2 — bottom center
    { ax: 0.6, ay: 0.85 },     // impact — bottom right
  ];

  nodes.forEach((node, i) => {
    node.x = cx + positions[i].ax * radiusX;
    node.y = cy + positions[i].ay * radiusY;
  });

  return nodes;
}

export default function DemoBreachChain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [dims, setDims] = useState({ w: 1200, h: 800 });
  const nodesRef = useRef(layoutNodes(1200, 800));
  const timeRef = useRef(0);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      const w = Math.max(width, 600);
      const h = Math.max(height, 500);
      setDims({ w, h });
      nodesRef.current = layoutNodes(w, h);
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = dims.w * dpr;
    canvas.height = dims.h * dpr;
    ctx.scale(dpr, dpr);

    const nodes = nodesRef.current;
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));

    function draw() {
      timeRef.current += 0.012;
      const t = timeRef.current;
      ctx!.clearRect(0, 0, dims.w, dims.h);

      // Draw edges
      DEMO_EDGES.forEach((edge, i) => {
        const from = nodeMap.get(edge.from)!;
        const to = nodeMap.get(edge.to)!;

        // Animated dash offset
        const dashOffset = -t * 40 + i * 20;

        // Edge glow
        ctx!.save();
        ctx!.strokeStyle = `rgba(56, 189, 248, ${0.08 + Math.sin(t + i) * 0.03})`;
        ctx!.lineWidth = 6;
        ctx!.beginPath();
        ctx!.moveTo(from.x, from.y);

        // Curved edges
        const mx = (from.x + to.x) / 2 + (i % 2 === 0 ? 30 : -30);
        const my = (from.y + to.y) / 2 + (i % 3 === 0 ? -20 : 20);
        ctx!.quadraticCurveTo(mx, my, to.x, to.y);
        ctx!.stroke();
        ctx!.restore();

        // Edge line
        ctx!.save();
        ctx!.strokeStyle = `rgba(56, 189, 248, ${0.25 + edge.prob * 0.2})`;
        ctx!.lineWidth = 1.5;
        ctx!.setLineDash([6, 8]);
        ctx!.lineDashOffset = dashOffset;
        ctx!.beginPath();
        ctx!.moveTo(from.x, from.y);
        ctx!.quadraticCurveTo(mx, my, to.x, to.y);
        ctx!.stroke();
        ctx!.restore();

        // Animated particle along edge
        const particleT = ((t * 0.3 + i * 0.15) % 1);
        const pt = 1 - particleT;
        const px = pt * pt * from.x + 2 * pt * particleT * mx + particleT * particleT * to.x;
        const py = pt * pt * from.y + 2 * pt * particleT * my + particleT * particleT * to.y;

        ctx!.save();
        ctx!.beginPath();
        ctx!.arc(px, py, 3, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(56, 189, 248, ${0.7 + Math.sin(t * 3) * 0.3})`;
        ctx!.fill();
        ctx!.beginPath();
        ctx!.arc(px, py, 8, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(56, 189, 248, 0.15)`;
        ctx!.fill();
        ctx!.restore();

        // Arrow head
        const arrowT = 0.85;
        const apt = 1 - arrowT;
        const ax = apt * apt * from.x + 2 * apt * arrowT * mx + arrowT * arrowT * to.x;
        const ay = apt * apt * from.y + 2 * apt * arrowT * my + arrowT * arrowT * to.y;
        const dx = to.x - mx;
        const dy = to.y - my;
        const angle = Math.atan2(dy, dx);

        ctx!.save();
        ctx!.translate(ax, ay);
        ctx!.rotate(angle);
        ctx!.fillStyle = `rgba(56, 189, 248, 0.5)`;
        ctx!.beginPath();
        ctx!.moveTo(6, 0);
        ctx!.lineTo(-4, -4);
        ctx!.lineTo(-4, 4);
        ctx!.closePath();
        ctx!.fill();
        ctx!.restore();

        // Technique label at midpoint
        ctx!.save();
        ctx!.font = "10px 'IBM Plex Mono', monospace";
        ctx!.fillStyle = "rgba(148, 163, 184, 0.5)";
        ctx!.textAlign = "center";
        ctx!.fillText(edge.technique, mx, my - 8);
        ctx!.restore();
      });

      // Draw nodes
      nodes.forEach((node) => {
        const colors = NODE_COLORS[node.type] || NODE_COLORS.pivot;
        const isHovered = hoveredNode === node.id;
        const pulse = 1 + Math.sin(t * 2 + nodes.indexOf(node)) * 0.04;
        const r = (isHovered ? 32 : 26) * pulse;

        // Outer glow
        const gradient = ctx!.createRadialGradient(node.x, node.y, r * 0.5, node.x, node.y, r * 2.5);
        gradient.addColorStop(0, colors.glow);
        gradient.addColorStop(1, "transparent");
        ctx!.save();
        ctx!.fillStyle = gradient;
        ctx!.beginPath();
        ctx!.arc(node.x, node.y, r * 2.5, 0, Math.PI * 2);
        ctx!.fill();
        ctx!.restore();

        // Node circle
        ctx!.save();
        ctx!.beginPath();
        ctx!.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx!.fillStyle = colors.bg;
        ctx!.fill();
        ctx!.strokeStyle = colors.border;
        ctx!.lineWidth = isHovered ? 2.5 : 1.5;
        ctx!.stroke();
        ctx!.restore();

        // Node icon (simple shapes)
        ctx!.save();
        ctx!.fillStyle = colors.border;
        ctx!.font = `${isHovered ? 14 : 12}px sans-serif`;
        ctx!.textAlign = "center";
        ctx!.textBaseline = "middle";
        const icons: Record<string, string> = {
          entry: "\u25C9",     // target
          exploit: "\u26A1",   // lightning
          harvest: "\u{1F511}",// key
          pivot: "\u21C4",     // arrows
          objective: "\u2622", // biohazard
        };
        ctx!.fillText(icons[node.type] || "\u25CF", node.x, node.y);
        ctx!.restore();

        // Node label
        ctx!.save();
        ctx!.font = "bold 11px 'Sora', sans-serif";
        ctx!.fillStyle = isHovered ? "#f1f5f9" : "#cbd5e1";
        ctx!.textAlign = "center";
        ctx!.fillText(node.label, node.x, node.y + r + 16);

        // Tactic label
        ctx!.font = "9px 'IBM Plex Mono', monospace";
        const tacticColor = TACTICS_COLORS[node.tactic] || "#64748b";
        ctx!.fillStyle = tacticColor;
        ctx!.fillText(node.tactic.toUpperCase(), node.x, node.y + r + 30);
        ctx!.restore();

        // Asset label on hover
        if (isHovered) {
          ctx!.save();
          ctx!.font = "10px 'IBM Plex Mono', monospace";
          ctx!.fillStyle = "rgba(56, 189, 248, 0.7)";
          ctx!.textAlign = "center";
          ctx!.fillText(node.asset, node.x, node.y - r - 20);
          ctx!.fillStyle = "rgba(148, 163, 184, 0.6)";
          ctx!.fillText(node.detail, node.x, node.y - r - 8);
          ctx!.restore();
        }
      });

      animRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [dims, hoveredNode]);

  // Mouse hit detection
  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const nodes = nodesRef.current;
    let found: string | null = null;
    for (const node of nodes) {
      const dx = mx - node.x;
      const dy = my - node.y;
      if (dx * dx + dy * dy < 900) {
        found = node.id;
        break;
      }
    }
    setHoveredNode(found);
  };

  return (
    <div
      style={{
        background: "#06090f",
        minHeight: "100vh",
        fontFamily: "'Sora', 'DM Sans', sans-serif",
        color: "#f1f5f9",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "20px 32px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          borderBottom: "1px solid rgba(56,189,248,0.08)",
          background: "rgba(6,9,15,0.9)",
          backdropFilter: "blur(12px)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ fontWeight: 800, fontSize: 18, letterSpacing: -0.5 }}>
            ODIN<span style={{ color: "#38bdf8" }}>FORGE</span>
          </span>
          <span
            style={{
              fontSize: 11,
              fontFamily: "'IBM Plex Mono', monospace",
              color: "#38bdf8",
              background: "rgba(56,189,248,0.1)",
              padding: "4px 12px",
              borderRadius: 100,
              border: "1px solid rgba(56,189,248,0.15)",
            }}
          >
            BREACH CHAIN SIMULATION
          </span>
        </div>
        <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 10, color: "#64748b", fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 1 }}>Risk Score</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: "#ef4444", letterSpacing: -1 }}>94<span style={{ fontSize: 14, color: "#64748b" }}>/100</span></div>
          </div>
          <div style={{ width: 1, height: 36, background: "rgba(56,189,248,0.1)" }} />
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 10, color: "#64748b", fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 1 }}>Time to Compromise</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: "#f59e0b", letterSpacing: -1 }}>4.2<span style={{ fontSize: 14, color: "#64748b" }}> min</span></div>
          </div>
          <div style={{ width: 1, height: 36, background: "rgba(56,189,248,0.1)" }} />
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 10, color: "#64748b", fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 1 }}>Assets Compromised</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: "#38bdf8", letterSpacing: -1 }}>7</div>
          </div>
          <div style={{ width: 1, height: 36, background: "rgba(56,189,248,0.1)" }} />
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 10, color: "#64748b", fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 1 }}>Credentials Harvested</div>
            <div style={{ fontSize: 28, fontWeight: 800, color: "#a855f7", letterSpacing: -1 }}>12</div>
          </div>
        </div>
      </div>

      {/* Kill Chain Bar */}
      <div
        style={{
          display: "flex",
          gap: 2,
          padding: "0 32px",
          background: "rgba(6,9,15,0.6)",
          borderBottom: "1px solid rgba(56,189,248,0.06)",
        }}
      >
        {["Reconnaissance", "Initial Access", "Credential Access", "Collection", "Lateral Movement", "Privilege Escalation", "Impact"].map((tactic) => (
          <div
            key={tactic}
            style={{
              flex: 1,
              padding: "10px 0",
              textAlign: "center",
              fontSize: 10,
              fontFamily: "'IBM Plex Mono', monospace",
              fontWeight: 600,
              letterSpacing: 0.5,
              color: TACTICS_COLORS[tactic] || "#64748b",
              borderBottom: `2px solid ${TACTICS_COLORS[tactic] || "#1e293b"}`,
              textTransform: "uppercase",
            }}
          >
            {tactic}
          </div>
        ))}
      </div>

      {/* Canvas */}
      <div
        ref={containerRef}
        style={{ width: "100%", height: "calc(100vh - 130px)", position: "relative" }}
      >
        <canvas
          ref={canvasRef}
          style={{ width: "100%", height: "100%", cursor: hoveredNode ? "pointer" : "default" }}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setHoveredNode(null)}
        />

        {/* Legend */}
        <div
          style={{
            position: "absolute",
            bottom: 24,
            left: 32,
            display: "flex",
            gap: 20,
            fontSize: 11,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "#64748b",
          }}
        >
          {[
            { color: "#64748b", label: "Entry Point" },
            { color: "#ef4444", label: "Exploit" },
            { color: "#f59e0b", label: "Credential Harvest" },
            { color: "#3b82f6", label: "Lateral Movement" },
            { color: "#dc2626", label: "Objective" },
          ].map((item) => (
            <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: item.color }} />
              {item.label}
            </div>
          ))}
        </div>

        {/* Watermark */}
        <div
          style={{
            position: "absolute",
            bottom: 24,
            right: 32,
            fontSize: 11,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "rgba(56,189,248,0.3)",
          }}
        >
          odinforgeai.com — Autonomous Breach Simulation
        </div>
      </div>
    </div>
  );
}
