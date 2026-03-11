import { useQuery } from "@tanstack/react-query";

interface TrendPoint {
  chainId: string;
  assetIds?: string[];
  overallRiskScore: number;
  createdAt: string;
}

interface ChainSparklineProps {
  chainId: string;
  assetIds?: string[];
  width?: number;
  height?: number;
}

export function ChainSparkline({ chainId, width = 80, height = 24 }: ChainSparklineProps) {
  const { data, isLoading } = useQuery<TrendPoint[]>({
    queryKey: ["/api/breach-chains/trend"],
    queryFn: () => fetch("/api/breach-chains/trend").then((r) => r.json()),
    staleTime: 60_000,
  });

  if (isLoading) {
    return <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>—</span>;
  }

  const points = (data ?? [])
    .filter((p) => p.chainId === chainId)
    .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
    .map((p) => p.overallRiskScore);

  if (points.length === 0) {
    return <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>—</span>;
  }

  const last = points[points.length - 1];
  const first = points[0];
  const lineColor = last < first ? "var(--falcon-green)" : last > first ? "var(--falcon-red)" : "var(--falcon-t4)";
  const textColor = lineColor;

  const PAD = 3;
  const chartW = width - PAD * 2;
  const chartH = height - PAD * 2 - 10; // reserve 10px for label

  if (points.length === 1) {
    const cx = PAD + chartW / 2;
    const cy = PAD + chartH / 2;
    return (
      <svg width={width} height={height} style={{ display: "block", overflow: "visible" }}>
        <circle cx={cx} cy={cy} r={3} fill={lineColor} />
        <text x={width / 2} y={height} textAnchor="middle" fontSize={9} fill={textColor} fontFamily="var(--font-mono)">
          {last}
        </text>
      </svg>
    );
  }

  const minScore = Math.min(...points);
  const maxScore = Math.max(...points);
  const range = maxScore - minScore || 1;

  const coords = points.map((score, i) => {
    const x = PAD + (i / (points.length - 1)) * chartW;
    // Invert Y: high score (bad) = high on SVG (near top)
    const y = PAD + ((maxScore - score) / range) * chartH;
    return { x, y };
  });

  const d = coords.reduce((path, pt, i) => {
    if (i === 0) return `M ${pt.x} ${pt.y}`;
    const prev = coords[i - 1];
    const cpx = (prev.x + pt.x) / 2;
    return `${path} C ${cpx} ${prev.y} ${cpx} ${pt.y} ${pt.x} ${pt.y}`;
  }, "");

  return (
    <svg width={width} height={height} style={{ display: "block", overflow: "visible" }}>
      <path d={d} fill="none" stroke={lineColor} strokeWidth={1.5} strokeLinecap="round" />
      <circle cx={coords[coords.length - 1].x} cy={coords[coords.length - 1].y} r={2} fill={lineColor} />
      <text x={width} y={height} textAnchor="end" fontSize={9} fill={textColor} fontFamily="var(--font-mono)">
        {last}
      </text>
    </svg>
  );
}
