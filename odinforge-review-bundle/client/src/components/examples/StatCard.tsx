import { StatCard } from "../StatCard";
import { Target, AlertTriangle, ShieldCheck, Activity, Zap } from "lucide-react";

export default function StatCardExample() {
  return (
    <div className="grid grid-cols-5 gap-4 p-4">
      <StatCard 
        label="Total Evaluations" 
        value={42} 
        icon={Target}
        trend={{ value: 12, isPositive: true }}
      />
      <StatCard 
        label="Active" 
        value={3} 
        icon={Activity}
        colorClass="text-amber-400"
      />
      <StatCard 
        label="Exploitable" 
        value={8} 
        icon={AlertTriangle}
        colorClass="text-red-400"
        trend={{ value: 5, isPositive: false }}
      />
      <StatCard 
        label="Safe" 
        value={31} 
        icon={ShieldCheck}
        colorClass="text-emerald-400"
      />
      <StatCard 
        label="Avg Confidence" 
        value="87%" 
        icon={Zap}
        colorClass="text-cyan-400"
      />
    </div>
  );
}
