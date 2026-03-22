import { AttackPathVisualizer } from "../AttackPathVisualizer";

const mockSteps = [
  {
    id: 1,
    title: "Initial Access via Malformed Header",
    description: "Exploit CVE-2024-1234 by sending crafted X-Forwarded-For header",
    technique: "T1190",
    severity: "critical" as const,
  },
  {
    id: 2,
    title: "Privilege Escalation",
    description: "Leverage misconfigured IAM role to gain elevated permissions",
    technique: "T1068",
    severity: "high" as const,
  },
  {
    id: 3,
    title: "Lateral Movement to Database",
    description: "Use compromised credentials to access internal database",
    technique: "T1021",
    severity: "high" as const,
  },
  {
    id: 4,
    title: "Data Exfiltration",
    description: "Extract sensitive customer PII via DNS tunneling",
    technique: "T1048",
    severity: "critical" as const,
  },
];

export default function AttackPathVisualizerExample() {
  return (
    <div className="p-6 bg-card rounded-lg border border-border max-w-2xl mx-auto">
      <AttackPathVisualizer steps={mockSteps} isExploitable={true} />
    </div>
  );
}
