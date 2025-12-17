import type { AdversaryProfile } from "@shared/schema";

export interface AdversaryProfileConfig {
  profileType: AdversaryProfile;
  technicalSophistication: number;
  resources: number;
  persistence: number;
  stealth: number;
  targetedAttacks: boolean;
  zerodays: boolean;
  socialEngineering: boolean;
  physicalAccess: boolean;
  typicalTTPs: string[];
  motivations: string[];
  avgDwellTime: number;
  detectionDifficulty: "low" | "medium" | "high" | "very_high";
  attackStyle: string;
  toolsUsed: string[];
  evasionTechniques: string[];
}

export const defaultAdversaryProfiles: Record<AdversaryProfile, AdversaryProfileConfig> = {
  script_kiddie: {
    profileType: "script_kiddie",
    technicalSophistication: 2,
    resources: 1,
    persistence: 2,
    stealth: 1,
    targetedAttacks: false,
    zerodays: false,
    socialEngineering: false,
    physicalAccess: false,
    typicalTTPs: [
      "T1190", // Exploit Public-Facing Application
      "T1078", // Valid Accounts (leaked credentials)
      "T1110", // Brute Force
      "T1059", // Command and Scripting Interpreter
    ],
    motivations: ["curiosity", "notoriety", "minor_financial"],
    avgDwellTime: 1,
    detectionDifficulty: "low",
    attackStyle: "Uses publicly available exploit tools and scripts without deep understanding. Relies on automated scanners and default exploits. Easily detected by standard security controls.",
    toolsUsed: ["Metasploit (default modules)", "SQLmap", "Nmap", "Nikto", "Public exploit scripts"],
    evasionTechniques: ["None - uses tools without modification"],
  },
  opportunistic_criminal: {
    profileType: "opportunistic_criminal",
    technicalSophistication: 4,
    resources: 3,
    persistence: 4,
    stealth: 3,
    targetedAttacks: false,
    zerodays: false,
    socialEngineering: true,
    physicalAccess: false,
    typicalTTPs: [
      "T1566", // Phishing
      "T1486", // Data Encrypted for Impact (ransomware)
      "T1082", // System Information Discovery
      "T1005", // Data from Local System
      "T1071", // Application Layer Protocol
    ],
    motivations: ["financial_gain", "ransomware", "data_theft"],
    avgDwellTime: 7,
    detectionDifficulty: "medium",
    attackStyle: "Opportunistic attacker seeking easy financial gains. Uses phishing campaigns and commodity malware. Will deploy ransomware or steal data for sale. Some operational security but not highly sophisticated.",
    toolsUsed: ["Cobalt Strike (cracked)", "Phishing kits", "Commodity RATs", "Ransomware-as-a-Service"],
    evasionTechniques: ["Basic obfuscation", "Encrypted C2", "Living off the land basics"],
  },
  organized_crime: {
    profileType: "organized_crime",
    technicalSophistication: 6,
    resources: 7,
    persistence: 7,
    stealth: 6,
    targetedAttacks: true,
    zerodays: false,
    socialEngineering: true,
    physicalAccess: false,
    typicalTTPs: [
      "T1566.001", // Spearphishing Attachment
      "T1195", // Supply Chain Compromise
      "T1021", // Remote Services
      "T1486", // Data Encrypted for Impact
      "T1567", // Exfiltration Over Web Service
      "T1070", // Indicator Removal
    ],
    motivations: ["financial_gain", "extortion", "data_theft", "fraud"],
    avgDwellTime: 30,
    detectionDifficulty: "high",
    attackStyle: "Well-funded criminal organization with dedicated operators. Uses custom tooling and sophisticated tactics. Targets high-value organizations for maximum financial return. Will persist for extended periods to maximize extraction.",
    toolsUsed: ["Custom loaders", "Private exploit kits", "Commercial C2 frameworks", "Custom ransomware variants"],
    evasionTechniques: ["Process injection", "Timestomping", "Log deletion", "Anti-forensics", "Encrypted tunneling"],
  },
  insider_threat: {
    profileType: "insider_threat",
    technicalSophistication: 5,
    resources: 4,
    persistence: 8,
    stealth: 7,
    targetedAttacks: true,
    zerodays: false,
    socialEngineering: false,
    physicalAccess: true,
    typicalTTPs: [
      "T1078", // Valid Accounts
      "T1083", // File and Directory Discovery
      "T1005", // Data from Local System
      "T1048", // Exfiltration Over Alternative Protocol
      "T1552", // Unsecured Credentials
      "T1213", // Data from Information Repositories
    ],
    motivations: ["revenge", "financial_gain", "espionage", "sabotage"],
    avgDwellTime: 180,
    detectionDifficulty: "very_high",
    attackStyle: "Trusted insider with legitimate access. Uses authorized credentials and knows internal systems intimately. Actions blend with normal behavior. May exfiltrate data slowly over time or sabotage systems before leaving.",
    toolsUsed: ["Legitimate admin tools", "Personal cloud storage", "USB devices", "Personal email"],
    evasionTechniques: ["Legitimate access patterns", "Data hiding in allowed traffic", "Slow exfiltration", "Credential reuse"],
  },
  nation_state: {
    profileType: "nation_state",
    technicalSophistication: 9,
    resources: 10,
    persistence: 10,
    stealth: 9,
    targetedAttacks: true,
    zerodays: true,
    socialEngineering: true,
    physicalAccess: true,
    typicalTTPs: [
      "T1195.002", // Supply Chain Compromise: Software Supply Chain
      "T1210", // Exploitation of Remote Services
      "T1055", // Process Injection
      "T1003", // OS Credential Dumping
      "T1570", // Lateral Tool Transfer
      "T1041", // Exfiltration Over C2 Channel
      "T1027", // Obfuscated Files or Information
      "T1562", // Impair Defenses
    ],
    motivations: ["espionage", "intellectual_property_theft", "infrastructure_disruption", "strategic_advantage"],
    avgDwellTime: 365,
    detectionDifficulty: "very_high",
    attackStyle: "State-sponsored actor with unlimited resources and patience. Uses zero-days, custom implants, and sophisticated tradecraft. Targets strategic assets for long-term intelligence collection. Employs advanced evasion and may compromise supply chains.",
    toolsUsed: ["Zero-day exploits", "Custom implants", "Hardware implants", "Supply chain compromises", "Proprietary C2 infrastructure"],
    evasionTechniques: ["Firmware-level persistence", "Living off the land", "Traffic blending", "Counter-intelligence", "Multi-stage payloads", "Steganography"],
  },
  apt_group: {
    profileType: "apt_group",
    technicalSophistication: 8,
    resources: 8,
    persistence: 9,
    stealth: 8,
    targetedAttacks: true,
    zerodays: true,
    socialEngineering: true,
    physicalAccess: false,
    typicalTTPs: [
      "T1566.002", // Spearphishing Link
      "T1204", // User Execution
      "T1036", // Masquerading
      "T1055", // Process Injection
      "T1003", // OS Credential Dumping
      "T1560", // Archive Collected Data
      "T1041", // Exfiltration Over C2 Channel
    ],
    motivations: ["espionage", "intellectual_property_theft", "sabotage"],
    avgDwellTime: 200,
    detectionDifficulty: "very_high",
    attackStyle: "Advanced Persistent Threat group with defined objectives. Uses custom malware, sophisticated spearphishing, and patient approach. Maintains long-term access and adapts to defensive measures. May have nation-state backing.",
    toolsUsed: ["Custom malware families", "Modified open-source tools", "Living off the land binaries", "Custom C2 protocols"],
    evasionTechniques: ["Fileless malware", "Memory-only execution", "DLL side-loading", "Encrypted C2", "Time-based execution", "Anti-analysis techniques"],
  },
  hacktivist: {
    profileType: "hacktivist",
    technicalSophistication: 5,
    resources: 4,
    persistence: 6,
    stealth: 3,
    targetedAttacks: true,
    zerodays: false,
    socialEngineering: true,
    physicalAccess: false,
    typicalTTPs: [
      "T1498", // Network Denial of Service
      "T1491", // Defacement
      "T1190", // Exploit Public-Facing Application
      "T1213", // Data from Information Repositories
      "T1565", // Data Manipulation
    ],
    motivations: ["ideology", "political_statement", "activism", "public_attention"],
    avgDwellTime: 3,
    detectionDifficulty: "medium",
    attackStyle: "Ideologically motivated attacker seeking public attention. Uses DDoS, website defacement, and data leaks. Often announces attacks publicly. Variable skill levels within groups. More focused on impact and publicity than stealth.",
    toolsUsed: ["DDoS tools", "Web exploitation frameworks", "Social media for coordination", "Leak sites"],
    evasionTechniques: ["VPNs", "Tor", "Botnets for DDoS", "Minimal - focus on impact not stealth"],
  },
  competitor: {
    profileType: "competitor",
    technicalSophistication: 6,
    resources: 7,
    persistence: 7,
    stealth: 8,
    targetedAttacks: true,
    zerodays: false,
    socialEngineering: true,
    physicalAccess: false,
    typicalTTPs: [
      "T1566", // Phishing
      "T1078", // Valid Accounts
      "T1213", // Data from Information Repositories
      "T1552", // Unsecured Credentials
      "T1048", // Exfiltration Over Alternative Protocol
    ],
    motivations: ["competitive_intelligence", "trade_secrets", "strategic_planning", "market_advantage"],
    avgDwellTime: 90,
    detectionDifficulty: "high",
    attackStyle: "Corporate espionage actor seeking competitive advantage. May hire contractors or criminal groups. Targets R&D, sales data, pricing strategies, and strategic plans. Focuses on data theft rather than disruption. Highly motivated to remain undetected.",
    toolsUsed: ["Commercial spyware", "Hired penetration testers", "Social engineering contractors", "Insider recruitment"],
    evasionTechniques: ["Legitimate-looking traffic", "Cloud service abuse", "Long-term credential theft", "Insider placement"],
  },
};

export function getAdversaryProfileConfig(profileType: AdversaryProfile): AdversaryProfileConfig {
  return defaultAdversaryProfiles[profileType];
}

export function generateAdversaryPromptContext(profileType: AdversaryProfile): string {
  const profile = getAdversaryProfileConfig(profileType);
  
  return `
ADVERSARY SIMULATION CONTEXT:
You are simulating an attack from the perspective of a "${profile.profileType.replace(/_/g, " ").toUpperCase()}" threat actor.

ADVERSARY CHARACTERISTICS:
- Technical Sophistication: ${profile.technicalSophistication}/10
- Resources: ${profile.resources}/10
- Persistence: ${profile.persistence}/10
- Stealth: ${profile.stealth}/10
- Average Dwell Time: ${profile.avgDwellTime} days
- Detection Difficulty: ${profile.detectionDifficulty}

ADVERSARY CAPABILITIES:
- Uses Zero-day Exploits: ${profile.zerodays ? "Yes" : "No"}
- Social Engineering: ${profile.socialEngineering ? "Yes" : "No"}
- Targeted Attacks: ${profile.targetedAttacks ? "Yes" : "No"}
- Physical Access: ${profile.physicalAccess ? "Yes" : "No"}

ATTACK STYLE:
${profile.attackStyle}

TYPICAL TOOLS:
${profile.toolsUsed.join(", ")}

TYPICAL TTPs (MITRE ATT&CK):
${profile.typicalTTPs.join(", ")}

EVASION TECHNIQUES:
${profile.evasionTechniques.join(", ")}

MOTIVATIONS:
${profile.motivations.join(", ")}

SIMULATION INSTRUCTIONS:
- Generate attack paths and techniques consistent with this adversary profile
- Consider the adversary's resource limitations and sophistication level
- A script kiddie would not use zero-days or sophisticated evasion
- A nation-state actor would use patient, stealthy approaches
- Match exploit complexity to the adversary's technical sophistication
- Consider typical dwell time in attack timeline estimates
`;
}

export function adjustFindingsForProfile(
  profileType: AdversaryProfile,
  findings: any
): any {
  const profile = getAdversaryProfileConfig(profileType);
  
  if (profileType === "script_kiddie") {
    if (findings.exploitChains) {
      findings.exploitChains = findings.exploitChains.filter(
        (chain: any) => chain.success_likelihood !== "low" || chain.technique?.startsWith("T1190") || chain.technique?.startsWith("T1110")
      ).slice(0, 3);
    }
  }
  
  if (profileType === "nation_state" || profileType === "apt_group") {
    if (findings.exploitChains) {
      findings.exploitChains = findings.exploitChains.map((chain: any) => ({
        ...chain,
        stealth_approach: "Uses advanced evasion techniques to avoid detection",
        patience_factor: "Will wait for optimal timing and conditions",
      }));
    }
  }
  
  return findings;
}
