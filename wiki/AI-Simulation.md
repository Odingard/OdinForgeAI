# AI vs AI Simulation

OdinForge AI includes a purple team simulation system where Attacker AI competes against Defender AI in iterative rounds.

## Overview

AI vs AI simulations provide:
- **Realistic attack scenarios** - AI-driven attack patterns
- **Defense validation** - Test detection and response capabilities
- **Gap identification** - Discover security blind spots
- **Training value** - Learn from AI-generated TTPs

## How It Works

```
Round 1
┌─────────────────┐     ┌─────────────────┐
│   Attacker AI   │────▶│   Defender AI   │
│                 │     │                 │
│ Plans attack    │     │ Analyzes attack │
│ Executes TTPs   │     │ Detects patterns│
│ Adapts strategy │◀────│ Recommends fix  │
└─────────────────┘     └─────────────────┘
        │                       │
        └───────┬───────────────┘
                │
                ▼
          Next Round
        (Attacker adapts)
```

### Attacker AI

Uses the full AEV agent pipeline:
- Reconnaissance to map attack surface
- Exploit analysis for vulnerabilities
- Lateral movement path discovery
- Multi-vector attack combination
- Business impact assessment

### Defender AI

Analyzes attacks and responds:
- Attack pattern detection
- Control effectiveness assessment
- Response recommendations
- Gap identification
- Priority-based alerts

### Iterative Rounds

Each round:
1. Attacker launches attack based on previous learnings
2. Defender analyzes and attempts to block
3. Results scored for both sides
4. Attacker adapts strategy for next round
5. Repeat until configured rounds complete

## Running Simulations

### From the UI

1. Go to **Simulations** in the sidebar
2. Click **New Simulation**
3. Configure:
   - **Target Asset** - What to simulate attacking
   - **Scenario** - Attack type or custom description
   - **Rounds** - Number of iterations (1-10)
   - **Priority** - Simulation urgency
4. Click **Start Simulation**
5. Watch rounds execute in real-time
6. Review results when complete

### Quick-Start Templates

Pre-configured scenarios:

| Template | Description |
|----------|-------------|
| Web Application Breach | Attack on web app with SQLi, XSS |
| Cloud Infrastructure Attack | Cloud misconfiguration exploitation |
| Ransomware Simulation | File encryption and lateral spread |
| Data Exfiltration | Sensitive data theft scenario |
| Insider Threat | Malicious insider with access |

### From Completed Evaluations

Launch simulations from AEV results:
1. Go to an evaluation's detail page
2. Click **Run Simulation** button
3. Parameters pre-filled from evaluation
4. Adjust rounds and priority as needed
5. Start simulation

## Understanding Results

### Performance Metrics

| Metric | Description |
|--------|-------------|
| Attacker Success Rate | Percentage of successful attack actions |
| Defender Block Rate | Percentage of attacks detected/blocked |
| Detection Time | How quickly attacks were identified |
| Response Effectiveness | Quality of defensive recommendations |

### Round Details

Each round shows:
- Attack techniques used (MITRE ATT&CK)
- Detection points where defender identified attacks
- Gaps where attacks went undetected
- Defender recommendations for that round

### Purple Team Recommendations

Final output includes:
- Prioritized security gaps
- Specific control improvements
- Detection rule suggestions
- Process enhancements
- Training recommendations

## Configuration Options

### Simulation Settings

| Setting | Description | Range |
|---------|-------------|-------|
| Rounds | Number of attack/defense cycles | 1-10 |
| Priority | Execution priority | Low, Medium, High, Critical |
| Scenario | Attack description or template | Text |

### Adversary Profiles

Simulations can use adversary profiles:
- **Script Kiddie** - Basic techniques, low sophistication
- **Organized Crime** - Moderate resources, financial motivation
- **Nation State** - Advanced TTPs, high stealth
- **Insider Threat** - Internal access and knowledge
- **APT Group** - Persistent, targeted attacks

Profile affects attacker behavior and techniques.

## Best Practices

### Designing Simulations

1. **Start small** - Begin with 2-3 rounds
2. **Use templates** - Leverage pre-built scenarios
3. **Match threat model** - Choose relevant adversary profiles
4. **Focus scope** - Target specific assets or attack types

### Interpreting Results

1. **Look at trends** - How does defender improve across rounds?
2. **Identify patterns** - What attack types succeed most?
3. **Prioritize gaps** - Focus on highest-impact blind spots
4. **Track improvements** - Re-run simulations after fixes

### Acting on Recommendations

1. **Create tickets** - Turn findings into actionable tasks
2. **Update detections** - Implement suggested rules
3. **Enhance controls** - Address identified gaps
4. **Train teams** - Share TTPs with security staff

## Integration

### With AEV Evaluations

- Launch simulations from completed evaluations
- Use evaluation findings as attack starting points
- Validate remediation with follow-up simulations

### With Reports

- Include simulation results in technical reports
- Executive summaries highlight key gaps
- Export for external sharing

### With Governance

- Simulations respect execution mode settings
- Kill switch stops active simulations
- Scope rules apply to simulation targets
