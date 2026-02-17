# OdinForge AI — Go-to-Market Plan

**Created**: 2026-02-17
**Status**: Active
**Platform**: OdinForge AI — Adversarial Exposure Validation (AEV)

---

## 1. Content-Led SEO (Highest ROI)

### Comparison Pages
Capture buyers actively evaluating tools. Build SEO-optimized landing pages:

| Page | Target Keyword | Priority |
|------|---------------|----------|
| `/compare/shannon` | OdinForge vs Shannon Security | Done |
| `/compare/pentera` | OdinForge vs Pentera | High |
| `/compare/nodezero` | OdinForge vs NodeZero / Horizon3.ai | High |
| `/compare/attackiq` | OdinForge vs AttackIQ | High |
| `/compare/keygraph` | OdinForge vs Keygraph | Medium |

Use Brand24 competitor monitoring data to prioritize which competitors get the most discussion.

### Problem-Solution Blog Posts
Target search intent with educational content:

- "How to run automated breach simulations without a red team"
- "Continuous security validation for cloud-native environments"
- "Why traditional pentesting is broken (and what to do instead)"
- "AEV explained: Adversarial Exposure Validation for security teams"
- "Breach chain analysis: understanding lateral movement paths"
- "Automated exploit validation vs manual penetration testing"

---

## 2. Community Presence

### Target Communities
| Platform | Where | Approach |
|----------|-------|----------|
| Reddit | r/netsec, r/cybersecurity, r/blueteam, r/sysadmin | Contribute value, don't pitch. Answer questions about attack simulation |
| LinkedIn | Security groups, personal posts | Post 3x/week: trends, AEV concepts, breach chain insights |
| Hacker News | Show HN, technical discussions | Share technical deep-dives, not product pitches |
| Twitter/X | Infosec accounts, breach news | Engage with commentary, share OdinForge perspective |

### Rules of Engagement
- Lead with value, not product
- Build relationships before asking for anything
- Link to OdinForge only when genuinely helpful
- Respond to every comment/reply within 24 hours

---

## 3. Product Hunt Launch

**Timeline**: Prep in Week 2, launch Week 3

### Prep Checklist
- [ ] 1-minute demo video showing breach chain simulation
- [ ] Compelling tagline: "Autonomous breach simulation — find what attackers find, before they do"
- [ ] 5-10 people ready to upvote and comment on launch day
- [ ] Hunter badge and maker profile set up
- [ ] Respond to every comment within 30 minutes

### Launch Day
- Tuesday or Wednesday (highest traffic days)
- Post between 12:01 AM PT and 3:00 AM PT for maximum runway
- Share on all social channels simultaneously
- Engage actively throughout the entire day

---

## 4. Direct Outreach

### Brand24-Driven Signals
| Signal | Action |
|--------|--------|
| Someone complains about competitor pricing | Reach out with value proposition |
| Someone asks "best BAS tool?" | Respond with helpful comparison, mention OdinForge |
| Influencer posts about attack simulation | Engage, build relationship first |
| Competitor mentioned negatively | Offer alternative perspective |

### Cold Outreach Strategy
- **Target**: CISOs and security engineers at mid-market companies (100-1000 employees)
- **Lead**: Free breach simulation report for their public-facing assets
- **Channel**: LinkedIn InMail or email (Hunter.io for discovery)
- **Format**: 3 sentences max — problem → what OdinForge does → offer a demo
- **Follow-up**: 3-touch sequence over 2 weeks, then stop

---

## 5. Partnerships & Integrations

### Priority Partners
1. **MSSPs (Managed Security Service Providers)** — Multi-tenant architecture fits perfectly. They serve multiple clients and need scalable tooling
2. **Security consultancies** — Partner program for white-label or resale
3. **Cloud marketplaces** — AWS, Azure, GCP marketplace listings (when ready)

### Integration Opportunities
- SIEM integrations (Splunk, Sentinel, QRadar)
- Ticketing (Jira, ServiceNow)
- Notification (Slack, Teams, PagerDuty)

---

## 6. Tool Directories & Listings

Submit to:
- [ ] AlternativeTo
- [ ] G2
- [ ] ToolsWatch
- [ ] Product Hunt (see Section 3)
- [ ] Capterra
- [ ] GetApp
- [ ] SourceForge

---

## 7. Trial Strategy

### Time-Limited Free Trial
- **Duration**: 14 days from signup
- **Access**: Full platform features (no feature gating during trial)
- **Limits**: Usage caps (e.g., max 5 breach simulations, 10 evaluations)
- **Enforcement**: Server-side expiration check on every authenticated request
- **Conversion**: Email nurture sequence during trial + in-app upgrade prompts at day 7, 12, 14
- **Post-trial**: Read-only access to existing data, no new scans/simulations

### Implementation
- `trial_expires_at` timestamp on user/organization record
- Middleware check: if trial expired and no active subscription → block write operations
- Grace period: 3 days after expiration with reduced functionality
- Data retention: 30 days after trial ends, then purge

---

## 8. What NOT To Do

- Don't pay for ads yet — brand isn't established enough for paid to convert
- Don't build features nobody asked for — let market feedback drive roadmap
- Don't spread too thin — pick 2-3 channels and go deep
- Don't cold-pitch on social media — it destroys credibility
- Don't launch on Product Hunt before the demo video is polished

---

## 9. 14-Day Brand24 Trial Plan

### Days 1-3: Competitive Intelligence
- **Project 1** (DONE): Competitor monitoring — Shannon, Keygraph, NodeZero, Horizon3, Pentera, AttackIQ
- Analyze: Where are competitors being discussed? What are people saying?
- Export: Top mentions, sentiment breakdown, key influencers

### Days 3-7: Buyer Intent Monitoring
- **Project 2**: Keywords — "breach simulation tool", "automated pentesting", "BAS platform", "attack simulation software", "security validation tool"
- Identify: Who is actively looking for solutions?
- Engage: Respond to relevant threads/posts with value

### Days 7-14: Engage & Build
- **Project 3**: Category — "adversarial exposure validation", "continuous security testing", "red team automation"
- **Project 4**: Brand — "OdinForge", "odinforgeai" (track brand mentions)
- Engage: Respond to every relevant mention within 24 hours
- Report: Export full 14-day dataset before trial ends

---

## 10. First 48 Hours Action Items

1. ✅ Save this plan
2. Build comparison pages: `/compare/pentera`, `/compare/nodezero`, `/compare/attackiq`
3. Post on LinkedIn introducing OdinForge with a screen recording of a breach chain simulation
4. Submit to AlternativeTo, G2, ToolsWatch
5. Join 3 relevant LinkedIn groups and start contributing
6. Set up Brand24 Projects 2-4
7. Design trial system (server-side enforcement)
