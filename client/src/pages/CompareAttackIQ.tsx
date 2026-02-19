import { useEffect, useRef } from "react";
import "./compare-shannon.css";

export default function CompareAttackIQ() {
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const els = wrapperRef.current?.querySelectorAll(".cp-reveal");
    if (!els) return;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) entry.target.classList.add("visible");
        });
      },
      { threshold: 0.1, rootMargin: "0px 0px -40px 0px" }
    );
    els.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  return (
    <div className="compare-page" ref={wrapperRef}>
      <div className="cp-grid-bg" />

      <div className="cp-wrapper">
        {/* NAV */}
        <nav className="cp-nav">
          <a href="/" className="cp-nav-logo">
            ODIN<span>FORGE</span>
          </a>
          <a href="#cta" className="cp-nav-cta">
            Start Free Trial &rarr;
          </a>
        </nav>

        {/* HERO */}
        <section className="cp-hero">
          <div className="cp-hero-badge">
            <span className="dot" /> Comparison Guide — Updated February 2026
          </div>
          <h1>
            AttackIQ simulates attacks.
            <br />
            <span className="accent">
              OdinForge proves
              <br />
              they actually work.
            </span>
          </h1>
          <p className="cp-hero-sub">
            AttackIQ is a well-established BAS platform focused on MITRE ATT&CK emulation and
            security control validation. But scripted simulations aren't real exploitation.
            OdinForge goes beyond playbooks — autonomously chaining vulnerabilities to prove
            real-world breach paths in your live environment.
          </p>
          <div className="cp-hero-actions">
            <a href="/signup" className="cp-btn-primary">
              Start Your Free Trial &rarr;
            </a>
            <a href="#comparison" className="cp-btn-secondary">
              Jump to Comparison &darr;
            </a>
          </div>
        </section>

        {/* STATS BAR */}
        <div className="cp-stats-bar">
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">Real</span> Exploits
            </div>
            <div className="cp-stat-label">Actual exploitation, not scripted playbooks</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">Visual</span> Chains
            </div>
            <div className="cp-stat-label">Interactive breach chain visualization</div>
          </div>
          <div className="cp-stat-item">
            <div className="cp-stat-value">
              <span className="hl">0</span> Agents
            </div>
            <div className="cp-stat-label">Agentless &middot; No endpoint deployment</div>
          </div>
        </div>

        {/* COMPARISON TABLE */}
        <section className="cp-section cp-reveal" id="comparison">
          <div className="cp-section-label">Feature Comparison</div>
          <div className="cp-section-title">OdinForge vs AttackIQ — no spin.</div>
          <p className="cp-section-desc">
            AttackIQ validates that your security controls detect known attacks. OdinForge proves
            whether attackers can actually breach your environment.
          </p>

          <table className="cp-table">
            <thead>
              <tr>
                <th>Capability</th>
                <th>&#x2B21; OdinForge</th>
                <th>AttackIQ</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Testing Approach</td>
                <td><span className="cp-check">Autonomous real exploitation</span></td>
                <td><span className="cp-limited">Scripted attack simulation (playbooks)</span></td>
              </tr>
              <tr>
                <td>Deployment</td>
                <td><span className="cp-check">Agentless, SaaS-delivered</span></td>
                <td><span className="cp-limited">Requires endpoint agents for testing</span></td>
              </tr>
              <tr>
                <td>Attack Chaining</td>
                <td><span className="cp-check">Autonomous multi-step breach paths</span></td>
                <td><span className="cp-limited">Pre-defined multi-stage campaigns</span></td>
              </tr>
              <tr>
                <td>MITRE ATT&CK</td>
                <td><span className="cp-check">Full framework mapping</span></td>
                <td><span className="cp-check">CTID founding member, deep alignment</span></td>
              </tr>
              <tr>
                <td>Exploit Validation</td>
                <td><span className="cp-check">Proof-of-exploitation with evidence</span></td>
                <td><span className="cp-miss">Simulates, doesn't exploit</span></td>
              </tr>
              <tr>
                <td>Setup Complexity</td>
                <td><span className="cp-check">Minutes — sign up and scan</span></td>
                <td><span className="cp-miss">Complex, "took a long time" per reviews</span></td>
              </tr>
              <tr>
                <td>Breach Chain Visualization</td>
                <td><span className="cp-check">Interactive animated attack graphs</span></td>
                <td><span className="cp-limited">Dashboard-based (data overload reported)</span></td>
              </tr>
              <tr>
                <td>Cloud Security</td>
                <td><span className="cp-check">AWS, Azure, GCP, Kubernetes</span></td>
                <td><span className="cp-limited">Limited cloud control testing</span></td>
              </tr>
              <tr>
                <td>Remediation Guidance</td>
                <td><span className="cp-check">Prioritized with code-level fixes</span></td>
                <td><span className="cp-limited">Detection rules, unclear deployment guidance</span></td>
              </tr>
              <tr>
                <td>Network Pentesting</td>
                <td><span className="cp-check">Full internal &amp; external assessment</span></td>
                <td><span className="cp-miss">Control validation, not pentesting</span></td>
              </tr>
              <tr>
                <td>Web App Testing</td>
                <td><span className="cp-check">Full OWASP &amp; business logic testing</span></td>
                <td><span className="cp-miss">Not a web app testing tool</span></td>
              </tr>
              <tr>
                <td>Multi-Tenant</td>
                <td><span className="cp-check">Native multi-org with RLS isolation</span></td>
                <td><span className="cp-limited">Enterprise-tier feature</span></td>
              </tr>
              <tr>
                <td>Pricing</td>
                <td><span className="cp-check">Transparent, accessible tiers</span></td>
                <td><span className="cp-limited">Enterprise custom + Flex from $4,995/mo</span></td>
              </tr>
              <tr>
                <td>Free Tier</td>
                <td><span className="cp-check">Free trial, full features</span></td>
                <td><span className="cp-check">AttackIQ Flex free tier (limited)</span></td>
              </tr>
            </tbody>
          </table>
        </section>

        {/* ADVANTAGES */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Why OdinForge</div>
          <div className="cp-section-title">Where OdinForge goes further.</div>
          <p className="cp-section-desc">
            AttackIQ answers "would my controls detect this known attack?" OdinForge answers
            "can an attacker actually breach my environment?"
          </p>

          <div className="cp-advantages-grid">
            <div className="cp-adv-card">
              <div className="cp-adv-number">01</div>
              <div className="cp-adv-title">
                Real exploitation.
                <br />
                Not playbook simulation.
              </div>
              <div className="cp-adv-desc">
                AttackIQ runs pre-scripted attack scenarios against your security controls to
                check if they trigger alerts. That's useful for control validation — but it
                doesn't tell you if an attacker can actually get in. OdinForge autonomously
                exploits real vulnerabilities, chains them together, and proves breach paths with
                evidence.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">APPROACH</span>
                <span>
                  Simulation tells you what might happen. Exploitation tells you what will happen.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">02</div>
              <div className="cp-adv-title">
                Zero agents.
                <br />
                Zero friction.
              </div>
              <div className="cp-adv-desc">
                AttackIQ requires deploying agents on endpoints to run simulations. That means
                change management, endpoint approvals, and ongoing maintenance across your fleet.
                OdinForge is entirely agentless — it attacks from the outside in, like a real
                adversary would. Nothing to deploy, nothing to maintain on your endpoints.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">AGENTLESS</span>
                <span>
                  No agents on your endpoints. No change management. No maintenance burden.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">03</div>
              <div className="cp-adv-title">
                Clarity, not data overload.
              </div>
              <div className="cp-adv-desc">
                AttackIQ users report being "overwhelmed with raw data" and struggling to
                understand what requires action. OdinForge surfaces breach chains as visual,
                interactive attack graphs — making it immediately clear where you're exposed,
                how an attacker would get in, and exactly what to fix first.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">VISUAL</span>
                <span>
                  One interactive breach chain is worth a thousand rows in a CSV.
                </span>
              </div>
            </div>

            <div className="cp-adv-card">
              <div className="cp-adv-number">04</div>
              <div className="cp-adv-title">
                Full-spectrum testing.
                <br />
                Not just control validation.
              </div>
              <div className="cp-adv-desc">
                AttackIQ validates that your SIEM, EDR, and firewall detect known attack
                patterns. That's one layer. OdinForge covers the full attack surface — network
                pentesting, web application testing, cloud security, API assessment, and exploit
                validation — all from a single platform. See the whole picture, not just the
                detection layer.
              </div>
              <div className="cp-adv-detail">
                <span className="tag">SCOPE</span>
                <span>
                  Control validation + pentesting + web apps + cloud + APIs. One platform.
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* BENCHMARK PROOF */}
        <section className="cp-section cp-reveal">
          <div className="cp-section-label">Benchmark Results</div>
          <div className="cp-section-title">Proven performance. Transparent results.</div>
          <p className="cp-section-desc">
            OdinForge publishes full benchmark results against OWASP Juice Shop &mdash; no cherry-picking.
            5/5 scenarios passed with 90% detection rate. Our exploit agent uses real HTTP validation,
            not AI speculation.
          </p>
          <div className="cp-hero-actions" style={{ justifyContent: "flex-start" }}>
            <a href="/benchmark" className="cp-btn-secondary">
              See Full Benchmark Results &rarr;
            </a>
          </div>
        </section>

        {/* COMPETITOR CREDIT */}
        <section className="cp-shannon-credit cp-reveal">
          <div className="cp-shannon-box">
            <div>
              <h3>Credit where it's due — AttackIQ pioneered BAS.</h3>
              <p>
                AttackIQ is a founding member of MITRE's Center for Threat-Informed Defense and
                has trained 70,000+ security professionals through their free Academy. Their
                deep MITRE ATT&CK alignment and structured approach to security control
                validation have influenced the entire BAS market.
              </p>
              <p style={{ marginTop: 16 }}>
                But control validation is one piece of the puzzle. To understand your real
                exposure, you need to go beyond simulation.
              </p>
            </div>
            <div className="cp-shannon-list">
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>AttackIQ excels at</strong> MITRE ATT&CK-aligned security control
                  validation and detection testing
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">{"\u2713"}</span>
                <span>
                  <strong>AttackIQ excels at</strong> free security education through AttackIQ
                  Academy (70K+ students)
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> real exploitation and evidence-based breach
                  proof instead of simulation
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> agentless deployment, web app testing, and
                  network pentesting
                </span>
              </div>
              <div className="cp-shannon-list-item">
                <span className="icon">&rarr;</span>
                <span>
                  <strong>OdinForge adds</strong> visual breach chains and accessible pricing for
                  mid-market teams
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="cp-cta-section" id="cta">
          <div className="cp-cta-box cp-reveal">
            <h2>Don't just simulate. Validate.</h2>
            <p>
              Start a free trial and see real breach paths in your environment — not scripted
              playbooks testing your SIEM rules.
            </p>
            <div className="cp-cta-actions">
              <a href="/signup" className="cp-btn-primary">
                Start Free Trial &rarr;
              </a>
              <a href="/signup" className="cp-btn-secondary">
                Talk to an Engineer
              </a>
            </div>
          </div>
        </section>

        {/* FOOTER */}
        <footer className="cp-footer">
          <p>
            &copy; {new Date().getFullYear()} OdinForge. Comparison data accurate as of February
            2026. AttackIQ information sourced from{" "}
            <a
              href="https://www.attackiq.com"
              target="_blank"
              rel="noopener noreferrer"
            >
              public documentation
            </a>{" "}
            and{" "}
            <a
              href="https://www.peerspot.com/products/attackiq-reviews"
              target="_blank"
              rel="noopener noreferrer"
            >
              verified peer reviews
            </a>
            .
          </p>
        </footer>
      </div>
    </div>
  );
}
